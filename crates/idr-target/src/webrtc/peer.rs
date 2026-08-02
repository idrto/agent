//! Native WebRTC peer session (libdatachannel). Built with `--features webrtc`.
//!
//! Callbacks never await or lock app state — they `try_send` onto a bounded
//! event queue (libdatachannel callback safety model).

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};

use datachannel::{
    DataChannelHandler, DataChannelInfo, PeerConnectionHandler, RtcConfig, RtcDataChannel,
    RtcPeerConnection, TransportPolicy,
};
use tokio::sync::mpsc;
use tracing::warn;

use crate::webrtc::ice::ice_servers_to_urls;
use idr_protocol::webrtc_ice::{
    IceServer, IceTransportPolicy, WEBRTC_DC_LABEL, WEBRTC_DC_PROTOCOL,
};
use idr_protocol::{MAX_FRAME_BYTES, MAX_ICE_CANDIDATE_BYTES, MAX_SDP_BYTES};

type NativeChannel = Box<RtcDataChannel<ChannelHandler>>;

pub struct LocalCandidate {
    pub candidate: String,
    pub mid: String,
}

pub struct LocalDescription {
    pub sdp_type: String,
    pub sdp: String,
}

#[derive(Debug)]
pub enum PeerEvent {
    LocalDescription(LocalDescription),
    LocalCandidate(LocalCandidate),
    GatheringComplete,
    DataChannelOpen,
    DataChannelClosed,
    BinaryMessage(Vec<u8>),
    ConnectionFailed(String),
    Error(String),
}

enum CallbackEvent {
    Public(PeerEvent),
    IncomingChannel(NativeChannel),
}

#[derive(Clone)]
struct EventSink {
    sender: mpsc::Sender<CallbackEvent>,
    dropped: Arc<AtomicU64>,
}

impl EventSink {
    fn push(&self, event: CallbackEvent) {
        match self.sender.try_send(event) {
            Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn public(&self, event: PeerEvent) {
        self.push(CallbackEvent::Public(event));
    }
}

struct ChannelHandler {
    sink: EventSink,
    open: Arc<AtomicBool>,
    max_message_bytes: usize,
}

impl DataChannelHandler for ChannelHandler {
    fn on_open(&mut self) {
        self.open.store(true, Ordering::Release);
        self.sink.public(PeerEvent::DataChannelOpen);
    }

    fn on_closed(&mut self) {
        self.open.store(false, Ordering::Release);
        self.sink.public(PeerEvent::DataChannelClosed);
    }

    fn on_error(&mut self, error: &str) {
        self.sink
            .public(PeerEvent::Error(truncate(error, self.max_message_bytes)));
    }

    fn on_message(&mut self, message: &[u8]) {
        if message.len() > self.max_message_bytes {
            self.sink
                .public(PeerEvent::Error("received message exceeds limit".into()));
        } else {
            self.sink.public(PeerEvent::BinaryMessage(message.to_vec()));
        }
    }
}

struct ConnectionHandler {
    sink: EventSink,
    open: Arc<AtomicBool>,
    max_sdp_bytes: usize,
    max_candidate_bytes: usize,
    max_message_bytes: usize,
    accept_next_channel: bool,
}

impl PeerConnectionHandler for ConnectionHandler {
    type DCH = ChannelHandler;

    fn data_channel_handler(&mut self, info: DataChannelInfo) -> Self::DCH {
        let reliability = &info.reliability;
        self.accept_next_channel = info.label == WEBRTC_DC_LABEL
            && info.protocol.as_deref() == Some(WEBRTC_DC_PROTOCOL)
            && !reliability.unordered
            && !reliability.unreliable
            && reliability.max_packet_life_time == 0
            && reliability.max_retransmits == 0;
        if !self.accept_next_channel {
            self.sink.public(PeerEvent::Error(
                "rejected data channel with unexpected label/protocol/reliability".into(),
            ));
        }
        ChannelHandler {
            sink: self.sink.clone(),
            open: Arc::clone(&self.open),
            max_message_bytes: self.max_message_bytes,
        }
    }

    fn on_description(&mut self, description: datachannel::SessionDescription) {
        let sdp_type = match description.sdp_type {
            datachannel::SdpType::Offer => "offer",
            datachannel::SdpType::Answer => "answer",
            _ => {
                self.sink
                    .public(PeerEvent::Error("unsupported local SDP type".into()));
                return;
            }
        };
        let sdp = description.sdp.to_string();
        if sdp.len() > self.max_sdp_bytes {
            self.sink
                .public(PeerEvent::Error("local SDP exceeds limit".into()));
            return;
        }
        self.sink
            .public(PeerEvent::LocalDescription(LocalDescription {
                sdp_type: sdp_type.into(),
                sdp,
            }));
    }

    fn on_candidate(&mut self, candidate: datachannel::IceCandidate) {
        if candidate.candidate.len() > self.max_candidate_bytes
            || candidate.mid.len() > self.max_candidate_bytes
        {
            self.sink
                .public(PeerEvent::Error("local ICE candidate exceeds limit".into()));
            return;
        }
        self.sink.public(PeerEvent::LocalCandidate(LocalCandidate {
            candidate: candidate.candidate,
            mid: candidate.mid,
        }));
    }

    fn on_connection_state_change(&mut self, state: datachannel::ConnectionState) {
        if matches!(
            state,
            datachannel::ConnectionState::Failed | datachannel::ConnectionState::Closed
        ) {
            self.sink
                .public(PeerEvent::ConnectionFailed(format!("{state:?}")));
        }
    }

    fn on_gathering_state_change(&mut self, state: datachannel::GatheringState) {
        if state == datachannel::GatheringState::Complete {
            self.sink.public(PeerEvent::GatheringComplete);
        }
    }

    fn on_ice_state_change(&mut self, state: datachannel::IceState) {
        if matches!(
            state,
            datachannel::IceState::Failed | datachannel::IceState::Closed
        ) {
            self.sink
                .public(PeerEvent::ConnectionFailed(format!("ice:{state:?}")));
        }
    }

    fn on_data_channel(&mut self, channel: NativeChannel) {
        if self.accept_next_channel {
            self.accept_next_channel = false;
            self.sink.push(CallbackEvent::IncomingChannel(channel));
        }
    }
}

pub struct PeerConfig {
    pub ice_servers: Vec<IceServer>,
    pub ice_transport_policy: IceTransportPolicy,
    pub event_queue_capacity: usize,
    pub max_sdp_bytes: usize,
    pub max_candidate_bytes: usize,
    pub max_message_bytes: usize,
    pub buffered_amount_low_threshold: usize,
}

impl Default for PeerConfig {
    fn default() -> Self {
        Self {
            ice_servers: Vec::new(),
            ice_transport_policy: IceTransportPolicy::All,
            event_queue_capacity: 256,
            max_sdp_bytes: MAX_SDP_BYTES,
            max_candidate_bytes: MAX_ICE_CANDIDATE_BYTES,
            max_message_bytes: MAX_FRAME_BYTES,
            buffered_amount_low_threshold: 256 * 1024,
        }
    }
}

/// Responder PeerConnection for Target-Agent WebRTC sessions.
pub struct NativePeerSession {
    peer: Option<Box<RtcPeerConnection<ConnectionHandler>>>,
    channel: Option<NativeChannel>,
    receiver: mpsc::Receiver<CallbackEvent>,
    dropped: Arc<AtomicU64>,
    channel_open: Arc<AtomicBool>,
    max_message_bytes: usize,
    buffered_amount_low_threshold: usize,
}

impl NativePeerSession {
    pub fn new(config: PeerConfig) -> anyhow::Result<Self> {
        let urls = ice_servers_to_urls(&config.ice_servers);
        if urls.is_empty() {
            anyhow::bail!("no ICE servers configured for PeerConnection");
        }
        let (sender, receiver) = mpsc::channel(config.event_queue_capacity.max(16));
        let dropped = Arc::new(AtomicU64::new(0));
        let channel_open = Arc::new(AtomicBool::new(false));
        let sink = EventSink {
            sender,
            dropped: Arc::clone(&dropped),
        };

        let mut rtc_config = RtcConfig::new(&urls);
        rtc_config.ice_transport_policy = match config.ice_transport_policy {
            IceTransportPolicy::All => TransportPolicy::All,
            IceTransportPolicy::Relay => TransportPolicy::Relay,
        };
        rtc_config.max_message_size = config.max_message_bytes as i32;

        let handler = ConnectionHandler {
            sink,
            open: Arc::clone(&channel_open),
            max_sdp_bytes: config.max_sdp_bytes,
            max_candidate_bytes: config.max_candidate_bytes,
            max_message_bytes: config.max_message_bytes,
            accept_next_channel: false,
        };
        let peer = RtcPeerConnection::new(&rtc_config, handler)
            .map_err(|e| anyhow::anyhow!("RtcPeerConnection::new: {e}"))?;

        Ok(Self {
            peer: Some(peer),
            channel: None,
            receiver,
            dropped,
            channel_open,
            max_message_bytes: config.max_message_bytes,
            buffered_amount_low_threshold: config.buffered_amount_low_threshold,
        })
    }

    pub fn set_remote_offer(&mut self, sdp: &str) -> anyhow::Result<()> {
        if sdp.len() > MAX_SDP_BYTES {
            anyhow::bail!("remote SDP too large");
        }
        let parsed = datachannel::sdp::parse_sdp(sdp, false)
            .map_err(|e| anyhow::anyhow!("parse remote SDP: {e}"))?;
        let description = datachannel::SessionDescription {
            sdp: parsed,
            sdp_type: datachannel::SdpType::Offer,
        };
        self.peer_mut()?
            .set_remote_description(&description)
            .map_err(|e| anyhow::anyhow!("set_remote_description: {e}"))
    }

    pub fn create_answer(&mut self) -> anyhow::Result<()> {
        self.peer_mut()?
            .set_local_description(datachannel::SdpType::Answer)
            .map_err(|e| anyhow::anyhow!("create_answer: {e}"))
    }

    pub fn add_remote_candidate(&mut self, candidate: &str, mid: &str) -> anyhow::Result<()> {
        if candidate.len() > MAX_ICE_CANDIDATE_BYTES || mid.len() > MAX_ICE_CANDIDATE_BYTES {
            anyhow::bail!("remote ICE candidate too large");
        }
        let cand = datachannel::IceCandidate {
            candidate: candidate.to_string(),
            mid: mid.to_string(),
        };
        self.peer_mut()?
            .add_remote_candidate(&cand)
            .map_err(|e| anyhow::anyhow!("add_remote_candidate: {e}"))
    }

    pub fn send_binary(&mut self, message: &[u8]) -> anyhow::Result<()> {
        if message.len() > self.max_message_bytes {
            anyhow::bail!("outbound message too large");
        }
        if !self.channel_open.load(Ordering::Acquire) {
            anyhow::bail!("data channel not open");
        }
        self.channel
            .as_deref_mut()
            .ok_or_else(|| anyhow::anyhow!("data channel missing"))?
            .send(message)
            .map_err(|e| anyhow::anyhow!("dc send: {e}"))
    }

    pub async fn next_event(&mut self) -> anyhow::Result<PeerEvent> {
        loop {
            let dropped = self.dropped.swap(0, Ordering::AcqRel);
            if dropped != 0 {
                warn!(dropped, "WebRTC callback queue overflow");
                return Ok(PeerEvent::Error(format!(
                    "callback queue overflow dropped={dropped}"
                )));
            }
            match self.receiver.recv().await {
                Some(CallbackEvent::Public(event)) => return Ok(event),
                Some(CallbackEvent::IncomingChannel(mut channel)) => {
                    if self.channel.is_some() {
                        return Ok(PeerEvent::Error("rejected duplicate data channel".into()));
                    }
                    channel
                        .set_buffered_amount_low_threshold(self.buffered_amount_low_threshold)
                        .map_err(|e| anyhow::anyhow!("set buffered threshold: {e}"))?;
                    self.channel = Some(channel);
                }
                None => anyhow::bail!("peer event channel closed"),
            }
        }
    }

    pub fn close(&mut self) {
        self.channel = None;
        self.peer = None;
        self.channel_open.store(false, Ordering::Release);
    }

    fn peer_mut(&mut self) -> anyhow::Result<&mut RtcPeerConnection<ConnectionHandler>> {
        self.peer
            .as_deref_mut()
            .ok_or_else(|| anyhow::anyhow!("peer closed"))
    }
}

fn truncate(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}
