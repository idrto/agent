//! libdatachannel-backed [`PeerTransport`] for offerer and answerer roles.
//!
//! Callbacks never await or lock app state — they `try_send` onto a bounded
//! event queue (libdatachannel callback safety model).

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};

use async_trait::async_trait;
use datachannel::{
    DataChannelHandler, DataChannelInfo, DataChannelInit, PeerConnectionHandler, RtcConfig,
    RtcDataChannel, RtcPeerConnection, SdpType, TransportPolicy,
};
use tokio::sync::mpsc;
use tracing::warn;

use idr_core::error::{IdrError, IdrErrorKind, Result};
use idr_protocol::webrtc_ice::{
    IceServer, IceTransportPolicy, STUN_GOOGLE, WEBRTC_DC_LABEL, WEBRTC_DC_PROTOCOL,
};
use idr_protocol::{MAX_FRAME_BYTES, MAX_ICE_CANDIDATE_BYTES, MAX_SDP_BYTES};

use crate::transport::{PeerConnectRequest, PeerEvent, PeerRole, PeerTransport};

mod ice_servers {
    //! Convert protocol ICE servers into libdatachannel `RtcConfig` URL strings.

    use idr_protocol::webrtc_ice::IceServer;

    /// Build ICE URL list for `RtcConfig::new`. TURN entries with username/credential
    /// are rewritten to `turn:` / `turns:` URLs with embedded userinfo.
    pub fn ice_servers_to_urls(servers: &[IceServer]) -> Vec<String> {
        let mut out = Vec::new();
        for server in servers {
            for url in &server.urls {
                out.push(embed_credentials(
                    url,
                    server.username.as_deref(),
                    server.credential.as_deref(),
                ));
            }
        }
        out
    }

    fn embed_credentials(url: &str, username: Option<&str>, credential: Option<&str>) -> String {
        let (Some(user), Some(pass)) = (username, credential) else {
            return url.to_string();
        };
        if url.contains('@') {
            return url.to_string();
        }
        let (scheme, rest) = if let Some(r) = url.strip_prefix("turns:") {
            ("turns", r)
        } else if let Some(r) = url.strip_prefix("turn:") {
            ("turn", r)
        } else {
            return url.to_string();
        };
        let user = encode_userinfo(user);
        let pass = encode_userinfo(pass);
        format!("{scheme}:{user}:{pass}@{rest}")
    }

    fn encode_userinfo(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    out.push(b as char);
                }
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }
}

use ice_servers::ice_servers_to_urls;

type NativeChannel = Box<RtcDataChannel<ChannelHandler>>;

enum CallbackEvent {
    Public(InternalEvent),
    IncomingChannel(NativeChannel),
}

#[derive(Debug, Clone)]
enum InternalEvent {
    LocalDescription { sdp_type: String, sdp: String },
    LocalCandidate { candidate: String, mid: String },
    GatheringComplete,
    DataChannelOpen,
    DataChannelClosed,
    BinaryMessage(Vec<u8>),
    ConnectionFailed,
    Closed,
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

    fn public(&self, event: InternalEvent) {
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
        self.sink.public(InternalEvent::DataChannelOpen);
    }

    fn on_closed(&mut self) {
        self.open.store(false, Ordering::Release);
        self.sink.public(InternalEvent::DataChannelClosed);
    }

    fn on_error(&mut self, _error: &str) {
        self.sink.public(InternalEvent::ConnectionFailed);
    }

    fn on_message(&mut self, message: &[u8]) {
        if message.len() > self.max_message_bytes {
            self.sink.public(InternalEvent::ConnectionFailed);
        } else {
            self.sink
                .public(InternalEvent::BinaryMessage(message.to_vec()));
        }
    }
}

struct ConnectionHandler {
    sink: EventSink,
    open: Arc<AtomicBool>,
    role: PeerRole,
    max_sdp_bytes: usize,
    max_candidate_bytes: usize,
    max_message_bytes: usize,
    accept_next_channel: bool,
}

impl PeerConnectionHandler for ConnectionHandler {
    type DCH = ChannelHandler;

    fn data_channel_handler(&mut self, info: DataChannelInfo) -> Self::DCH {
        if self.role == PeerRole::Offerer {
            self.accept_next_channel = false;
            self.sink.public(InternalEvent::ConnectionFailed);
        } else {
            let reliability = &info.reliability;
            self.accept_next_channel = info.label == WEBRTC_DC_LABEL
                && info.protocol.as_deref() == Some(WEBRTC_DC_PROTOCOL)
                && !reliability.unordered
                && !reliability.unreliable
                && reliability.max_packet_life_time == 0
                && reliability.max_retransmits == 0;
            if !self.accept_next_channel {
                self.sink.public(InternalEvent::ConnectionFailed);
            }
        }
        ChannelHandler {
            sink: self.sink.clone(),
            open: Arc::clone(&self.open),
            max_message_bytes: self.max_message_bytes,
        }
    }

    fn on_description(&mut self, description: datachannel::SessionDescription) {
        let sdp_type = match description.sdp_type {
            SdpType::Offer => "offer",
            SdpType::Answer => "answer",
            _ => {
                self.sink.public(InternalEvent::ConnectionFailed);
                return;
            }
        };
        let sdp = description.sdp.to_string();
        if sdp.len() > self.max_sdp_bytes {
            self.sink.public(InternalEvent::ConnectionFailed);
            return;
        }
        self.sink.public(InternalEvent::LocalDescription {
            sdp_type: sdp_type.into(),
            sdp,
        });
    }

    fn on_description_raw(&mut self, sdp: String, sdp_type: SdpType) {
        let sdp_type = match sdp_type {
            SdpType::Offer => "offer",
            SdpType::Answer => "answer",
            _ => "answer",
        };
        if sdp.len() > self.max_sdp_bytes {
            self.sink.public(InternalEvent::ConnectionFailed);
            return;
        }
        tracing::warn!(
            sdp_type,
            sdp_len = sdp.len(),
            "using raw local SDP (webrtc-sdp parse failed in datachannel-rs)"
        );
        self.sink.public(InternalEvent::LocalDescription {
            sdp_type: sdp_type.into(),
            sdp,
        });
    }

    fn on_candidate(&mut self, candidate: datachannel::IceCandidate) {
        if candidate.candidate.len() > self.max_candidate_bytes
            || candidate.mid.len() > self.max_candidate_bytes
        {
            self.sink.public(InternalEvent::ConnectionFailed);
            return;
        }
        self.sink.public(InternalEvent::LocalCandidate {
            candidate: candidate.candidate,
            mid: candidate.mid,
        });
    }

    fn on_connection_state_change(&mut self, state: datachannel::ConnectionState) {
        match state {
            datachannel::ConnectionState::Failed => {
                self.sink.public(InternalEvent::ConnectionFailed);
            }
            datachannel::ConnectionState::Closed => {
                self.sink.public(InternalEvent::Closed);
            }
            _ => {}
        }
    }

    fn on_gathering_state_change(&mut self, state: datachannel::GatheringState) {
        if state == datachannel::GatheringState::Complete {
            self.sink.public(InternalEvent::GatheringComplete);
        }
    }

    fn on_ice_state_change(&mut self, state: datachannel::IceState) {
        match state {
            datachannel::IceState::Failed => {
                self.sink.public(InternalEvent::ConnectionFailed);
            }
            datachannel::IceState::Closed => {
                self.sink.public(InternalEvent::Closed);
            }
            _ => {}
        }
    }

    fn on_data_channel(&mut self, channel: NativeChannel) {
        if self.role == PeerRole::Answerer && self.accept_next_channel {
            self.accept_next_channel = false;
            self.sink.push(CallbackEvent::IncomingChannel(channel));
        }
    }
}

/// Configuration for [`NativePeer`].
#[derive(Debug, Clone)]
pub struct NativePeerConfig {
    pub ice_transport_policy: IceTransportPolicy,
    pub event_queue_capacity: usize,
    pub max_sdp_bytes: usize,
    pub max_candidate_bytes: usize,
    pub max_message_bytes: usize,
    pub buffered_amount_low_threshold: usize,
}

impl Default for NativePeerConfig {
    fn default() -> Self {
        Self {
            ice_transport_policy: IceTransportPolicy::All,
            event_queue_capacity: 256,
            max_sdp_bytes: MAX_SDP_BYTES,
            max_candidate_bytes: MAX_ICE_CANDIDATE_BYTES,
            max_message_bytes: MAX_FRAME_BYTES,
            buffered_amount_low_threshold: 256 * 1024,
        }
    }
}

/// libdatachannel [`PeerTransport`] supporting offerer and answerer.
pub struct NativePeer {
    config: NativePeerConfig,
    role: Option<PeerRole>,
    peer: Option<Box<RtcPeerConnection<ConnectionHandler>>>,
    channel: Option<NativeChannel>,
    receiver: mpsc::Receiver<CallbackEvent>,
    event_sender: mpsc::Sender<CallbackEvent>,
    dropped: Arc<AtomicU64>,
    channel_open: Arc<AtomicBool>,
}

impl NativePeer {
    pub fn new(config: NativePeerConfig) -> Result<Self> {
        let cap = config.event_queue_capacity.max(16);
        let (event_sender, receiver) = mpsc::channel(cap);
        Ok(Self {
            config,
            role: None,
            peer: None,
            channel: None,
            receiver,
            event_sender,
            dropped: Arc::new(AtomicU64::new(0)),
            channel_open: Arc::new(AtomicBool::new(false)),
        })
    }

    fn peer_mut(&mut self) -> Result<&mut RtcPeerConnection<ConnectionHandler>> {
        self.peer.as_deref_mut().ok_or_else(|| {
            IdrError::new(IdrErrorKind::TransportClosed, "peer connection closed")
        })
    }

    fn ensure_offerer_channel(&mut self) -> Result<()> {
        if self.channel.is_some() {
            return Ok(());
        }
        let sink = EventSink {
            sender: self.event_sender.clone(),
            dropped: Arc::clone(&self.dropped),
        };
        let handler = ChannelHandler {
            sink,
            open: Arc::clone(&self.channel_open),
            max_message_bytes: self.config.max_message_bytes,
        };
        let dc_init = DataChannelInit::default().protocol(WEBRTC_DC_PROTOCOL);
        let mut channel = self
            .peer_mut()?
            .create_data_channel_ex(WEBRTC_DC_LABEL, handler, &dc_init)
            .map_err(|e| IdrError::new(IdrErrorKind::InternalError, format!("create_data_channel: {e}")))?;
        channel
            .set_buffered_amount_low_threshold(self.config.buffered_amount_low_threshold)
            .map_err(|e| {
                IdrError::new(
                    IdrErrorKind::InternalError,
                    format!("set buffered threshold: {e}"),
                )
            })?;
        self.channel = Some(channel);
        Ok(())
    }

    fn map_event(event: InternalEvent) -> PeerEvent {
        match event {
            InternalEvent::LocalDescription { sdp_type, sdp } => PeerEvent::LocalDescription {
                sdp_type,
                sdp,
            },
            InternalEvent::LocalCandidate { candidate, mid } => PeerEvent::LocalCandidate {
                candidate,
                mid,
            },
            InternalEvent::GatheringComplete => PeerEvent::GatheringComplete,
            InternalEvent::DataChannelOpen => PeerEvent::DataChannelOpen,
            InternalEvent::DataChannelClosed => PeerEvent::DataChannelClosed,
            InternalEvent::BinaryMessage(bytes) => PeerEvent::BinaryMessage(bytes),
            InternalEvent::ConnectionFailed => PeerEvent::ConnectionFailed,
            InternalEvent::Closed => PeerEvent::Closed,
        }
    }
}

fn parse_ice_servers(json: Option<&str>, role: PeerRole) -> Result<Vec<IceServer>> {
    if let Some(raw) = json.map(str::trim).filter(|s| !s.is_empty()) {
        serde_json::from_str(raw).map_err(|e| {
            IdrError::new(
                IdrErrorKind::InvalidArgument,
                format!("ice_servers_json: {e}"),
            )
        })
    } else if role == PeerRole::Offerer {
        // Local tests: signaling may omit ice_servers; default public STUN is enough for LAN/host.
        Ok(vec![IceServer {
            urls: vec![STUN_GOOGLE.to_string()],
            username: None,
            credential: None,
        }])
    } else {
        Err(IdrError::new(
            IdrErrorKind::InvalidArgument,
            "ice_servers_json required for answerer",
        ))
    }
}

#[async_trait]
impl PeerTransport for NativePeer {
    async fn start(&mut self, request: PeerConnectRequest) -> Result<()> {
        if self.peer.is_some() {
            return Err(IdrError::new(
                IdrErrorKind::InvalidArgument,
                "peer already started",
            ));
        }
        let ice_servers = parse_ice_servers(request.ice_servers_json.as_deref(), request.role)?;
        let urls = ice_servers_to_urls(&ice_servers);
        if urls.is_empty() {
            return Err(IdrError::new(
                IdrErrorKind::InvalidArgument,
                "no ICE server URLs configured",
            ));
        }

        self.role = Some(request.role);

        let sink = EventSink {
            sender: self.event_sender.clone(),
            dropped: Arc::clone(&self.dropped),
        };

        let mut rtc_config = RtcConfig::new(&urls);
        rtc_config.ice_transport_policy = match self.config.ice_transport_policy {
            IceTransportPolicy::All => TransportPolicy::All,
            IceTransportPolicy::Relay => TransportPolicy::Relay,
        };
        rtc_config.max_message_size = self.config.max_message_bytes as i32;

        let handler = ConnectionHandler {
            sink,
            open: Arc::clone(&self.channel_open),
            role: request.role,
            max_sdp_bytes: self.config.max_sdp_bytes,
            max_candidate_bytes: self.config.max_candidate_bytes,
            max_message_bytes: self.config.max_message_bytes,
            accept_next_channel: false,
        };

        let peer = RtcPeerConnection::new(&rtc_config, handler).map_err(|e| {
            IdrError::new(
                IdrErrorKind::InternalError,
                format!("RtcPeerConnection::new: {e}"),
            )
        })?;

        self.peer = Some(peer);
        Ok(())
    }

    async fn set_remote_description(&mut self, sdp_type: &str, sdp: &str) -> Result<()> {
        if sdp.len() > self.config.max_sdp_bytes {
            return Err(IdrError::new(
                IdrErrorKind::InvalidArgument,
                "remote SDP too large",
            ));
        }
        let sdp_type = match sdp_type {
            "offer" => SdpType::Offer,
            "answer" => SdpType::Answer,
            _ => {
                return Err(IdrError::new(
                    IdrErrorKind::InvalidArgument,
                    format!("unsupported remote SDP type: {sdp_type}"),
                ))
            }
        };
        if let Err(e) = datachannel::sdp::parse_sdp(sdp, false) {
            tracing::warn!(
                error = %e,
                sdp_len = sdp.len(),
                "remote SDP webrtc-sdp parse failed; applying raw to libdatachannel"
            );
        }
        self.peer_mut()?
            .set_remote_description_raw(sdp, sdp_type)
            .map_err(|e| {
                IdrError::new(
                    IdrErrorKind::SignalingFailed,
                    format!("set_remote_description: {e}"),
                )
            })
    }

    async fn create_local_description(&mut self) -> Result<()> {
        let role = self.role.ok_or_else(|| {
            IdrError::new(IdrErrorKind::NotInitialized, "peer not started")
        })?;
        match role {
            PeerRole::Offerer => {
                self.ensure_offerer_channel()?;
                self.peer_mut()?
                    .set_local_description(SdpType::Offer)
                    .map_err(|e| {
                        IdrError::new(
                            IdrErrorKind::SignalingFailed,
                            format!("create_offer: {e}"),
                        )
                    })?;
            }
            PeerRole::Answerer => {
                self.peer_mut()?
                    .set_local_description(SdpType::Answer)
                    .map_err(|e| {
                        IdrError::new(
                            IdrErrorKind::SignalingFailed,
                            format!("create_answer: {e}"),
                        )
                    })?;
            }
        }
        Ok(())
    }

    fn add_remote_candidate(&mut self, candidate: &str, mid: &str) -> Result<()> {
        if candidate.len() > self.config.max_candidate_bytes
            || mid.len() > self.config.max_candidate_bytes
        {
            return Err(IdrError::new(
                IdrErrorKind::InvalidArgument,
                "remote ICE candidate too large",
            ));
        }
        let cand = datachannel::IceCandidate {
            candidate: candidate.to_string(),
            mid: mid.to_string(),
        };
        self.peer_mut()?
            .add_remote_candidate(&cand)
            .map_err(|e| {
                IdrError::new(
                    IdrErrorKind::IceFailed,
                    format!("add_remote_candidate: {e}"),
                )
            })
    }

    fn send_binary(&mut self, message: &[u8]) -> Result<()> {
        if message.len() > self.config.max_message_bytes {
            return Err(IdrError::new(
                IdrErrorKind::InvalidArgument,
                "outbound message too large",
            ));
        }
        if !self.channel_open.load(Ordering::Acquire) {
            return Err(IdrError::new(
                IdrErrorKind::TransportClosed,
                "data channel not open",
            ));
        }
        self.channel
            .as_deref_mut()
            .ok_or_else(|| IdrError::new(IdrErrorKind::TransportClosed, "data channel missing"))?
            .send(message)
            .map_err(|e| IdrError::new(IdrErrorKind::InternalError, format!("dc send: {e}")))
    }

    async fn next_event(&mut self) -> Result<PeerEvent> {
        loop {
            let dropped = self.dropped.swap(0, Ordering::AcqRel);
            if dropped != 0 {
                warn!(dropped, "WebRTC callback queue overflow");
                return Ok(PeerEvent::ConnectionFailed);
            }
            match self.receiver.recv().await {
                Some(CallbackEvent::Public(event)) => return Ok(Self::map_event(event)),
                Some(CallbackEvent::IncomingChannel(mut channel)) => {
                    if self.channel.is_some() {
                        return Ok(PeerEvent::ConnectionFailed);
                    }
                    channel
                        .set_buffered_amount_low_threshold(self.config.buffered_amount_low_threshold)
                        .map_err(|e| {
                            IdrError::new(
                                IdrErrorKind::InternalError,
                                format!("set buffered threshold: {e}"),
                            )
                        })?;
                    self.channel = Some(channel);
                }
                None => return Ok(PeerEvent::Closed),
            }
        }
    }

    fn close(&mut self) {
        self.channel = None;
        self.peer = None;
        self.channel_open.store(false, Ordering::Release);
    }
}
