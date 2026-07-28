//! Source runtime and session orchestration.

use std::sync::Arc;

use async_trait::async_trait;
use idr_core::error::{IdrError, IdrErrorKind, Result};
use idr_core::session::{OpenStreamRequest, PeerSession};
use idr_core::stream::LogicalStream;
use idr_protocol::signaling::SignalingMessageType;
use idr_protocol::stream_mux::{StreamFrame, StreamOpenMeta};
use idr_protocol::webrtc_signaling::{
    SourceAgentIdentity, SourceAuthMode, SessionDescription, WebRtcSessionRequest,
};
use idr_protocol::PROTOCOL_VERSION;
use idr_signaling::ephemeral::{SignalingMessage, WebRtcSignalingClient};
use idr_webrtc::transport::{PeerConnectRequest, PeerEvent, PeerRole, PeerTransport};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::mux_session::{MuxLogicalStream, StreamDemux, StreamIdAllocator};
use crate::service_map::default_service_kind;

/// Entry point for embedded / mobile Source usage.
pub struct SourceRuntime {
    signaling: Box<dyn WebRtcSignalingClient>,
    /// Factory invoked per connect to build a fresh PeerTransport (mock or native).
    peer_factory: Box<dyn Fn() -> Box<dyn PeerTransport> + Send + Sync>,
    source_id: String,
    source_region: String,
}

impl SourceRuntime {
    pub fn new(
        signaling: Box<dyn WebRtcSignalingClient>,
        peer_factory: impl Fn() -> Box<dyn PeerTransport> + Send + Sync + 'static,
        source_id: impl Into<String>,
        source_region: impl Into<String>,
    ) -> Self {
        Self {
            signaling,
            peer_factory: Box::new(peer_factory),
            source_id: source_id.into(),
            source_region: source_region.into(),
        }
    }

    /// Connect to `target_fqhn` over WebRTC (Presence signaling + P2P/TURN data).
    pub async fn connect(&mut self, target_fqhn: &str) -> Result<SourceSession> {
        let mut peer = (self.peer_factory)();
        peer.start(PeerConnectRequest {
            role: PeerRole::Offerer,
            ice_servers_json: None,
        })
        .await?;
        peer.create_local_description().await?;

        let mut local_sdp = String::new();
        loop {
            match peer.next_event().await? {
                PeerEvent::LocalDescription { sdp_type, sdp } if sdp_type == "offer" => {
                    local_sdp = sdp;
                    break;
                }
                PeerEvent::GatheringComplete => {}
                PeerEvent::LocalCandidate { .. } => {}
                other => {
                    return Err(IdrError::new(
                        IdrErrorKind::IceFailed,
                        format!("unexpected peer event while creating offer: {other:?}"),
                    ));
                }
            }
        }
        let local_sdp = if local_sdp.is_empty() {
            return Err(IdrError::new(IdrErrorKind::IceFailed, "offer SDP missing"));
        } else {
            local_sdp
        };

        let session_id = Uuid::new_v4();
        let request = WebRtcSessionRequest {
            version: PROTOCOL_VERSION,
            message_type: SignalingMessageType::WebRtcSessionRequest,
            message_id: Uuid::new_v4(),
            session_id,
            target_fqhn: target_fqhn.to_string(),
            source: SourceAgentIdentity {
                auth_mode: SourceAuthMode::Anonymous,
                source_id: Some(self.source_id.clone()),
                sdk_version: Some(env!("CARGO_PKG_VERSION").into()),
            },
            source_region: self.source_region.clone(),
            sdp: SessionDescription {
                sdp_type: "offer".into(),
                sdp: local_sdp,
            },
            signature: None,
        };

        let mut channel = self.signaling.begin_session(request).await?;
        let mut answer_sdp = None;
        loop {
            match channel.next_message().await? {
                SignalingMessage::Pending(_) => {}
                SignalingMessage::Answer(ans) => {
                    answer_sdp = Some(ans.sdp.sdp);
                }
                SignalingMessage::IceCandidate(c) => {
                    peer.add_remote_candidate(&c.candidate, &c.mid)?;
                }
                SignalingMessage::IceComplete { .. } => {}
                SignalingMessage::SessionAck { result, detail, .. } => {
                    use idr_protocol::webrtc_signaling::WebRtcSessionResultCode::*;
                    match result {
                        Active | Negotiating | Received => {
                            if answer_sdp.is_some() {
                                break;
                            }
                        }
                        Failed | Expired | Busy => {
                            return Err(IdrError::new(
                                IdrErrorKind::SignalingFailed,
                                detail.unwrap_or_else(|| format!("session ack {result:?}")),
                            ));
                        }
                    }
                }
                SignalingMessage::Error { message } => {
                    return Err(IdrError::new(IdrErrorKind::SignalingFailed, message));
                }
            }
            if answer_sdp.is_some() {
                // Continue until Active ack when available; mock sends ack after answer.
            }
        }

        let answer = answer_sdp.ok_or_else(|| {
            IdrError::new(IdrErrorKind::SignalingFailed, "missing WebRTC answer")
        })?;
        peer.set_remote_description("answer", &answer).await?;

        // Wait for DataChannel
        loop {
            match peer.next_event().await? {
                PeerEvent::DataChannelOpen => break,
                PeerEvent::GatheringComplete | PeerEvent::LocalCandidate { .. } => {}
                PeerEvent::BinaryMessage(_) => {}
                PeerEvent::ConnectionFailed => {
                    return Err(IdrError::new(
                        IdrErrorKind::IceFailed,
                        "peer connection failed",
                    ));
                }
                PeerEvent::Closed | PeerEvent::DataChannelClosed => {
                    return Err(IdrError::new(
                        IdrErrorKind::TransportClosed,
                        "peer closed before datachannel",
                    ));
                }
                PeerEvent::LocalDescription { .. } => {}
            }
        }

        let _ = channel.close().await;
        let (control_tx, control_rx) = tokio::sync::mpsc::channel(64);
        Ok(SourceSession {
            target_fqhn: target_fqhn.to_string(),
            peer: Arc::new(Mutex::new(peer)),
            demux: StreamDemux::with_control(32, control_tx),
            control_rx,
            ids: StreamIdAllocator::default(),
            pump_started: false,
            prefer_flow_control: true,
        })
    }
}

pub struct SourceSession {
    target_fqhn: String,
    peer: Arc<Mutex<Box<dyn PeerTransport>>>,
    demux: StreamDemux,
    control_rx: tokio::sync::mpsc::Receiver<crate::mux_session::DemuxEvent>,
    ids: StreamIdAllocator,
    pump_started: bool,
    /// When true, wait briefly for OpenOk before falling back to legacy.
    prefer_flow_control: bool,
}

impl SourceSession {
    fn ensure_pump(&mut self) {
        if self.pump_started {
            return;
        }
        self.pump_started = true;
        // Pump is driven opportunistically from open_stream/read paths in v1 mock tests
        // via `poll_incoming`. Native builds will spawn a background task.
    }

    /// Drain inbound DC messages into stream inboxes (call periodically or from tests).
    pub async fn poll_incoming(&mut self) -> Result<()> {
        self.pump_once().await
    }

    /// Pull one peer event and feed stream demux when it is a binary frame.
    pub async fn pump_once(&mut self) -> Result<()> {
        if let Some(bytes) = self.drive_until_data().await? {
            self.ingest_dc_frame(bytes).await?;
        }
        Ok(())
    }

    async fn drive_until_data(&mut self) -> Result<Option<Vec<u8>>> {
        let mut peer = self.peer.lock().await;
        match peer.next_event().await? {
            PeerEvent::BinaryMessage(bytes) => Ok(Some(bytes)),
            PeerEvent::Closed | PeerEvent::DataChannelClosed => Err(IdrError::new(
                IdrErrorKind::TransportClosed,
                "datachannel closed",
            )),
            _ => Ok(None),
        }
    }

    pub async fn open_named_stream(&mut self, service: &str) -> Result<Box<dyn LogicalStream>> {
        let kind = default_service_kind(service).ok_or_else(|| {
            IdrError::new(
                IdrErrorKind::ServiceNotFound,
                format!("unknown service '{service}'"),
            )
        })?;
        let request = OpenStreamRequest {
            service: service.into(),
            kind,
            meta: StreamOpenMeta {
                target_fqhn: self.target_fqhn.clone(),
                host: None,
                port: None,
            },
        };
        self.open_stream(request).await
    }
}

#[async_trait]
impl PeerSession for SourceSession {
    fn target_fqhn(&self) -> &str {
        &self.target_fqhn
    }

    async fn open_stream(&mut self, request: OpenStreamRequest) -> Result<Box<dyn LogicalStream>> {
        self.ensure_pump();
        let stream_id = self.ids.next();
        let rx = self.demux.register(stream_id.0);
        let frame = StreamFrame::Open {
            stream_id: stream_id.0,
            kind: request.kind,
            meta: request.meta,
        };
        let enc = frame.encode()?;
        {
            let mut peer = self.peer.lock().await;
            peer.send_binary(&enc)?;
        }

        let (profile, initial_window) = if self.prefer_flow_control {
            // Drive one inbound event if the peer auto-replies OpenOk (test transports).
            if let Ok(Some(bytes)) = self.drive_until_data().await {
                let _ = self.ingest_dc_frame(bytes).await;
            }
            crate::mux_session::wait_open_result(
                &mut self.control_rx,
                stream_id.0,
                std::time::Duration::from_millis(50),
            )
            .await?
        } else {
            (
                idr_protocol::stream_mux::MuxProfile::Legacy,
                idr_protocol::stream_mux::INITIAL_STREAM_WINDOW,
            )
        };

        Ok(Box::new(MuxLogicalStream::new(
            stream_id,
            self.peer.clone(),
            rx,
            profile,
            initial_window,
        )))
    }

    async fn close(&mut self) -> Result<()> {
        let mut peer = self.peer.lock().await;
        peer.close();
        Ok(())
    }
}

impl SourceSession {
    async fn ingest_dc_frame(&mut self, bytes: Vec<u8>) -> Result<()> {
        let frame = StreamFrame::decode(&bytes)?;
        self.demux.handle_frame(frame).await
    }
}
