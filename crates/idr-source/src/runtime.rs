//! Source runtime and session orchestration.

use std::sync::Arc;

use async_trait::async_trait;
use idr_core::error::{IdrError, IdrErrorKind, Result};
use idr_core::session::{OpenStreamRequest, PeerSession};
use idr_core::stream::LogicalStream;
#[cfg(feature = "dp")]
use idr_dp::DeviceIdentity;
use idr_protocol::signaling::SignalingMessageType;
use idr_protocol::stream_mux::{StreamFrame, StreamOpenMeta};
use idr_protocol::webrtc_ice::{build_rtc_ice_servers, IceTransportPolicy};
use idr_protocol::webrtc_signaling::{
    SessionDescription, SourceAgentIdentity, SourceAuthMode, WebRtcIceCandidate, WebRtcIceComplete,
    WebRtcSessionRequest,
};
use idr_protocol::PROTOCOL_VERSION;
use idr_signaling::ephemeral::{SignalingMessage, WebRtcSignalingClient};
use idr_webrtc::transport::{PeerConnectRequest, PeerEvent, PeerRole, PeerTransport};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::mux_session::{MuxLogicalStream, StreamDemux, StreamIdAllocator};
use crate::service_map::default_service_kind;

/// Entry point for embedded / mobile / desktop Source usage.
pub struct SourceRuntime {
    signaling: Box<dyn WebRtcSignalingClient>,
    /// Factory invoked per connect to build a fresh PeerTransport (mock or native).
    #[cfg(not(target_arch = "wasm32"))]
    peer_factory: Box<dyn Fn() -> Box<dyn PeerTransport> + Send + Sync>,
    #[cfg(target_arch = "wasm32")]
    peer_factory: Box<dyn Fn() -> Box<dyn PeerTransport>>,
    source_id: String,
    source_region: String,
    /// Optional DP machine identity (mTLS AuthN + in-band AuthZ via PepClient).
    #[cfg(feature = "dp")]
    identity: Option<DeviceIdentity>,
    auth_mode: SourceAuthMode,
    auth_token: Option<String>,
}

impl SourceRuntime {
    pub fn new(
        signaling: Box<dyn WebRtcSignalingClient>,
        #[cfg(not(target_arch = "wasm32"))]
        peer_factory: impl Fn() -> Box<dyn PeerTransport> + Send + Sync + 'static,
        #[cfg(target_arch = "wasm32")]
        peer_factory: impl Fn() -> Box<dyn PeerTransport> + 'static,
        source_id: impl Into<String>,
        source_region: impl Into<String>,
    ) -> Self {
        Self::with_auth(
            signaling,
            peer_factory,
            source_id,
            source_region,
            SourceAuthMode::Anonymous,
            None,
        )
    }

    /// Product constructor: requires a non-anonymous auth mode and bearer/device token.
    pub fn with_auth(
        signaling: Box<dyn WebRtcSignalingClient>,
        #[cfg(not(target_arch = "wasm32"))]
        peer_factory: impl Fn() -> Box<dyn PeerTransport> + Send + Sync + 'static,
        #[cfg(target_arch = "wasm32")]
        peer_factory: impl Fn() -> Box<dyn PeerTransport> + 'static,
        source_id: impl Into<String>,
        source_region: impl Into<String>,
        auth_mode: SourceAuthMode,
        auth_token: Option<String>,
    ) -> Self {
        Self {
            signaling,
            peer_factory: Box::new(peer_factory),
            source_id: source_id.into(),
            source_region: source_region.into(),
            #[cfg(feature = "dp")]
            identity: None,
            auth_mode,
            auth_token,
        }
    }

    #[cfg(feature = "dp")]
    pub fn with_identity(mut self, identity: DeviceIdentity) -> Self {
        if self.source_id.is_empty()
            || self.source_id == "dart"
            || self.source_id == "dart-embedded"
        {
            self.source_id = identity.ski.clone();
        }
        self.identity = Some(identity);
        self
    }

    #[cfg(feature = "dp")]
    pub fn set_identity(&mut self, identity: DeviceIdentity) {
        if self.source_id.is_empty()
            || self.source_id == "dart"
            || self.source_id == "dart-embedded"
        {
            self.source_id = identity.ski.clone();
        }
        self.identity = Some(identity);
    }

    #[cfg(feature = "dp")]
    pub fn identity(&self) -> Option<&DeviceIdentity> {
        self.identity.as_ref()
    }

    fn source_agent_identity(&self, auth_token: Option<String>) -> SourceAgentIdentity {
        #[cfg(feature = "dp")]
        let auth_mode = if self.identity.is_some() {
            SourceAuthMode::Mtls
        } else {
            self.auth_mode
        };
        #[cfg(not(feature = "dp"))]
        let auth_mode = self.auth_mode;
        SourceAgentIdentity {
            auth_mode,
            source_id: Some(self.source_id.clone()),
            sdk_version: Some(env!("CARGO_PKG_VERSION").into()),
            auth_token,
        }
    }

    /// Connect to `target_fqhn` over WebRTC (Presence signaling + P2P/TURN data).
    ///
    /// Uses `{host}--{entity}.idr.to` on the wire (`.idr.to` appended if missing).
    /// DEF-encode is applied only inside Presence placement (index selection).
    pub async fn connect(&mut self, target_fqhn: &str) -> Result<SourceSession> {
        let target_fqhn = idr_protocol::fqhn::canonicalize(target_fqhn).map_err(|e| {
            IdrError::new(IdrErrorKind::InvalidArgument, e.to_string())
        })?;
        let auth_token = {
            #[cfg(feature = "dp")]
            {
                if self.identity.is_some() {
                    None
                } else {
                    if matches!(self.auth_mode, SourceAuthMode::Anonymous) {
                        return Err(IdrError::new(
                            IdrErrorKind::AuthenticationFailed,
                            "Anonymous Source auth is not allowed; provide bearer or device token",
                        ));
                    }
                    let token = self.auth_token.as_deref().filter(|t| !t.is_empty()).ok_or_else(|| {
                        IdrError::new(
                            IdrErrorKind::AuthenticationFailed,
                            "auth_token required for Source connect",
                        )
                    })?;
                    Some(token.to_string())
                }
            }
            #[cfg(not(feature = "dp"))]
            {
                if matches!(self.auth_mode, SourceAuthMode::Anonymous) {
                    return Err(IdrError::new(
                        IdrErrorKind::AuthenticationFailed,
                        "Anonymous Source auth is not allowed; provide bearer or device token",
                    ));
                }
                let token = self.auth_token.as_deref().filter(|t| !t.is_empty()).ok_or_else(|| {
                    IdrError::new(
                        IdrErrorKind::AuthenticationFailed,
                        "auth_token required for Source connect",
                    )
                })?;
                Some(token.to_string())
            }
        };

        let mut peer = (self.peer_factory)();
        peer.start(PeerConnectRequest {
            role: PeerRole::Offerer,
            ice_servers_json: None,
        })
        .await?;
        peer.create_local_description().await?;

        // Trickle ICE: send the offer as soon as local SDP exists. Candidates that
        // arrive before Presence WSS is up are buffered and flushed; later ones
        // are forwarded from the event loop below (browser/native auto-fire).
        let mut buffered_ice: Vec<(String, String)> = Vec::new();
        let mut gathering_done = false;
        let sdp_deadline = crate::time::Instant::now() + std::time::Duration::from_secs(5);
        let local_sdp = loop {
            tokio::select! {
                event = peer.next_event() => {
                    match event? {
                        PeerEvent::LocalDescription { sdp_type, sdp } if sdp_type == "offer" => {
                            break sdp;
                        }
                        PeerEvent::LocalCandidate { candidate, mid } => {
                            buffered_ice.push((candidate, mid));
                        }
                        PeerEvent::GatheringComplete => {
                            gathering_done = true;
                        }
                        other => {
                            return Err(IdrError::new(
                                IdrErrorKind::IceFailed,
                                format!("unexpected peer event while creating offer: {other:?}"),
                            ));
                        }
                    }
                }
                _ = crate::time::sleep_until(sdp_deadline) => {
                    return Err(IdrError::new(
                        IdrErrorKind::IceFailed,
                        "timed out waiting for local offer SDP",
                    ));
                }
            }
        };
        if local_sdp.is_empty() {
            return Err(IdrError::new(IdrErrorKind::IceFailed, "offer SDP missing"));
        }

        let session_id = Uuid::new_v4();
        let request = WebRtcSessionRequest {
            version: PROTOCOL_VERSION,
            message_type: SignalingMessageType::WebRtcSessionRequest,
            message_id: Uuid::new_v4(),
            session_id,
            target_fqhn: target_fqhn.to_string(),
            source: self.source_agent_identity(auth_token),
            source_region: self.source_region.clone(),
            sdp: SessionDescription {
                sdp_type: "offer".into(),
                sdp: local_sdp,
            },
            // Production default: allow P2P + relay. Set Relay only when Source must not use P2P.
            ice_transport_policy: IceTransportPolicy::All,
            signature: None,
        };

        let mut channel = self.signaling.begin_session(request).await?;

        // Flush local ICE that arrived before the signaling channel existed.
        for (candidate, mid) in buffered_ice {
            let msg = WebRtcIceCandidate {
                version: PROTOCOL_VERSION,
                message_type: SignalingMessageType::WebRtcIceCandidate,
                message_id: Uuid::new_v4(),
                session_id,
                candidate,
                mid,
                signature: None,
            };
            channel.send_ice(msg).await?;
        }
        if gathering_done {
            let complete = WebRtcIceComplete {
                version: PROTOCOL_VERSION,
                message_type: SignalingMessageType::WebRtcIceComplete,
                message_id: Uuid::new_v4(),
                session_id,
            };
            let _ = channel
                .send_json(&serde_json::to_string(&complete).map_err(|e| {
                    IdrError::new(IdrErrorKind::ProtocolError, format!("ice complete: {e}"))
                })?)
                .await;
        }

        // Apply answer as soon as it arrives (do NOT wait for Active first — Active requires
        // ICE/DataChannel, which requires the answer). Concurrently trickle local ICE and
        // ingest remote ICE until the DataChannel opens.
        let mut answer_applied = false;
        let mut remote_ice_before_answer: Vec<(String, String)> = Vec::new();
        loop {
            tokio::select! {
                msg = channel.next_message() => {
                    match msg? {
                        SignalingMessage::Pending(pending) => {
                            if let Some(ice) = pending.ice.as_ref() {
                                match build_rtc_ice_servers(ice, &[]) {
                                    Ok(servers) if !servers.is_empty() => {
                                        if let Ok(json) = serde_json::to_string(&servers) {
                                            if let Err(e) = peer.set_ice_servers_json(&json) {
                                                tracing::warn!(
                                                    error = %e,
                                                    "failed to apply Presence ICE servers"
                                                );
                                            }
                                        }
                                    }
                                    Ok(_) => {}
                                    Err(e) => {
                                        tracing::warn!(
                                            error = %e,
                                            "invalid Presence session ICE; keeping local servers"
                                        );
                                    }
                                }
                            }
                        }
                        SignalingMessage::Answer(ans) => {
                            peer.set_remote_description("answer", &ans.sdp.sdp).await?;
                            answer_applied = true;
                            for (candidate, mid) in remote_ice_before_answer.drain(..) {
                                peer.add_remote_candidate(&candidate, &mid)?;
                            }
                            tracing::info!(%session_id, "remote answer applied");
                        }
                        SignalingMessage::IceCandidate(c) => {
                            if answer_applied {
                                peer.add_remote_candidate(&c.candidate, &c.mid)?;
                            } else {
                                remote_ice_before_answer.push((c.candidate, c.mid));
                            }
                        }
                        SignalingMessage::IceComplete { .. } => {}
                        SignalingMessage::SessionAck { result, detail, .. } => {
                            use idr_protocol::webrtc_signaling::WebRtcSessionResultCode::*;
                            match result {
                                Active => {
                                    if answer_applied {
                                        break;
                                    }
                                }
                                Negotiating | Received => {}
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
                }
                event = peer.next_event() => {
                    match event? {
                        PeerEvent::DataChannelOpen => {
                            tracing::info!(%session_id, "datachannel open");
                            break;
                        }
                        PeerEvent::LocalCandidate { candidate, mid } => {
                            let msg = WebRtcIceCandidate {
                                version: PROTOCOL_VERSION,
                                message_type: SignalingMessageType::WebRtcIceCandidate,
                                message_id: Uuid::new_v4(),
                                session_id,
                                candidate,
                                mid,
                                signature: None,
                            };
                            if let Err(e) = channel.send_ice(msg).await {
                                tracing::warn!(error = %e, "failed to send local ICE candidate");
                            }
                        }
                        PeerEvent::GatheringComplete => {
                            let complete = WebRtcIceComplete {
                                version: PROTOCOL_VERSION,
                                message_type: SignalingMessageType::WebRtcIceComplete,
                                message_id: Uuid::new_v4(),
                                session_id,
                            };
                            if let Ok(json) = serde_json::to_string(&complete) {
                                let _ = channel.send_json(&json).await;
                            }
                        }
                        PeerEvent::BinaryMessage(_) | PeerEvent::LocalDescription { .. } => {}
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
                    }
                }
            }
        }

        if !answer_applied {
            return Err(IdrError::new(
                IdrErrorKind::SignalingFailed,
                "missing WebRTC answer",
            ));
        }

        let _ = channel.close().await;
        let (control_tx, control_rx) = tokio::sync::mpsc::channel(64);
        let mut session = SourceSession {
            target_fqhn: target_fqhn.to_string(),
            peer: Arc::new(Mutex::new(peer)),
            demux: StreamDemux::with_control(32, control_tx),
            control_rx,
            ids: StreamIdAllocator::default(),
            pump_started: false,
            prefer_flow_control: true,
            named_services: Vec::new(),
            catalog_entries: Vec::new(),
        };
        // Catalog rides the DataChannel (or future relay pipe), not Presence.
        if let Err(e) = session.refresh_named_services().await {
            tracing::warn!(error = %e, "Target services catalog unavailable after connect");
        }
        Ok(session)
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
    /// Services last advertised by Target on this session.
    named_services: Vec<String>,
    /// Structured catalog (credential mode / TLS). Empty when Target is names-only.
    catalog_entries: Vec<idr_protocol::stream_mux::ServiceCatalogEntry>,
}

impl SourceSession {
    /// Named services last received from Target over the mux (may be empty).
    pub fn named_services(&self) -> &[String] {
        &self.named_services
    }

    /// Structured catalog entries (may be empty for legacy Targets).
    pub fn catalog_entries(&self) -> &[idr_protocol::stream_mux::ServiceCatalogEntry] {
        &self.catalog_entries
    }

    /// Ask Target for its live `openStream` catalog over the DataChannel / relay path.
    pub async fn refresh_named_services(&mut self) -> Result<()> {
        let req = StreamFrame::ServicesCatalogRequest;
        let enc = req.encode()?;
        {
            let mut peer = self.peer.lock().await;
            peer.send_binary(&enc)?;
        }
        let deadline = crate::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut got_names = false;
        let mut detailed_deadline: Option<crate::time::Instant> = None;
        loop {
            while let Ok(ev) = self.control_rx.try_recv() {
                match ev {
                    crate::mux_session::DemuxEvent::ServicesCatalogDetailed { entries } => {
                        self.named_services =
                            entries.iter().map(|e| e.name.clone()).collect();
                        self.catalog_entries = entries;
                        tracing::info!(
                            count = self.catalog_entries.len(),
                            "received Target services catalog (detailed)"
                        );
                        return Ok(());
                    }
                    crate::mux_session::DemuxEvent::ServicesCatalog { services } => {
                        self.named_services = services.clone();
                        if self.catalog_entries.is_empty() {
                            self.catalog_entries = services
                                .into_iter()
                                .map(idr_protocol::stream_mux::ServiceCatalogEntry::name_only)
                                .collect();
                        }
                        got_names = true;
                        // Target may also send ServicesCatalogDetailed; wait briefly.
                        detailed_deadline = Some(
                            crate::time::Instant::now() + std::time::Duration::from_millis(50),
                        );
                        tracing::info!(
                            count = self.named_services.len(),
                            "received Target services catalog (names)"
                        );
                    }
                    _ => {}
                }
            }
            if let Some(d) = detailed_deadline {
                if crate::time::Instant::now() >= d {
                    return Ok(());
                }
            }
            let left = deadline.saturating_duration_since(crate::time::Instant::now());
            if left.is_zero() {
                if got_names {
                    return Ok(());
                }
                return Err(IdrError::new(
                    IdrErrorKind::Timeout,
                    "timed out waiting for Target ServicesCatalog",
                ));
            }
            let slice = left.min(std::time::Duration::from_millis(50));
            match crate::time::timeout(slice, self.drive_until_data()).await {
                Ok(Ok(Some(bytes))) => self.ingest_dc_frame(bytes).await?,
                Ok(Ok(None)) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {}
            }
        }
    }

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
                service_name: Some(service.into()),
                host: None,
                port: None,
            },
        };
        self.open_stream(request).await
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
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
        tracing::info!(stream_id = stream_id.0, "sent StreamFrame::Open");

        let (profile, initial_window) = if self.prefer_flow_control {
            // Do NOT block forever on the next peer event — after DC open the peer may be
            // quiet until Target answers. Pump with a deadline while waiting for OpenOk.
            self.wait_for_open_handshake(stream_id.0, std::time::Duration::from_secs(10))
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
    /// Pump peer events into demux until OpenOk/OpenError for `stream_id`, or fall back to Legacy.
    async fn wait_for_open_handshake(
        &mut self,
        stream_id: u32,
        timeout: std::time::Duration,
    ) -> Result<(idr_protocol::stream_mux::MuxProfile, u32)> {
        let deadline = crate::time::Instant::now() + timeout;
        loop {
            if let Ok(ev) = self.control_rx.try_recv() {
                if let Some(result) = Self::open_result_from_control(ev, stream_id) {
                    return result;
                }
            }

            let left = deadline.saturating_duration_since(crate::time::Instant::now());
            if left.is_zero() {
                tracing::warn!(
                    stream_id,
                    "OpenOk not received in time; continuing with legacy mux"
                );
                return Ok((
                    idr_protocol::stream_mux::MuxProfile::Legacy,
                    idr_protocol::stream_mux::INITIAL_STREAM_WINDOW,
                ));
            }

            // Cap each peer wait so a quiet DataChannel cannot stall openStream forever.
            let slice = left.min(std::time::Duration::from_millis(200));
            match crate::time::timeout(slice, self.drive_until_data()).await {
                Ok(Ok(Some(bytes))) => {
                    self.ingest_dc_frame(bytes).await?;
                }
                Ok(Ok(None)) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    // No peer event this slice — keep waiting until overall deadline.
                }
            }
        }
    }

    fn open_result_from_control(
        ev: crate::mux_session::DemuxEvent,
        stream_id: u32,
    ) -> Option<Result<(idr_protocol::stream_mux::MuxProfile, u32)>> {
        match ev {
            crate::mux_session::DemuxEvent::OpenOk {
                stream_id: sid,
                initial_window,
            } if sid == stream_id => Some(Ok((
                idr_protocol::stream_mux::MuxProfile::FlowControlV1,
                initial_window,
            ))),
            crate::mux_session::DemuxEvent::OpenError {
                stream_id: sid,
                message,
                ..
            } if sid == stream_id => Some(Err(IdrError::new(
                IdrErrorKind::ConnectionRefused,
                message,
            ))),
            _ => None,
        }
    }

    async fn ingest_dc_frame(&mut self, bytes: Vec<u8>) -> Result<()> {
        let frame = StreamFrame::decode(&bytes)?;
        self.demux.handle_frame(frame).await
    }
}
