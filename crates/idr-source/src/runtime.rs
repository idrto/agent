//! Source runtime and session orchestration.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use idr_core::error::{IdrError, IdrErrorKind, Result};
use idr_core::session::{OpenStreamRequest, PeerSession};
use idr_core::stream::{LogicalStream, StreamId};
#[cfg(feature = "dp")]
use idr_dp::DeviceIdentity;
use idr_protocol::signaling::SignalingMessageType;
use idr_core::{MuxOut, MuxOutRx, StreamPriority, BULK_LOW_WATER};
use idr_protocol::stream_mux::{
    MuxProfile, StreamFrame, StreamOpenMeta, CREDIT_CONN_WINDOW, FEATURE_FLOW_CREDIT,
    FEATURE_PEER_OPEN, STREAM_MUX_VERSION,
};
use idr_protocol::webrtc_ice::{build_rtc_ice_servers, IceTransportPolicy};
use idr_protocol::webrtc_signaling::{
    SessionDescription, SourceAgentIdentity, SourceAuthMode, SourceProof, WebRtcIceCandidate,
    WebRtcIceComplete, WebRtcSessionRequest,
};
use idr_protocol::PROTOCOL_VERSION;
use idr_signaling::ephemeral::{SignalingMessage, WebRtcSignalingClient};
use idr_webrtc::transport::{PeerConnectRequest, PeerEvent, PeerRole, PeerTransport};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::mux_session::{IncomingStream, MuxLogicalStream, StreamDemux, STREAM_INBOX_FRAMES};

/// Frames each outbound priority queue holds before writers wait.
const OUT_QUEUE_FRAMES: usize = 64;
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
        #[cfg(not(target_arch = "wasm32"))] peer_factory: impl Fn() -> Box<dyn PeerTransport>
            + Send
            + Sync
            + 'static,
        #[cfg(target_arch = "wasm32")] peer_factory: impl Fn() -> Box<dyn PeerTransport> + 'static,
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
        #[cfg(not(target_arch = "wasm32"))] peer_factory: impl Fn() -> Box<dyn PeerTransport>
            + Send
            + Sync
            + 'static,
        #[cfg(target_arch = "wasm32")] peer_factory: impl Fn() -> Box<dyn PeerTransport> + 'static,
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

    /// Proof of the enrolled device key for this session: signed with the
    /// identity's private key, carrying its certificate chain. None when not
    /// enrolled (no identity, or no issued certificate yet).
    #[cfg(feature = "dp")]
    fn source_proof(&self, session_id: Uuid, target_fqhn: &str) -> Option<SourceProof> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let id = self.identity.as_ref()?;
        let chain = id.chain_pem.clone().or_else(|| id.cert_pem.clone())?;
        let seed: [u8; 32] = URL_SAFE_NO_PAD
            .decode(id.private_jwk.get("d")?.as_str()?)
            .ok()?
            .try_into()
            .ok()?;
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        Some(SourceProof::sign(
            &key,
            id.ski.clone(),
            chain,
            session_id,
            target_fqhn,
            chrono::Utc::now(),
        ))
    }

    #[cfg(not(feature = "dp"))]
    fn source_proof(&self, _session_id: Uuid, _target_fqhn: &str) -> Option<SourceProof> {
        None
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
            policy: None,
        }
    }

    /// Connect to `target_fqhn` over WebRTC (Presence signaling + P2P/TURN data).
    ///
    /// Uses `{host}--{entity}.idr.to` on the wire (`.idr.to` appended if missing).
    /// DEF-encode is applied only inside Presence placement (index selection).
    pub async fn connect(&mut self, target_fqhn: &str) -> Result<SourceSession> {
        let target_fqhn = idr_protocol::fqhn::canonicalize(target_fqhn)
            .map_err(|e| IdrError::new(IdrErrorKind::InvalidArgument, e.to_string()))?;
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
                    let token = self
                        .auth_token
                        .as_deref()
                        .filter(|t| !t.is_empty())
                        .ok_or_else(|| {
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
                let token = self
                    .auth_token
                    .as_deref()
                    .filter(|t| !t.is_empty())
                    .ok_or_else(|| {
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
        let offer_sdp = local_sdp.clone();
        let mut remote_sdp = String::new();
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
            ice_transport_policy: IceTransportPolicy::All,
            source_proof: self.source_proof(session_id, &target_fqhn),
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
        // Presence waits ~60s for Target; fail slightly sooner with a clear error.
        let signaling_deadline = crate::time::Instant::now() + std::time::Duration::from_secs(55);
        loop {
            tokio::select! {
                msg = channel.next_message() => {
                    match msg? {
                        SignalingMessage::Pending(pending) => {
                            let ice_json = pending
                                .ice
                                .as_ref()
                                .map(|ice| {
                                    if ice.has_turn_credentials() {
                                        tracing::info!(
                                            %session_id,
                                            "received TURN credentials"
                                        );
                                    }
                                    match build_rtc_ice_servers(ice, &[]) {
                                        Ok(servers) if !servers.is_empty() => {
                                            serde_json::to_string(&servers).ok()
                                        }
                                        Ok(_) => Some("[]".into()),
                                        Err(e) => {
                                            tracing::warn!(
                                                error = %e,
                                                "invalid Presence session ICE; gathering without extra servers"
                                            );
                                            Some("[]".into())
                                        }
                                    }
                                })
                                .flatten()
                                .unwrap_or_else(|| "[]".into());
                            if let Err(e) = peer.set_ice_servers_json(&ice_json) {
                                tracing::warn!(
                                    error = %e,
                                    "failed to apply Presence ICE servers"
                                );
                            }
                        }
                        SignalingMessage::Answer(ans) => {
                            remote_sdp = ans.sdp.sdp.clone();
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
                        PeerEvent::BinaryMessage(_)
                        | PeerEvent::LocalDescription { .. }
                        | PeerEvent::BufferedAmountLow => {}
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
                _ = crate::time::sleep_until(signaling_deadline) => {
                    return Err(IdrError::new(
                        IdrErrorKind::SignalingFailed,
                        if answer_applied {
                            "timed out waiting for WebRTC datachannel after answer"
                        } else {
                            "timed out waiting for Target WebRTC answer (is target-agent registered on Presence?)"
                        },
                    ));
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
        let path = peer
            .selected_candidate_pair()
            .and_then(|(l, r)| idr_protocol::webrtc_ice::IcePath::of_pair(&l, &r));
        tracing::info!(%session_id, path = path.map_or("unknown", |p| p.as_str()), "selected ICE path");
        let mut session = SourceSession::start(target_fqhn.to_string(), peer);
        session.bind_ctx = idr_protocol::peer_bind::BindContext {
            session_id: session_id.to_string(),
            target_fqhn: target_fqhn.to_string(),
            offerer_fingerprint: idr_protocol::peer_bind::sdp_fingerprint(&offer_sdp)
                .unwrap_or_default(),
            answerer_fingerprint: idr_protocol::peer_bind::sdp_fingerprint(&remote_sdp)
                .unwrap_or_default(),
            path,
        };
        // Offer credit flow control and Target-initiated streams first; the HelloAck is
        // ingested while the catalog reply is awaited. Any Target that serves the
        // catalog request decodes Hello; one that doesn't ack a feature keeps the
        // pre-feature behavior.
        let mut features = MuxProfile::FlowControlV1.advertised_features();
        features.push(FEATURE_FLOW_CREDIT.into());
        features.push(FEATURE_PEER_OPEN.into());
        session
            .send_control(&StreamFrame::Hello {
                version: STREAM_MUX_VERSION,
                features,
                conn_window: CREDIT_CONN_WINDOW,
            })
            .await?;
        // Catalog rides the DataChannel (or future relay pipe), not Presence.
        if let Err(e) = session.refresh_named_services().await {
            tracing::warn!(error = %e, "Target services catalog unavailable after connect");
        }
        Ok(session)
    }
}

/// Owns the transport for the life of the session: routes inbound frames through
/// the demux and sends queued frames, control first and bulk only while the
/// DataChannel buffer is below its low-water mark.
async fn drive(
    mut peer: Box<dyn PeerTransport>,
    demux: Arc<Mutex<StreamDemux>>,
    mut out: MuxOutRx,
    mut stop: tokio::sync::oneshot::Receiver<()>,
    closed: tokio::sync::watch::Sender<bool>,
) {
    loop {
        let bulk_open = peer.buffered_amount() < BULK_LOW_WATER;
        tokio::select! {
            biased;
            _ = &mut stop => break,
            event = peer.next_event() => match event {
                Ok(PeerEvent::BinaryMessage(bytes)) => {
                    let frame = match StreamFrame::decode(&bytes) {
                        Ok(f) => f,
                        Err(e) => {
                            tracing::warn!(error = %e, "undecodable mux frame");
                            continue;
                        }
                    };
                    let replies = demux.lock().await.handle_frame(frame).await;
                    let Ok(replies) = replies else { break };
                    if replies
                        .iter()
                        .filter_map(|f| f.encode().ok())
                        .any(|b| peer.send_binary(&b).is_err())
                    {
                        break;
                    }
                }
                Ok(PeerEvent::Closed | PeerEvent::DataChannelClosed | PeerEvent::ConnectionFailed)
                | Err(_) => break,
                Ok(_) => {}
            },
            frame = out.next(bulk_open) => match frame {
                Some(bytes) if peer.send_binary(&bytes).is_ok() => {}
                _ => break,
            },
            _ = crate::time::sleep(std::time::Duration::from_millis(5)), if !bulk_open => {}
        }
    }
    peer.close();
    demux.lock().await.close_all();
    let _ = closed.send(true);
    tracing::info!("source session driver stopped");
}

pub struct SourceSession {
    target_fqhn: String,
    out: MuxOut,
    demux: Arc<Mutex<StreamDemux>>,
    control_rx: tokio::sync::mpsc::Receiver<crate::mux_session::DemuxEvent>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    opener: SessionOpener,
    /// Becomes true when the DataChannel is gone.
    closed: tokio::sync::watch::Receiver<bool>,
    /// Session facts for the peer-binding exchange.
    bind_ctx: idr_protocol::peer_bind::BindContext,
    /// Services last advertised by Target on this session.
    named_services: Vec<String>,
    /// Structured catalog (credential mode / TLS). Empty when Target is names-only.
    catalog_entries: Vec<idr_protocol::stream_mux::ServiceCatalogEntry>,
}

impl SourceSession {
    /// Hand the open DataChannel to a background driver task.
    fn start(target_fqhn: String, peer: Box<dyn PeerTransport>) -> Self {
        let (control_tx, control_rx) = tokio::sync::mpsc::channel(64);
        let (out, out_rx) = idr_core::mux_out(OUT_QUEUE_FRAMES);
        let demux = Arc::new(Mutex::new(StreamDemux::new(
            STREAM_INBOX_FRAMES,
            out.clone(),
            control_tx,
        )));
        let (stop, stop_rx) = tokio::sync::oneshot::channel();
        let (closed_tx, closed) = tokio::sync::watch::channel(false);
        crate::time::spawn(drive(peer, demux.clone(), out_rx, stop_rx, closed_tx));
        let opener = SessionOpener {
            target_fqhn: target_fqhn.clone(),
            out: out.clone(),
            demux: demux.clone(),
            next_id: Arc::new(AtomicU32::new(1)),
        };
        Self {
            bind_ctx: idr_protocol::peer_bind::BindContext {
                session_id: String::new(),
                target_fqhn: target_fqhn.clone(),
                offerer_fingerprint: String::new(),
                answerer_fingerprint: String::new(),
                path: None,
            },
            target_fqhn,
            out,
            demux,
            control_rx,
            stop: Some(stop),
            opener,
            closed,
            named_services: Vec::new(),
            catalog_entries: Vec::new(),
        }
    }

    /// Resolves once the session has ended (peer closed, connection failed, or `close`).
    pub fn closed(&self) -> impl std::future::Future<Output = ()> + Send + 'static {
        let mut rx = self.closed.clone();
        async move {
            let _ = rx.wait_for(|c| *c).await;
        }
    }

    /// A handle that opens streams on this session concurrently (e.g. a
    /// transfer's control and data streams), usable from other tasks.
    pub fn opener(&self) -> SessionOpener {
        self.opener.clone()
    }

    /// Session id, Target FQHN and both DTLS fingerprints, for `peer_bind`.
    pub fn bind_context(&self) -> &idr_protocol::peer_bind::BindContext {
        &self.bind_ctx
    }

    /// Named services last received from Target over the mux (may be empty).
    pub fn named_services(&self) -> &[String] {
        &self.named_services
    }

    /// Structured catalog entries (may be empty for legacy Targets).
    pub fn catalog_entries(&self) -> &[idr_protocol::stream_mux::ServiceCatalogEntry] {
        &self.catalog_entries
    }

    async fn send_control(&self, frame: &StreamFrame) -> Result<()> {
        if self.out.control(frame.encode()?).await {
            Ok(())
        } else {
            Err(IdrError::new(IdrErrorKind::TransportClosed, "session closed"))
        }
    }

    async fn next_control(
        &mut self,
        deadline: crate::time::Instant,
    ) -> Result<Option<crate::mux_session::DemuxEvent>> {
        let left = deadline.saturating_duration_since(crate::time::Instant::now());
        match crate::time::timeout(left, self.control_rx.recv()).await {
            Ok(Some(ev)) => Ok(Some(ev)),
            Ok(None) => Err(IdrError::new(
                IdrErrorKind::TransportClosed,
                "datachannel closed",
            )),
            Err(_) => Ok(None),
        }
    }

    /// Ask Target for its live `openStream` catalog over the DataChannel / relay path.
    pub async fn refresh_named_services(&mut self) -> Result<()> {
        self.send_control(&StreamFrame::ServicesCatalogRequest).await?;
        let mut deadline = crate::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut got_names = false;
        loop {
            match self.next_control(deadline).await? {
                Some(crate::mux_session::DemuxEvent::ServicesCatalogDetailed { entries }) => {
                    self.named_services = entries.iter().map(|e| e.name.clone()).collect();
                    self.catalog_entries = entries;
                    tracing::info!(
                        count = self.catalog_entries.len(),
                        "received Target services catalog (detailed)"
                    );
                    return Ok(());
                }
                Some(crate::mux_session::DemuxEvent::ServicesCatalog { services }) => {
                    self.named_services = services.clone();
                    if self.catalog_entries.is_empty() {
                        self.catalog_entries = services
                            .into_iter()
                            .map(idr_protocol::stream_mux::ServiceCatalogEntry::name_only)
                            .collect();
                    }
                    got_names = true;
                    // Target may also send ServicesCatalogDetailed; wait briefly.
                    deadline = crate::time::Instant::now() + std::time::Duration::from_millis(50);
                    tracing::info!(
                        count = self.named_services.len(),
                        "received Target services catalog (names)"
                    );
                }
                Some(_) => {}
                None if got_names => return Ok(()),
                None => {
                    return Err(IdrError::new(
                        IdrErrorKind::Timeout,
                        "timed out waiting for Target ServicesCatalog",
                    ))
                }
            }
        }
    }

    /// The background driver now delivers frames; kept for callers that used to
    /// pump the session by hand.
    pub async fn poll_incoming(&mut self) -> Result<()> {
        crate::time::sleep(std::time::Duration::from_millis(1)).await;
        Ok(())
    }

    /// See [`poll_incoming`](Self::poll_incoming).
    pub async fn pump_once(&mut self) -> Result<()> {
        self.poll_incoming().await
    }

    /// Accept Target-initiated streams (`peer_open_v1`) for `services`. Opens for
    /// any other service are refused. Replaces an earlier registration.
    pub async fn accept_streams(
        &mut self,
        services: &[&str],
    ) -> tokio::sync::mpsc::Receiver<IncomingStream> {
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let services = services.iter().map(|s| s.to_string()).collect();
        self.demux.lock().await.accept(services, tx);
        rx
    }

    pub async fn open_named_stream(&mut self, service: &str) -> Result<Box<dyn LogicalStream>> {
        self.open_named_stream_with(service, StreamPriority::Interactive)
            .await
    }

    /// Open `service` with an explicit scheduling class (bulk for file transfer).
    pub async fn open_named_stream_with(
        &mut self,
        service: &str,
        priority: StreamPriority,
    ) -> Result<Box<dyn LogicalStream>> {
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
        self.open_with(request, priority).await
    }

    async fn open_with(
        &mut self,
        request: OpenStreamRequest,
        priority: StreamPriority,
    ) -> Result<Box<dyn LogicalStream>> {
        self.opener.open_request(request, priority).await
    }
}

/// Opens streams on a live [`SourceSession`]; cheap to clone, safe to use concurrently.
#[derive(Clone)]
pub struct SessionOpener {
    target_fqhn: String,
    out: MuxOut,
    demux: Arc<Mutex<StreamDemux>>,
    /// Source-initiated stream ids are odd.
    next_id: Arc<AtomicU32>,
}

impl SessionOpener {
    pub async fn open(&self, service: &str, priority: StreamPriority) -> Result<Box<dyn LogicalStream>> {
        let kind = default_service_kind(service).ok_or_else(|| {
            IdrError::new(IdrErrorKind::ServiceNotFound, format!("unknown service '{service}'"))
        })?;
        self.open_request(
            OpenStreamRequest {
                service: service.into(),
                kind,
                meta: StreamOpenMeta {
                    target_fqhn: self.target_fqhn.clone(),
                    service_name: Some(service.into()),
                    host: None,
                    port: None,
                },
            },
            priority,
        )
        .await
    }

    async fn open_request(
        &self,
        request: OpenStreamRequest,
        priority: StreamPriority,
    ) -> Result<Box<dyn LogicalStream>> {
        let stream_id = StreamId(self.next_id.fetch_add(2, Ordering::Relaxed));
        let (rx, answer) = {
            let mut d = self.demux.lock().await;
            (d.register(stream_id.0), d.expect_open(stream_id.0))
        };
        let open = StreamFrame::Open {
            stream_id: stream_id.0,
            kind: request.kind,
            meta: request.meta,
        };
        if !self.out.control(open.encode()?).await {
            return Err(IdrError::new(IdrErrorKind::TransportClosed, "session closed"));
        }
        tracing::info!(stream_id = stream_id.0, "sent StreamFrame::Open");
        let profile = match crate::time::timeout(std::time::Duration::from_secs(10), answer).await {
            Ok(Ok(Ok(()))) => MuxProfile::FlowControlV1,
            Ok(Ok(Err(message))) => {
                return Err(IdrError::new(IdrErrorKind::ConnectionRefused, message))
            }
            Ok(Err(_)) => {
                return Err(IdrError::new(IdrErrorKind::TransportClosed, "datachannel closed"))
            }
            Err(_) => {
                self.demux.lock().await.forget_open(stream_id.0);
                tracing::warn!(stream_id = stream_id.0, "OpenOk not received in time; continuing with legacy mux");
                MuxProfile::Legacy
            }
        };
        let credit = match profile {
            MuxProfile::FlowControlV1 => self.demux.lock().await.credit_for(stream_id.0),
            MuxProfile::Legacy => None,
        };
        Ok(Box::new(MuxLogicalStream::new(
            stream_id,
            self.out.clone(),
            priority,
            rx,
            profile,
            credit,
        )))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl PeerSession for SourceSession {
    fn target_fqhn(&self) -> &str {
        &self.target_fqhn
    }

    async fn open_stream(&mut self, request: OpenStreamRequest) -> Result<Box<dyn LogicalStream>> {
        self.open_with(request, StreamPriority::Interactive).await
    }

    async fn close(&mut self) -> Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        Ok(())
    }
}

impl Drop for SourceSession {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
