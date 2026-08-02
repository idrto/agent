//! Presence PEP client: QUIC with WSS fallback + optional DP credential presentation.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use idr_core::error::{IdrError, IdrErrorKind, Result};
use idr_dp::{
    encode_credential_frame, materialize_mtls_client, DeviceIdentity, MtlsClientMaterial,
};
use idr_protocol::discovery::PresenceServer;
use idr_protocol::webrtc_signaling::{
    WebRtcAnswer, WebRtcIceCandidate, WebRtcSessionRequest, WebRtcSessionResultCode,
};
use serde_json::Value;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::ephemeral::{
    EphemeralSignaling, SessionPending, SignalingMessage, WebRtcSignalingClient,
};
use crate::pep::endpoint::{
    build_transport_attempts, transport_label, PresenceNetworkCaps, PresenceTransportChoice,
};
use crate::pep::quic::PepQuicEndpoint;
use crate::pep::session::PepSession;
use crate::pep::wss::connect_wss;

#[derive(Debug, Clone)]
pub struct PepClientConfig {
    pub prefer_quic: bool,
    pub connect_timeout: Duration,
    pub transport_fallback_delay: Duration,
    pub insecure_dev: bool,
    pub bind: SocketAddr,
    pub network: PresenceNetworkCaps,
}

impl Default for PepClientConfig {
    fn default() -> Self {
        Self {
            prefer_quic: true,
            connect_timeout: Duration::from_secs(10),
            transport_fallback_delay: Duration::from_millis(150),
            insecure_dev: false,
            bind: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            network: PresenceNetworkCaps::all(),
        }
    }
}

/// Source-facing Presence PEP connector (QUIC → WSS).
pub struct PepClient {
    servers: Vec<PresenceServer>,
    cfg: PepClientConfig,
    identity: Option<DeviceIdentity>,
    mtls: Option<MtlsClientMaterial>,
}

impl PepClient {
    pub fn new(servers: Vec<PresenceServer>, cfg: PepClientConfig) -> Self {
        Self {
            servers,
            cfg,
            identity: None,
            mtls: None,
        }
    }

    /// Attach DP DeviceIdentity: materializes mTLS client cert and enables in-band AuthZ.
    pub fn with_identity(mut self, identity: DeviceIdentity) -> Result<Self> {
        let material = materialize_mtls_client(&identity)
            .map_err(|e| IdrError::new(IdrErrorKind::AuthenticationFailed, e.to_string()))?;
        self.mtls = Some(material);
        self.identity = Some(identity);
        Ok(self)
    }

    pub fn identity(&self) -> Option<&DeviceIdentity> {
        self.identity.as_ref()
    }

    pub async fn connect_session(&self) -> Result<PepSession> {
        let mut last_err = None;
        for server in &self.servers {
            match self.connect_server(server).await {
                Ok(session) => {
                    if let Some(id) = &self.identity {
                        let frame = encode_credential_frame(&id.credential).map_err(|e| {
                            IdrError::new(IdrErrorKind::ProtocolError, e.to_string())
                        })?;
                        session.send_bytes(&frame).await?;
                        debug!(ski = %id.ski, "presented dp.credential.v1 to PEP");
                    }
                    return Ok(session);
                }
                Err(e) => {
                    warn!(presence_id = %server.presence_id, error = %e, "PEP connect failed");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            IdrError::new(
                IdrErrorKind::SignalingFailed,
                "no Presence servers configured",
            )
        }))
    }

    async fn connect_server(&self, server: &PresenceServer) -> Result<PepSession> {
        let attempts = build_transport_attempts(server, &self.cfg.network, self.cfg.prefer_quic);
        if attempts.is_empty() {
            return Err(IdrError::new(
                IdrErrorKind::SignalingFailed,
                "no compatible presence transports",
            ));
        }

        let quic = PepQuicEndpoint::new(self.cfg.bind, self.cfg.insecure_dev, self.mtls.as_ref())?;
        let mut last_err = None;
        for (i, choice) in attempts.into_iter().enumerate() {
            if i > 0 {
                tokio::time::sleep(self.cfg.transport_fallback_delay).await;
            }
            let label = transport_label(choice);
            debug!(transport = label, presence = %server.presence_id, "attempting PEP connect");
            let result = match choice {
                PresenceTransportChoice::Quic(addr) => self.connect_quic(&quic, server, addr).await,
                PresenceTransportChoice::Wss => {
                    connect_wss(
                        server,
                        self.cfg.connect_timeout,
                        self.mtls.as_ref(),
                        self.cfg.insecure_dev,
                    )
                    .await
                }
            };
            match result {
                Ok(s) => return Ok(s),
                Err(e) => {
                    warn!(transport = label, error = %e, "PEP transport failed");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            IdrError::new(IdrErrorKind::SignalingFailed, "all PEP transports failed")
        }))
    }

    async fn connect_quic(
        &self,
        quic: &PepQuicEndpoint,
        server: &PresenceServer,
        addr: SocketAddr,
    ) -> Result<PepSession> {
        let connection = quic.connect(server, addr, self.cfg.connect_timeout).await?;
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, e.to_string()))?;
        Ok(PepSession::Quic {
            connection,
            send: tokio::sync::Mutex::new(send),
            recv: tokio::sync::Mutex::new(recv),
        })
    }
}

#[async_trait]
impl WebRtcSignalingClient for PepClient {
    async fn begin_session(
        &mut self,
        request: WebRtcSessionRequest,
    ) -> Result<Box<dyn EphemeralSignaling>> {
        let session = Arc::new(self.connect_session().await?);
        let req_json = serde_json::to_string(&request)
            .map_err(|e| IdrError::new(IdrErrorKind::ProtocolError, e.to_string()))?;
        session.send_json(&req_json).await?;
        Ok(Box::new(PepEphemeral {
            session,
            session_id: request.session_id,
        }))
    }
}

struct PepEphemeral {
    session: Arc<PepSession>,
    session_id: Uuid,
}

#[async_trait]
impl EphemeralSignaling for PepEphemeral {
    async fn next_message(&mut self) -> Result<SignalingMessage> {
        let raw = self.session.recv_json().await?;
        parse_signaling_message(&raw, self.session_id)
    }

    async fn send_ice(&mut self, candidate: WebRtcIceCandidate) -> Result<()> {
        let json = serde_json::to_string(&candidate)
            .map_err(|e| IdrError::new(IdrErrorKind::ProtocolError, e.to_string()))?;
        self.session.send_json(&json).await
    }

    async fn send_json(&mut self, json: &str) -> Result<()> {
        self.session.send_json(json).await
    }

    async fn close(&mut self) -> Result<()> {
        self.session.close().await
    }
}

fn parse_signaling_message(raw: &str, session_id: Uuid) -> Result<SignalingMessage> {
    let value: Value = serde_json::from_str(raw)
        .map_err(|e| IdrError::new(IdrErrorKind::ProtocolError, e.to_string()))?;
    let msg_type = value
        .get("message_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    match msg_type {
        "session_pending" | "webrtc_session_pending" => {
            let pending: SessionPending = serde_json::from_value(value)
                .map_err(|e| IdrError::new(IdrErrorKind::ProtocolError, e.to_string()))?;
            Ok(SignalingMessage::Pending(pending))
        }
        "webrtc_answer" => {
            let answer: WebRtcAnswer = serde_json::from_value(value)
                .map_err(|e| IdrError::new(IdrErrorKind::ProtocolError, e.to_string()))?;
            Ok(SignalingMessage::Answer(answer))
        }
        "webrtc_ice_candidate" => {
            let cand: WebRtcIceCandidate = serde_json::from_value(value)
                .map_err(|e| IdrError::new(IdrErrorKind::ProtocolError, e.to_string()))?;
            Ok(SignalingMessage::IceCandidate(cand))
        }
        "webrtc_ice_complete" => Ok(SignalingMessage::IceComplete { session_id }),
        "webrtc_session_ack" => {
            let result = value
                .get("result")
                .cloned()
                .and_then(|v| serde_json::from_value::<WebRtcSessionResultCode>(v).ok())
                .unwrap_or(WebRtcSessionResultCode::Failed);
            let detail = value
                .get("detail")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let sid = value
                .get("session_id")
                .and_then(|v| serde_json::from_value::<Uuid>(v.clone()).ok())
                .unwrap_or(session_id);
            Ok(SignalingMessage::SessionAck {
                session_id: sid,
                result,
                detail,
            })
        }
        "error" => Ok(SignalingMessage::Error {
            message: value
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("presence error")
                .to_string(),
        }),
        other => Ok(SignalingMessage::Error {
            message: format!("unhandled presence message_type: {other}"),
        }),
    }
}
