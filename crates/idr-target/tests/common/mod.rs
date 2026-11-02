//! Real WebRTC (libdatachannel) Source ↔ Target in one process: `SourceRuntime`
//! with `NativePeer` against the Target's `run_responder_session`, with Presence
//! replaced by an in-memory relay.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use idr_core::{Connector, ConnectorRegistry, NamedService, PeerSession};
use idr_protocol::signaling::SignalingMessageType;
use idr_protocol::stream_mux::{StreamKind, StreamOpenMeta};
use idr_protocol::webrtc_ice::{
    build_rtc_ice_servers, IceRelayMode, IceServer, IceTransportPolicy, SessionIceConfig, StunPolicy, TurnAllocation,
};
use idr_protocol::webrtc_signaling::{
    SourceAuthMode, WebRtcAnswer, WebRtcIceCandidate, WebRtcSessionAck, WebRtcSessionOffer,
    WebRtcSessionRequest,
};
use idr_signaling::ephemeral::{
    EphemeralSignaling, SessionPending, SignalingMessage, WebRtcSignalingClient,
};
use idr_source::{SourceRuntime, SourceSession};
use idr_target::config::{NginxConfig, WebRtcConfig, WebRtcPolicyConfig};
use idr_target::identity::TargetIdentity;
use idr_target::presence::outbox::PresenceSignalingOutbox;
use idr_target::webrtc::session::{run_responder_session, SessionRuntime};
use idr_target::webrtc::WebRtcSessionManager;
use idr_webrtc::native::NativePeerConfig;
use idr_webrtc::NativePeer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use uuid::Uuid;

pub const FQHN: &str = "loop--test.idr.to";

// ---- Target services ------------------------------------------------------

struct AddrConnector {
    addr: SocketAddr,
    delay: Duration,
}

#[async_trait]
impl Connector for AddrConnector {
    fn name(&self) -> &str {
        "test"
    }
    fn supported_kinds(&self) -> &[StreamKind] {
        &[StreamKind::TcpConnect]
    }
    async fn connect(&self, _: StreamKind, _: &StreamOpenMeta) -> idr_core::Result<TcpStream> {
        tokio::time::sleep(self.delay).await;
        TcpStream::connect(self.addr).await.map_err(|e| {
            idr_core::IdrError::new(idr_core::IdrErrorKind::ConnectionRefused, e.to_string())
        })
    }
}

pub async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

pub async fn sink_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                while matches!(s.read(&mut buf).await, Ok(n) if n > 0) {}
            });
        }
    });
    addr
}

pub fn registry(echo: SocketAddr, sink: SocketAddr) -> ConnectorRegistry {
    let mut reg = ConnectorRegistry::new();
    for (name, addr, delay) in [
        ("echo", echo, Duration::ZERO),
        ("slow", echo, Duration::from_secs(3)),
        ("sink", sink, Duration::ZERO),
    ] {
        reg.register(
            NamedService::new(
                name,
                StreamKind::TcpConnect,
                StreamOpenMeta {
                    target_fqhn: FQHN.into(),
                    host: None,
                    port: None,
                    service_name: Some(name.into()),
                },
            ),
            Arc::new(AddrConnector { addr, delay }),
        );
    }
    reg
}

// ---- In-memory Presence ---------------------------------------------------

pub struct LoopPresence {
    pub connectors: Arc<ConnectorRegistry>,
    /// The Target's transfer endpoint (None: transfer disabled).
    pub transfers: Option<Arc<idr_target::webrtc::local::TransferEndpoint>>,
    /// The Source SKI Presence verified and signed into the offer (None: unverified).
    pub attested_ski: Option<String>,
    /// TURN servers: both peers then use relay-only ICE (None: host candidates only).
    pub relay: Option<Vec<IceServer>>,
}

#[async_trait]
impl WebRtcSignalingClient for LoopPresence {
    async fn begin_session(
        &mut self,
        req: WebRtcSessionRequest,
    ) -> idr_core::Result<Box<dyn EphemeralSignaling>> {
        let session_id = req.session_id;
        let sessions = WebRtcSessionManager::new(WebRtcConfig::default());
        sessions.try_acquire(session_id).unwrap().keep_alive();
        let policy = if self.relay.is_some() { IceTransportPolicy::Relay } else { IceTransportPolicy::All };
        let ice = SessionIceConfig {
            relay_mode: IceRelayMode::Platform,
            stun_policy: StunPolicy::GoogleAndIdr,
            stun_servers: Some(Vec::new()),
            turn: self.relay.clone().map(|servers| TurnAllocation {
                turn_node_id: "test-turn".into(),
                region: "local".into(),
                servers,
            }),
            byor: None,
            ice_transport_policy: policy,
            p2p_only: self.relay.is_none(),
        };
        let pending_ice = self.relay.is_some().then(|| ice.clone());
        let target_ice = if self.relay.is_some() { build_rtc_ice_servers(&ice, &[]).unwrap() } else { Vec::new() };
        let offer = WebRtcSessionOffer {
            version: req.version,
            message_type: SignalingMessageType::WebRtcSessionOffer,
            message_id: Uuid::new_v4(),
            session_id,
            target_fqhn: FQHN.into(),
            source: {
                let mut source = req.source;
                source.policy = self.attested_ski.clone().map(|ski| {
                    idr_protocol::webrtc_signaling::SourcePolicy {
                        ski,
                        zone: None,
                        allowed_services: vec!["*".into()],
                        policy_version: 0,
                    }
                });
                source
            },
            sdp: req.sdp,
            ice,
            session_token: "loopback".into(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(60),
            presence_generation: 1,
            signature: String::new(),
        };
        let (tx, rx) = mpsc::unbounded_channel();
        let rt = SessionRuntime {
            offer,
            ice_servers: target_ice,
            ice_transport_policy: policy,
            outbox: PresenceSignalingOutbox::from_wss(tx),
            identity: TargetIdentity::load_or_generate(None).unwrap(),
            sessions: sessions.clone(),
            nginx: NginxConfig::default(),
            policy: WebRtcPolicyConfig::default(),
            fqhn: FQHN.into(),
            connectors: self.connectors.clone(),
            transfers: self.transfers.clone(),
        };
        tokio::spawn(async move {
            if let Err(e) = run_responder_session(rt).await {
                eprintln!("target session ended: {e}");
            }
        });
        Ok(Box::new(LoopChannel {
            session_id,
            sessions,
            from_target: rx,
            sent_pending: false,
            pending_ice,
        }))
    }
}

struct LoopChannel {
    session_id: Uuid,
    sessions: Arc<WebRtcSessionManager>,
    from_target: mpsc::UnboundedReceiver<String>,
    sent_pending: bool,
    /// With TURN: the session ICE the Source gathers with.
    pending_ice: Option<SessionIceConfig>,
}

#[async_trait]
impl EphemeralSignaling for LoopChannel {
    async fn next_message(&mut self) -> idr_core::Result<SignalingMessage> {
        if !self.sent_pending {
            // Host candidates only: Source gathers once it has its (empty) ICE servers.
            self.sent_pending = true;
            return Ok(SignalingMessage::Pending(SessionPending {
                session_id: self.session_id,
                ice: self.pending_ice.clone(),
            }));
        }
        loop {
            let json = self.from_target.recv().await.ok_or_else(|| {
                idr_core::IdrError::new(idr_core::IdrErrorKind::SignalingFailed, "target gone")
            })?;
            let v: serde_json::Value = serde_json::from_str(&json).unwrap();
            match v["message_type"].as_str().unwrap_or_default() {
                "webrtc_answer" => {
                    return Ok(SignalingMessage::Answer(
                        serde_json::from_value::<WebRtcAnswer>(v).unwrap(),
                    ))
                }
                "webrtc_ice_candidate" => {
                    return Ok(SignalingMessage::IceCandidate(
                        serde_json::from_value::<WebRtcIceCandidate>(v).unwrap(),
                    ))
                }
                "webrtc_session_ack" => {
                    let ack: WebRtcSessionAck = serde_json::from_value(v).unwrap();
                    return Ok(SignalingMessage::SessionAck {
                        session_id: ack.session_id,
                        result: ack.result,
                        detail: ack.detail,
                    });
                }
                _ => {}
            }
        }
    }

    async fn send_ice(&mut self, c: WebRtcIceCandidate) -> idr_core::Result<()> {
        // The responder registers its inbox shortly after spawn.
        for _ in 0..200 {
            if let Some(inbox) = self.sessions.ice_inbox(self.session_id) {
                let _ = inbox.add_candidate(c.candidate, c.mid).await;
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(())
    }

    async fn send_json(&mut self, _json: &str) -> idr_core::Result<()> {
        Ok(())
    }

    async fn close(&mut self) -> idr_core::Result<()> {
        Ok(())
    }
}

pub async fn services() -> Arc<ConnectorRegistry> {
    let (echo, sink) = (echo_server().await, sink_server().await);
    Arc::new(registry(echo, sink))
}

pub async fn connect() -> SourceSession {
    connect_to(LoopPresence {
        connectors: services().await,
        transfers: None,
        attested_ski: None,
        relay: None,
    })
    .await
}

pub async fn connect_to(presence: LoopPresence) -> SourceSession {
    timeout(Duration::from_secs(30), try_connect(presence))
        .await
        .expect("WebRTC loopback connect timed out")
        .unwrap()
}

/// A Source runtime over `presence` (relay-only when it carries TURN servers).
pub async fn try_connect(presence: LoopPresence) -> idr_core::Result<SourceSession> {
    let policy = if presence.relay.is_some() { IceTransportPolicy::Relay } else { IceTransportPolicy::All };
    let mut runtime = SourceRuntime::with_auth(
        Box::new(presence),
        move || {
            Box::new(
                NativePeer::new(NativePeerConfig { ice_transport_policy: policy, ..NativePeerConfig::default() }).unwrap(),
            )
        },
        "loop-src",
        "local",
        SourceAuthMode::Bearer,
        Some("t".into()),
    );
    runtime.connect(FQHN).await
}

