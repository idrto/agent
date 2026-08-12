//! Presence QUIC ephemeral signaling for Source WebRTC session requests.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use idr_core::error::{IdrError, IdrErrorKind, Result};
use idr_protocol::discovery::PresenceServer;
use idr_protocol::signaling_json;
use idr_protocol::webrtc_signaling::{
    WebRtcAnswer, WebRtcIceCandidate, WebRtcSessionRequest,
};
use idr_protocol::ALPN_IDR_PRESENCE_V1;
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream};
use rustls::pki_types::ServerName;
use rustls::RootCertStore;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::ephemeral::{
    EphemeralSignaling, SessionPending, SignalingMessage, WebRtcSignalingClient,
};

/// Connects to Presence over QUIC and drives an ephemeral WebRTC session.
pub struct PresenceQuicSignalingClient {
    endpoint: Endpoint,
    server: PresenceServer,
    addr: SocketAddr,
    timeout: Duration,
}

impl PresenceQuicSignalingClient {
    pub fn new(
        bind: SocketAddr,
        server: PresenceServer,
        addr: SocketAddr,
        insecure_dev: bool,
        timeout: Duration,
    ) -> Result<Self> {
        let mut crypto = if insecure_dev {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
                .with_no_client_auth()
        } else {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        };
        crypto.alpn_protocols = vec![ALPN_IDR_PRESENCE_V1.to_vec()];

        let client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(|e| {
                IdrError::new(IdrErrorKind::InternalError, format!("quic crypto: {e}"))
            })?,
        ));
        let mut endpoint = Endpoint::client(bind).map_err(|e| {
            IdrError::new(IdrErrorKind::InternalError, format!("quic endpoint: {e}"))
        })?;
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(
            Duration::from_secs(120).try_into().expect("idle timeout"),
        ));
        transport.keep_alive_interval(Some(Duration::from_secs(15)));
        let mut client_config = client_config;
        client_config.transport_config(Arc::new(transport));
        endpoint.set_default_client_config(client_config);
        Ok(Self {
            endpoint,
            server,
            addr,
            timeout,
        })
    }
}

#[async_trait]
impl WebRtcSignalingClient for PresenceQuicSignalingClient {
    async fn begin_session(
        &mut self,
        request: WebRtcSessionRequest,
    ) -> Result<Box<dyn EphemeralSignaling>> {
        let connecting = self
            .endpoint
            .connect(self.addr, self.server.server_name.as_str())
            .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, format!("connect: {e}")))?;
        let connection = tokio::time::timeout(self.timeout, connecting)
            .await
            .map_err(|_| IdrError::new(IdrErrorKind::Timeout, "presence QUIC connect timeout"))?
            .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, format!("handshake: {e}")))?;

        let json = serde_json::to_string(&request).map_err(|e| {
            IdrError::new(IdrErrorKind::ProtocolError, format!("serialize request: {e}"))
        })?;
        let frame = signaling_json::encode_webrtc_json_frame(json.as_bytes()).map_err(|e| {
            IdrError::new(IdrErrorKind::ProtocolError, format!("encode frame: {e}"))
        })?;
        let (mut send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, format!("open_bi: {e}")))?;
        send.write_all(&frame)
            .await
            .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, format!("write: {e}")))?;
        // Keep send half open so Presence can write responses on the same bi-stream.
        Ok(Box::new(PresenceEphemeral {
            connection,
            send,
            recv,
            session_id: request.session_id,
            closed: false,
        }))
    }
}

struct PresenceEphemeral {
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
    session_id: Uuid,
    closed: bool,
}

#[async_trait]
impl EphemeralSignaling for PresenceEphemeral {
    async fn next_message(&mut self) -> Result<SignalingMessage> {
        if self.closed {
            return Err(IdrError::new(
                IdrErrorKind::SignalingFailed,
                "signaling closed",
            ));
        }
        let json = read_signaling_json(&mut self.recv).await?;
        parse_signaling_json(&json, self.session_id)
    }

    async fn send_ice(&mut self, candidate: WebRtcIceCandidate) -> Result<()> {
        let json = serde_json::to_string(&candidate).map_err(|e| {
            IdrError::new(IdrErrorKind::ProtocolError, format!("serialize ice: {e}"))
        })?;
        self.send_json(&json).await
    }

    async fn send_json(&mut self, json: &str) -> Result<()> {
        let frame = signaling_json::encode_webrtc_json_frame(json.as_bytes()).map_err(|e| {
            IdrError::new(IdrErrorKind::ProtocolError, format!("encode: {e}"))
        })?;
        self.send
            .write_all(&frame)
            .await
            .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, format!("write: {e}")))
    }

    async fn close(&mut self) -> Result<()> {
        self.closed = true;
        let _ = self.send.finish();
        self.connection.close(0u32.into(), b"done");
        Ok(())
    }
}

async fn read_signaling_json(recv: &mut RecvStream) -> Result<String> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, format!("read len: {e}")))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > idr_protocol::MAX_WEBRTC_SIGNALING_BYTES.max(idr_protocol::MAX_SIGNALING_BYTES) {
        return Err(IdrError::new(
            IdrErrorKind::ProtocolError,
            "signaling frame too large",
        ));
    }
    let mut payload = vec![0u8; len];
    recv.read_exact(&mut payload)
        .await
        .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, format!("read body: {e}")))?;
    let mut frame = len_buf.to_vec();
    frame.extend_from_slice(&payload);
    let json_bytes = signaling_json::decode_json_frame(&frame).map_err(|e| {
        IdrError::new(IdrErrorKind::ProtocolError, format!("decode frame: {e}"))
    })?;
    String::from_utf8(json_bytes)
        .map_err(|e| IdrError::new(IdrErrorKind::ProtocolError, format!("utf8: {e}")))
}

fn parse_signaling_json(json: &str, session_id: Uuid) -> Result<SignalingMessage> {
    let value: Value = serde_json::from_str(json).map_err(|e| {
        IdrError::new(IdrErrorKind::ProtocolError, format!("parse json: {e}"))
    })?;
    let msg_type = value
        .get("message_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    match msg_type {
        "session_pending" | "webrtc_session_pending" => {
            let pending: SessionPending = serde_json::from_str(json).map_err(|e| {
                IdrError::new(IdrErrorKind::ProtocolError, format!("pending: {e}"))
            })?;
            Ok(SignalingMessage::Pending(pending))
        }
        "webrtc_answer" => {
            let ans: WebRtcAnswer = serde_json::from_str(json).map_err(|e| {
                IdrError::new(IdrErrorKind::ProtocolError, format!("answer: {e}"))
            })?;
            Ok(SignalingMessage::Answer(ans))
        }
        "webrtc_ice_candidate" => {
            let c: WebRtcIceCandidate = serde_json::from_str(json).map_err(|e| {
                IdrError::new(IdrErrorKind::ProtocolError, format!("ice: {e}"))
            })?;
            Ok(SignalingMessage::IceCandidate(c))
        }
        "webrtc_ice_complete" => Ok(SignalingMessage::IceComplete { session_id }),
        "webrtc_session_ack" | "webrtc_session_offer_ack" => {
            #[derive(serde::Deserialize)]
            struct AckCompat {
                session_id: Uuid,
                result: idr_protocol::webrtc_signaling::WebRtcSessionResultCode,
                #[serde(default)]
                detail: Option<String>,
            }
            let ack: AckCompat = serde_json::from_str(json).map_err(|e| {
                IdrError::new(IdrErrorKind::ProtocolError, format!("ack: {e}"))
            })?;
            Ok(SignalingMessage::SessionAck {
                session_id: ack.session_id,
                result: ack.result,
                detail: ack.detail,
            })
        }
        "presence_error" => {
            let message = value
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("presence error")
                .to_string();
            Ok(SignalingMessage::Error { message })
        }
        other => Err(IdrError::new(
            IdrErrorKind::ProtocolError,
            format!("unexpected signaling type '{other}'"),
        )),
    }
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
