//! Presence WSS fallback transport.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use idr_core::error::{IdrError, IdrErrorKind, Result};
use idr_dp::{load_client_auth, MtlsClientMaterial};
use idr_protocol::discovery::PresenceServer;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::sync::Mutex;
use tokio_tungstenite::{
    connect_async_tls_with_config, tungstenite::client::IntoClientRequest, Connector,
};
use tracing::debug;

use super::session::PepSession;

pub async fn connect_wss(
    server: &PresenceServer,
    timeout: Duration,
    mtls: Option<&MtlsClientMaterial>,
    insecure_dev: bool,
) -> Result<PepSession> {
    let mut request = server
        .wss_url
        .as_str()
        .into_client_request()
        .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, e.to_string()))?;
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        "idr-presence-v1"
            .parse()
            .map_err(|e| IdrError::new(IdrErrorKind::InternalError, format!("{e}")))?,
    );

    let connector = build_connector(mtls, insecure_dev)?;
    let (ws, _) = tokio::time::timeout(
        timeout,
        connect_async_tls_with_config(request, None, false, Some(connector)),
    )
    .await
    .map_err(|_| IdrError::new(IdrErrorKind::SignalingFailed, "presence WSS timeout"))?
    .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, e.to_string()))?;

    debug!(url = %server.wss_url, "presence WSS connected");
    let (write, read) = ws.split();
    Ok(PepSession::Wss {
        write: Arc::new(Mutex::new(write)),
        read: Arc::new(Mutex::new(read)),
    })
}

fn build_connector(mtls: Option<&MtlsClientMaterial>, insecure_dev: bool) -> Result<Connector> {
    let builder = if insecure_dev {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder().with_root_certificates(roots)
    };

    let crypto = if let Some(material) = mtls {
        let auth = load_client_auth(material)
            .map_err(|e| IdrError::new(IdrErrorKind::AuthenticationFailed, e.to_string()))?;
        builder
            .with_client_auth_cert(auth.certs, auth.key)
            .map_err(|e| IdrError::new(IdrErrorKind::AuthenticationFailed, e.to_string()))?
    } else {
        builder.with_no_client_auth()
    };

    Ok(Connector::Rustls(Arc::new(crypto)))
}

#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
