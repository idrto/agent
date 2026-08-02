//! Presence QUIC client (idr-presence-v1) with optional DP mTLS client auth.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use idr_core::error::{IdrError, IdrErrorKind, Result};
use idr_dp::{load_client_auth, MtlsClientMaterial};
use idr_protocol::discovery::PresenceServer;
use idr_protocol::ALPN_IDR_PRESENCE_V1;
use quinn::{ClientConfig, Connection, Endpoint};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig as RustlsClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};

pub struct PepQuicEndpoint {
    endpoint: Endpoint,
}

impl PepQuicEndpoint {
    pub fn new(
        bind: SocketAddr,
        insecure_dev: bool,
        mtls: Option<&MtlsClientMaterial>,
    ) -> Result<Self> {
        let crypto = build_rustls(insecure_dev, mtls)?;
        let client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(|e| {
                IdrError::new(IdrErrorKind::InternalError, format!("quic crypto: {e}"))
            })?,
        ));
        let mut endpoint = Endpoint::client(bind).map_err(|e| {
            IdrError::new(IdrErrorKind::InternalError, format!("quic endpoint: {e}"))
        })?;
        endpoint.set_default_client_config(client_config);
        Ok(Self { endpoint })
    }

    pub async fn connect(
        &self,
        server: &PresenceServer,
        addr: SocketAddr,
        timeout: Duration,
    ) -> Result<Connection> {
        let connecting = self
            .endpoint
            .connect(addr, server.server_name.as_str())
            .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, e.to_string()))?;
        tokio::time::timeout(timeout, connecting)
            .await
            .map_err(|_| IdrError::new(IdrErrorKind::SignalingFailed, "presence QUIC timeout"))?
            .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, e.to_string()))
    }
}

fn build_rustls(
    insecure_dev: bool,
    mtls: Option<&MtlsClientMaterial>,
) -> Result<RustlsClientConfig> {
    let mut crypto = if insecure_dev {
        if let Some(material) = mtls {
            let auth = load_client_auth(material)
                .map_err(|e| IdrError::new(IdrErrorKind::AuthenticationFailed, e.to_string()))?;
            RustlsClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
                .with_client_auth_cert(auth.certs, auth.key)
                .map_err(|e| IdrError::new(IdrErrorKind::AuthenticationFailed, e.to_string()))?
        } else {
            RustlsClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
                .with_no_client_auth()
        }
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let builder = RustlsClientConfig::builder().with_root_certificates(roots);
        if let Some(material) = mtls {
            let auth = load_client_auth(material)
                .map_err(|e| IdrError::new(IdrErrorKind::AuthenticationFailed, e.to_string()))?;
            builder
                .with_client_auth_cert(auth.certs, auth.key)
                .map_err(|e| IdrError::new(IdrErrorKind::AuthenticationFailed, e.to_string()))?
        } else {
            builder.with_no_client_auth()
        }
    };
    crypto.alpn_protocols = vec![ALPN_IDR_PRESENCE_V1.to_vec()];
    Ok(crypto)
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
