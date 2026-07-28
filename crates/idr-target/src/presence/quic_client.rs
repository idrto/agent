use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use quinn::{ClientConfig, Connection, Endpoint};
use rustls::pki_types::ServerName;
use rustls::RootCertStore;
use tokio::io::AsyncWriteExt;
use tracing::debug;

use idr_protocol::discovery::PresenceServer;
use idr_protocol::signaling_json;
use idr_protocol::ALPN_IDR_PRESENCE_V1;

pub struct PresenceQuicClient {
    endpoint: Endpoint,
    insecure_dev: bool,
}

impl PresenceQuicClient {
    pub fn new(bind: SocketAddr, insecure_dev: bool) -> Result<Self> {
        let mut crypto = if insecure_dev {
            let crypto = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
                .with_no_client_auth();
            crypto
        } else {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        };
        crypto.alpn_protocols = vec![ALPN_IDR_PRESENCE_V1.to_vec()];

        let client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
        ));

        let mut endpoint = Endpoint::client(bind)?;
        endpoint.set_default_client_config(client_config);
        Ok(Self {
            endpoint,
            insecure_dev,
        })
    }

    pub async fn connect_persistent(
        &self,
        server: &PresenceServer,
        addr: SocketAddr,
        register_json: &str,
        timeout: Duration,
    ) -> Result<Connection> {
        let connecting = self
            .endpoint
            .connect(addr, server.server_name.as_str())
            .context("start presence QUIC")?;
        let connection = tokio::time::timeout(timeout, connecting)
            .await
            .context("presence QUIC connect timeout")?
            .context("presence QUIC handshake")?;

        let frame = signaling_json::encode_json_frame(register_json.as_bytes())
            .map_err(|e| anyhow::anyhow!("encode register frame: {e}"))?;
        let (mut send, mut recv) = connection.open_bi().await.context("open bi stream")?;
        send.write_all(&frame).await.context("write register")?;
        send.finish().context("finish register stream")?;
        drop(recv);

        debug!(%addr, "presence QUIC registered");
        Ok(connection)
    }

    pub async fn send_ephemeral(
        &self,
        server: &PresenceServer,
        addr: SocketAddr,
        json: &str,
        timeout: Duration,
    ) -> Result<()> {
        let connecting = self
            .endpoint
            .connect(addr, server.server_name.as_str())
            .context("start presence QUIC")?;
        let connection = tokio::time::timeout(timeout, connecting)
            .await
            .context("presence QUIC connect timeout")?
            .context("presence QUIC handshake")?;

        let frame = signaling_json::encode_json_frame(json.as_bytes())
            .map_err(|e| anyhow::anyhow!("encode frame: {e}"))?;
        let (mut send, _recv) = connection.open_bi().await.context("open bi stream")?;
        send.write_all(&frame).await.context("write command")?;
        send.finish().context("finish command stream")?;
        connection.close(0u32.into(), b"done");
        Ok(())
    }

    pub fn insecure_dev(&self) -> bool {
        self.insecure_dev
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
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
