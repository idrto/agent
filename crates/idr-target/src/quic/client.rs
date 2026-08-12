use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::{ClientConfig, Endpoint, TransportConfig};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
use tracing::{debug, info};

use crate::network::quic_bind_addr;
use crate::quic::authentication::build_client_hello;
use crate::quic::limits::apply_relay_client_transport_limits;
use crate::quic::RelayQuicConnection;
use crate::relay::descriptor::{ConnectionAuthorization, StableRelayDescriptor};
use idr_protocol::quic_control::QuicControlMessage;
use idr_protocol::ALPN_IDR_RELAY_V1;

pub struct QuicClient {
    endpoint: Endpoint,
    target_identity: String,
}

impl QuicClient {
    pub fn new(bind_addr: SocketAddr, target_identity: String, insecure_dev: bool) -> Result<Self> {
        let crypto = if insecure_dev {
            let mut crypto = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
                .with_no_client_auth();
            crypto.alpn_protocols = vec![ALPN_IDR_RELAY_V1.to_vec()];
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?
        } else {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut crypto = RustlsClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            crypto.alpn_protocols = vec![ALPN_IDR_RELAY_V1.to_vec()];
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?
        };

        let mut client_config = ClientConfig::new(Arc::new(crypto));
        let mut transport = TransportConfig::default();
        apply_relay_client_transport_limits(&mut transport);
        client_config.transport_config(Arc::new(transport));

        let mut endpoint = Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(client_config);
        Ok(Self {
            endpoint,
            target_identity,
        })
    }

    pub async fn connect(
        &self,
        descriptor: &StableRelayDescriptor,
        addr: SocketAddr,
        auth: &ConnectionAuthorization,
    ) -> Result<Arc<RelayQuicConnection>> {
        info!(relay_id = %descriptor.relay_id, %addr, "dialing relay QUIC");
        let connecting = self
            .endpoint
            .connect(addr, descriptor.server_name.as_str())
            .context("start QUIC connect")?;
        let connection = connecting.await.context("QUIC handshake")?;
        info!(relay_id = %descriptor.relay_id, %addr, "QUIC handshake ok — sending ClientHello");

        let hello = build_client_hello(descriptor, auth, &self.target_identity);
        let frame = hello.encode().context("encode client hello")?;
        let (mut send, mut recv) = connection.open_bi().await.context("open control stream")?;
        use tokio::io::AsyncReadExt;
        use tokio::io::AsyncWriteExt;
        send.write_all(&frame).await.context("write client hello")?;
        send.finish().context("finish client hello stream")?;

        // Wait for ServerHello — previously we returned after write and Relay auth
        // failures looked like a successful Target connect while Relay still timed out.
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf)
            .await
            .context("read ServerHello length")?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut payload = vec![0u8; len];
        recv.read_exact(&mut payload)
            .await
            .context("read ServerHello payload")?;
        let mut reply = len_buf.to_vec();
        reply.extend_from_slice(&payload);
        let msg = QuicControlMessage::decode(&reply).context("decode ServerHello")?;
        match msg {
            QuicControlMessage::ServerHello(h) if h.accepted => {
                info!(
                    relay_id = %descriptor.relay_id,
                    %addr,
                    session_id = %h.session_id,
                    "relay accepted Target QUIC session"
                );
            }
            QuicControlMessage::ServerHello(h) => {
                anyhow::bail!(
                    "relay rejected Target QUIC: {}",
                    h.reason.unwrap_or_else(|| "rejected".into())
                );
            }
            other => anyhow::bail!("expected ServerHello, got {other:?}"),
        }

        Ok(Arc::new(RelayQuicConnection::new(connection)))
    }

    /// Rebind the local UDP socket after a network interface change so active QUIC
    /// connections can migrate instead of waiting for idle timeout.
    pub fn rebind(&self, bind_addr: SocketAddr) -> Result<()> {
        let socket = UdpSocket::bind(bind_addr).with_context(|| format!("bind UDP {bind_addr}"))?;
        self.endpoint
            .rebind(socket)
            .context("rebind relay QUIC endpoint")?;
        debug!(%bind_addr, "relay QUIC endpoint rebound for migration");
        Ok(())
    }

    pub fn rebind_for_caps(&self, caps: crate::network::NetworkCapabilities) -> Result<()> {
        self.rebind(quic_bind_addr(caps))
    }
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
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

pub fn dev_certificates() -> Result<(rcgen::CertifiedKey, Vec<CertificateDer<'static>>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    Ok((cert, vec![cert_der]))
}
