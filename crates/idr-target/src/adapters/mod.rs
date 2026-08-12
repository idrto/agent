//! Target adapters implementing idr-core connector traits over existing bridges.

mod gateway;

pub use gateway::ServiceGatewayConnector;

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use idr_core::connector::{Connector, NamedService};
use idr_core::error::{IdrError, IdrErrorKind, Result};
use idr_protocol::stream_mux::{StreamKind, StreamOpenMeta};
use tokio::net::TcpStream;

use crate::config::{NginxConfig, WebRtcPolicyConfig};
use crate::webrtc::bridge;

/// Connector that maps stream kinds to local nginx upstreams / TcpConnect policy.
pub struct NginxBridgeConnector {
    name: String,
    nginx: NginxConfig,
    policy: WebRtcPolicyConfig,
    expected_fqhn: String,
}

impl NginxBridgeConnector {
    pub fn new(
        name: impl Into<String>,
        nginx: NginxConfig,
        policy: WebRtcPolicyConfig,
        expected_fqhn: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            nginx,
            policy,
            expected_fqhn: expected_fqhn.into(),
        }
    }

    /// Default named services wired to nginx TLS/HTTP upstreams.
    pub fn default_services(
        nginx: NginxConfig,
        policy: WebRtcPolicyConfig,
        fqhn: &str,
    ) -> Vec<(NamedService, Arc<dyn Connector>)> {
        let connector: Arc<dyn Connector> = Arc::new(Self::new("nginx", nginx, policy, fqhn));
        use idr_protocol::stream_mux::{CredentialMode, ServiceTransportKind};
        vec![
            (
                NamedService::new(
                    "https",
                    StreamKind::TlsPassthrough,
                    StreamOpenMeta {
                        target_fqhn: fqhn.into(),
                        service_name: Some("https".into()),
                        host: None,
                        port: None,
                    },
                )
                .with_credential_policy(CredentialMode::Target, false)
                .with_transport_kind(ServiceTransportKind::Tcp),
                connector.clone(),
            ),
            (
                NamedService::new(
                    "http",
                    StreamKind::HttpPassthrough,
                    StreamOpenMeta {
                        target_fqhn: fqhn.into(),
                        service_name: Some("http".into()),
                        host: None,
                        port: None,
                    },
                )
                .with_credential_policy(CredentialMode::Target, false)
                .with_transport_kind(ServiceTransportKind::Http),
                connector,
            ),
        ]
    }
}

#[async_trait]
impl Connector for NginxBridgeConnector {
    fn name(&self) -> &str {
        &self.name
    }

    fn supported_kinds(&self) -> &[StreamKind] {
        &[
            StreamKind::TlsPassthrough,
            StreamKind::HttpPassthrough,
            StreamKind::TcpConnect,
        ]
    }

    async fn connect(&self, kind: StreamKind, meta: &StreamOpenMeta) -> Result<TcpStream> {
        bridge::open_upstream(
            kind,
            meta.clone(),
            &self.nginx,
            &self.policy,
            &self.expected_fqhn,
        )
        .await
        .map_err(|e| IdrError::new(IdrErrorKind::ConnectionRefused, e.to_string()))
    }
}

/// Parse `host:port` for connector configs.
pub fn parse_socket_addr(host: &str, port: u16) -> Result<SocketAddr> {
    format!("{host}:{port}")
        .parse()
        .map_err(|e| IdrError::new(IdrErrorKind::InvalidArgument, format!("addr: {e}")))
}
