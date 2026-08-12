//! Target-side named service connectors.

use async_trait::async_trait;
use idr_protocol::stream_mux::{
    CredentialMode, ServiceCatalogEntry, ServiceTransportKind, StreamKind, StreamOpenMeta,
};
#[cfg(feature = "net")]
use tokio::net::TcpStream;

use crate::error::{IdrError, IdrErrorKind, Result};

/// Named allowlisted Target service.
#[derive(Debug, Clone)]
pub struct NamedService {
    pub name: String,
    pub kind: StreamKind,
    pub meta: StreamOpenMeta,
    /// Who authenticates to the upstream (advertised in the live catalog).
    pub credential_mode: CredentialMode,
    /// Source must use TLS inside the mux stream when true.
    pub require_upstream_tls: bool,
    /// Catalog transport hint (HTTP gateway vs raw TCP). Overrides kind mapping when set.
    pub transport_kind: Option<ServiceTransportKind>,
}

impl NamedService {
    pub fn new(name: impl Into<String>, kind: StreamKind, meta: StreamOpenMeta) -> Self {
        Self {
            name: name.into(),
            kind,
            meta,
            credential_mode: CredentialMode::Source,
            require_upstream_tls: false,
            transport_kind: None,
        }
    }

    pub fn with_credential_policy(
        mut self,
        mode: CredentialMode,
        require_upstream_tls: bool,
    ) -> Self {
        self.credential_mode = mode;
        self.require_upstream_tls = require_upstream_tls;
        self
    }

    pub fn with_transport_kind(mut self, kind: ServiceTransportKind) -> Self {
        self.transport_kind = Some(kind);
        self
    }

    pub fn catalog_entry(&self) -> ServiceCatalogEntry {
        let transport = self.transport_kind.unwrap_or(match self.kind {
            StreamKind::HttpPassthrough => ServiceTransportKind::Http,
            StreamKind::TlsPassthrough | StreamKind::TcpConnect => ServiceTransportKind::Tcp,
        });
        ServiceCatalogEntry {
            name: self.name.clone(),
            kind: transport,
            credential_mode: self.credential_mode,
            require_upstream_tls: self.require_upstream_tls,
        }
    }
}

/// Opens a local byte connection for an allowlisted service / stream kind.
#[async_trait]
pub trait Connector: Send + Sync {
    fn name(&self) -> &str;

    fn supported_kinds(&self) -> &[StreamKind];

    #[cfg(feature = "net")]
    async fn connect(&self, kind: StreamKind, meta: &StreamOpenMeta) -> Result<TcpStream>;
}

/// In-memory registry of named services → connectors.
#[derive(Default)]
pub struct ConnectorRegistry {
    services: Vec<(NamedService, std::sync::Arc<dyn Connector>)>,
}

impl ConnectorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, service: NamedService, connector: std::sync::Arc<dyn Connector>) {
        self.services.push((service, connector));
    }

    pub fn resolve(&self, service_name: &str) -> Result<(&NamedService, &dyn Connector)> {
        self.services
            .iter()
            .find(|(s, _)| s.name == service_name)
            .map(|(s, c)| (s, c.as_ref()))
            .ok_or_else(|| {
                IdrError::new(
                    IdrErrorKind::ServiceNotFound,
                    format!("unknown service '{service_name}'"),
                )
            })
    }

    pub fn map_service_to_request(
        &self,
        service_name: &str,
        target_fqhn: &str,
    ) -> Result<(StreamKind, StreamOpenMeta)> {
        let (svc, _) = self.resolve(service_name)?;
        let mut meta = svc.meta.clone();
        if meta.target_fqhn.is_empty() {
            meta.target_fqhn = target_fqhn.to_string();
        }
        if meta.service_name.is_none() {
            meta.service_name = Some(svc.name.clone());
        }
        Ok((svc.kind, meta))
    }

    /// Catalog of registered service names (for Presence advertisement).
    pub fn service_names(&self) -> Vec<String> {
        self.services.iter().map(|(s, _)| s.name.clone()).collect()
    }

    /// Structured catalog for mux `ServicesCatalogDetailed`.
    pub fn catalog_entries(&self) -> Vec<ServiceCatalogEntry> {
        self.services
            .iter()
            .map(|(s, _)| s.catalog_entry())
            .collect()
    }
}
