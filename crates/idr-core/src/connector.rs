//! Target-side named service connectors.

use async_trait::async_trait;
use idr_protocol::stream_mux::{StreamKind, StreamOpenMeta};
use tokio::net::TcpStream;

use crate::error::{IdrError, IdrErrorKind, Result};

/// Named allowlisted Target service.
#[derive(Debug, Clone)]
pub struct NamedService {
    pub name: String,
    pub kind: StreamKind,
    pub meta: StreamOpenMeta,
}

/// Opens a local byte connection for an allowlisted service / stream kind.
#[async_trait]
pub trait Connector: Send + Sync {
    fn name(&self) -> &str;

    fn supported_kinds(&self) -> &[StreamKind];

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
        Ok((svc.kind, meta))
    }
}
