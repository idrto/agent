//! Session and stream-open request types.

use async_trait::async_trait;
use idr_protocol::stream_mux::{StreamKind, StreamOpenMeta};

use crate::error::Result;
use crate::stream::LogicalStream;

/// Request to open a logical stream to a named Target service (or legacy kind).
#[derive(Debug, Clone)]
pub struct OpenStreamRequest {
    pub service: String,
    pub kind: StreamKind,
    pub meta: StreamOpenMeta,
}

impl OpenStreamRequest {
    pub fn named(
        service: impl Into<String>,
        target_fqhn: impl Into<String>,
        kind: StreamKind,
    ) -> Self {
        let service = service.into();
        Self {
            service,
            kind,
            meta: StreamOpenMeta {
                target_fqhn: target_fqhn.into(),
                host: None,
                port: None,
            },
        }
    }
}

/// Persistent Source–Target session carrying multiplexed logical streams.
#[async_trait]
pub trait PeerSession: Send {
    fn target_fqhn(&self) -> &str;

    async fn open_stream(&mut self, request: OpenStreamRequest) -> Result<Box<dyn LogicalStream>>;

    async fn close(&mut self) -> Result<()>;
}
