use std::sync::Arc;

use tracing::debug;

use quinn::{Connection, VarInt};

pub struct RelayQuicConnection {
    inner: Connection,
}

impl RelayQuicConnection {
    pub fn new(inner: Connection) -> Self {
        Self { inner }
    }

    pub fn connection(&self) -> &Connection {
        &self.inner
    }

    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        self.inner.close(error_code, reason);
    }

    pub async fn open_bi(&self) -> anyhow::Result<(quinn::SendStream, quinn::RecvStream)> {
        Ok(self.inner.open_bi().await?)
    }

    /// Emit a small uni-directional stream to trigger QUIC path validation after rebind.
    pub fn nudge_path_probe(&self) {
        let conn = self.inner.clone();
        tokio::spawn(async move {
            match conn.open_uni().await {
                Ok(mut send) => {
                    let _ = send.finish();
                }
                Err(err) => {
                    debug!(error = %err, "path probe uni stream failed");
                }
            }
        });
    }
}

pub type SharedRelayQuicConnection = Arc<RelayQuicConnection>;
