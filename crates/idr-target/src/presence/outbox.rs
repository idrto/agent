use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::Connection;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use idr_protocol::signaling_json;

#[derive(Clone)]
pub enum PresenceSignalingOutbox {
    Quic { connection: Arc<Connection> },
    Wss(mpsc::UnboundedSender<String>),
}

impl PresenceSignalingOutbox {
    pub fn from_quic(connection: Connection) -> Self {
        Self::Quic {
            connection: Arc::new(connection),
        }
    }

    pub fn from_wss(tx: mpsc::UnboundedSender<String>) -> Self {
        Self::Wss(tx)
    }

    pub async fn send_json(&self, json: &str) -> Result<()> {
        match self {
            Self::Quic { connection } => {
                // Prefer WebRTC-sized frames when payload exceeds normal signaling max.
                let frame = if json.len() > idr_protocol::MAX_SIGNALING_BYTES {
                    signaling_json::encode_webrtc_json_frame(json.as_bytes())
                } else {
                    signaling_json::encode_json_frame(json.as_bytes())
                }
                .map_err(|e| anyhow::anyhow!("encode signaling frame: {e}"))?;
                let (mut send, _recv) = connection
                    .open_bi()
                    .await
                    .context("open presence signaling bi-stream")?;
                send.write_all(&frame)
                    .await
                    .context("write signaling frame")?;
                send.finish().context("finish signaling bi-stream")?;
            }
            Self::Wss(tx) => {
                tx.send(json.to_string())
                    .map_err(|_| anyhow::anyhow!("wss signaling outbox closed"))?;
            }
        }
        Ok(())
    }
}
