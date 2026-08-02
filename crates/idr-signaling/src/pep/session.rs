//! Byte-oriented Presence PEP session (QUIC bi-stream or WSS).

use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use idr_core::error::{IdrError, IdrErrorKind, Result};
use idr_protocol::signaling_json;
use quinn::Connection;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type WsWrite = futures::stream::SplitSink<WsStream, Message>;
type WsRead = futures::stream::SplitStream<WsStream>;

pub enum PepSession {
    Quic {
        connection: Connection,
        send: Mutex<quinn::SendStream>,
        recv: Mutex<quinn::RecvStream>,
    },
    Wss {
        write: Arc<Mutex<WsWrite>>,
        read: Arc<Mutex<WsRead>>,
    },
}

impl PepSession {
    pub async fn send_json(&self, json: &str) -> Result<()> {
        match self {
            Self::Quic { send, .. } => {
                let frame = signaling_json::encode_webrtc_json_frame(json.as_bytes())
                    .map_err(|e| IdrError::new(IdrErrorKind::ProtocolError, e.to_string()))?;
                send.lock()
                    .await
                    .write_all(&frame)
                    .await
                    .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, e.to_string()))?;
                Ok(())
            }
            Self::Wss { write, .. } => write
                .lock()
                .await
                .send(Message::Text(json.to_string()))
                .await
                .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, e.to_string())),
        }
    }

    pub async fn send_bytes(&self, bytes: &[u8]) -> Result<()> {
        match self {
            Self::Quic { send, .. } => {
                let frame = signaling_json::encode_json_frame(bytes)
                    .map_err(|e| IdrError::new(IdrErrorKind::ProtocolError, e.to_string()))?;
                send.lock()
                    .await
                    .write_all(&frame)
                    .await
                    .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, e.to_string()))
            }
            Self::Wss { write, .. } => {
                let text = std::str::from_utf8(bytes)
                    .map_err(|e| IdrError::new(IdrErrorKind::ProtocolError, e.to_string()))?;
                write
                    .lock()
                    .await
                    .send(Message::Text(text.to_string()))
                    .await
                    .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, e.to_string()))
            }
        }
    }

    pub async fn recv_json(&self) -> Result<String> {
        match self {
            Self::Quic { recv, .. } => {
                let mut len_buf = [0u8; 4];
                recv.lock()
                    .await
                    .read_exact(&mut len_buf)
                    .await
                    .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, e.to_string()))?;
                let len = u32::from_be_bytes(len_buf) as usize;
                if len > idr_protocol::MAX_WEBRTC_SIGNALING_BYTES {
                    return Err(IdrError::new(
                        IdrErrorKind::ProtocolError,
                        format!("frame too large: {len}"),
                    ));
                }
                let mut body = vec![0u8; len];
                recv.lock()
                    .await
                    .read_exact(&mut body)
                    .await
                    .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, e.to_string()))?;
                String::from_utf8(body)
                    .map_err(|e| IdrError::new(IdrErrorKind::ProtocolError, e.to_string()))
            }
            Self::Wss { read, .. } => loop {
                let msg = read
                    .lock()
                    .await
                    .next()
                    .await
                    .ok_or_else(|| IdrError::new(IdrErrorKind::TransportClosed, "wss closed"))?
                    .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, e.to_string()))?;
                match msg {
                    Message::Text(t) => return Ok(t),
                    Message::Binary(b) => {
                        return String::from_utf8(b).map_err(|e| {
                            IdrError::new(IdrErrorKind::ProtocolError, e.to_string())
                        });
                    }
                    Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
                    Message::Close(_) => {
                        return Err(IdrError::new(
                            IdrErrorKind::TransportClosed,
                            "wss close frame",
                        ));
                    }
                }
            },
        }
    }

    pub async fn close(&self) -> Result<()> {
        match self {
            Self::Quic {
                connection, send, ..
            } => {
                let _ = send.lock().await.finish();
                connection.close(0u32.into(), b"done");
                Ok(())
            }
            Self::Wss { write, .. } => {
                let _ = write.lock().await.close().await;
                Ok(())
            }
        }
    }
}
