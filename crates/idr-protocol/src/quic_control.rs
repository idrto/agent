use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::errors::{ProtocolError, Result};
use crate::framing::{decode_frame, encode_frame};
use crate::PROTOCOL_VERSION;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum QuicControlMessageType {
    ClientHello = 1,
    ServerHello = 2,
    ConnectionAccepted = 3,
    ConnectionRejected = 4,
    StreamOpen = 5,
    StreamClose = 6,
    GracefulDrain = 7,
    Ping = 8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientHello {
    pub protocol_version: u32,
    pub message_id: Uuid,
    pub session_id: Uuid,
    pub target_fqhn: String,
    pub target_identity: String,
    pub connection_token: String,
    pub connection_epoch: u64,
    pub relay_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerHello {
    pub protocol_version: u32,
    pub message_id: Uuid,
    pub session_id: Uuid,
    pub relay_id: String,
    pub connection_epoch: u64,
    pub accepted: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamOpen {
    pub protocol_version: u32,
    pub message_id: Uuid,
    pub stream_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GracefulDrain {
    pub protocol_version: u32,
    pub message_id: Uuid,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QuicControlMessage {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    StreamOpen(StreamOpen),
    GracefulDrain(GracefulDrain),
}

impl QuicControlMessage {
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_frame(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_frame(bytes)
    }

    pub fn validate_version(&self) -> Result<()> {
        let version = match self {
            QuicControlMessage::ClientHello(h) => h.protocol_version,
            QuicControlMessage::ServerHello(h) => h.protocol_version,
            QuicControlMessage::StreamOpen(s) => s.protocol_version,
            QuicControlMessage::GracefulDrain(d) => d.protocol_version,
        };
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        Ok(())
    }
}
