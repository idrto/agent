use serde::{de::DeserializeOwned, Serialize};

use crate::errors::{ProtocolError, Result};
use crate::MAX_FRAME_BYTES;

/// Length-prefixed postcard frame: [u32 BE length][postcard payload]
pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let payload = postcard::to_allocvec(value)
        .map_err(|e| ProtocolError::Serialization(e.to_string()))?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge(payload.len()));
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn decode_frame<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() < 4 {
        return Err(ProtocolError::InvalidFrame);
    }
    let len = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge(len));
    }
    if bytes.len() != 4 + len {
        return Err(ProtocolError::InvalidFrame);
    }
    postcard::from_bytes(&bytes[4..])
        .map_err(|e| ProtocolError::Serialization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic_control::{ClientHello, QuicControlMessage};
    use uuid::Uuid;

    #[test]
    fn roundtrip() {
        let msg = QuicControlMessage::ClientHello(ClientHello {
            protocol_version: 1,
            message_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            target_fqhn: "a.example.idr.to".into(),
            target_identity: "id".into(),
            connection_token: "tok".into(),
            connection_epoch: 1,
            relay_id: "relay-a".into(),
        });
        let encoded = msg.encode().unwrap();
        let decoded: QuicControlMessage = decode_frame(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }
}
