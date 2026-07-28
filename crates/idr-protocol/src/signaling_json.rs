use crate::errors::{ProtocolError, Result};
use crate::{MAX_SIGNALING_BYTES, MAX_WEBRTC_SIGNALING_BYTES};

/// Length-prefixed UTF-8 JSON signaling frame: `[u32 BE len][json bytes]`
pub fn encode_json_frame(json: &[u8]) -> Result<Vec<u8>> {
    encode_json_frame_limited(json, MAX_SIGNALING_BYTES)
}

/// WebRTC SDP-bearing frames may be up to `MAX_WEBRTC_SIGNALING_BYTES`.
pub fn encode_webrtc_json_frame(json: &[u8]) -> Result<Vec<u8>> {
    encode_json_frame_limited(json, MAX_WEBRTC_SIGNALING_BYTES)
}

fn encode_json_frame_limited(json: &[u8], max: usize) -> Result<Vec<u8>> {
    if json.len() > max {
        return Err(ProtocolError::FrameTooLarge(json.len()));
    }
    let mut out = Vec::with_capacity(4 + json.len());
    out.extend_from_slice(&(json.len() as u32).to_be_bytes());
    out.extend_from_slice(json);
    Ok(out)
}

pub fn decode_json_frame(bytes: &[u8]) -> Result<Vec<u8>> {
    decode_json_frame_limited(bytes, MAX_SIGNALING_BYTES)
}

pub fn decode_webrtc_json_frame(bytes: &[u8]) -> Result<Vec<u8>> {
    decode_json_frame_limited(bytes, MAX_WEBRTC_SIGNALING_BYTES)
}

fn decode_json_frame_limited(bytes: &[u8], max: usize) -> Result<Vec<u8>> {
    if bytes.len() < 4 {
        return Err(ProtocolError::InvalidFrame);
    }
    let len = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
    if len > max {
        return Err(ProtocolError::FrameTooLarge(len));
    }
    if bytes.len() != 4 + len {
        return Err(ProtocolError::InvalidFrame);
    }
    Ok(bytes[4..].to_vec())
}

/// Auto-select decode limit: try WebRTC max when payload claims larger than signaling max.
pub fn decode_json_frame_auto(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() < 4 {
        return Err(ProtocolError::InvalidFrame);
    }
    let len = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
    if len > MAX_SIGNALING_BYTES {
        decode_webrtc_json_frame(bytes)
    } else {
        decode_json_frame(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let payload = br#"{"message_type":"register_target"}"#;
        let framed = encode_json_frame(payload).unwrap();
        assert_eq!(decode_json_frame(&framed).unwrap(), payload);
    }

    #[test]
    fn webrtc_frame_allows_large() {
        let payload = vec![b'a'; 32 * 1024];
        let framed = encode_webrtc_json_frame(&payload).unwrap();
        assert_eq!(decode_webrtc_json_frame(&framed).unwrap(), payload);
    }
}
