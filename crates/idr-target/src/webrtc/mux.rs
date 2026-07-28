//! Demux StreamFrame messages from WebRTC DataChannel binary payloads.

use idr_protocol::stream_mux::StreamFrame;

pub fn decode_datachannel_message(bytes: &[u8]) -> anyhow::Result<StreamFrame> {
    StreamFrame::decode(bytes).map_err(|e| anyhow::anyhow!("mux decode: {e}"))
}

pub fn encode_datachannel_message(frame: &StreamFrame) -> anyhow::Result<Vec<u8>> {
    frame.encode().map_err(|e| anyhow::anyhow!("mux encode: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use idr_protocol::stream_mux::{StreamFrame, StreamKind, StreamOpenMeta};

    #[test]
    fn roundtrip_open_frame() {
        let frame = StreamFrame::Open {
            stream_id: 1,
            kind: StreamKind::TlsPassthrough,
            meta: StreamOpenMeta {
                target_fqhn: "device.example.idr.to".into(),
                host: None,
                port: None,
            },
        };
        let bytes = encode_datachannel_message(&frame).unwrap();
        match decode_datachannel_message(&bytes).unwrap() {
            StreamFrame::Open { stream_id, .. } => assert_eq!(stream_id, 1),
            _ => panic!("expected open frame"),
        }
    }
}
