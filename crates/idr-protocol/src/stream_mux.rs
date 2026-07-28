//! Multiplexed stream frames over a single WebRTC DataChannel (`idr-stream-v1`).
//!
//! Wire format: `[u32 BE length][postcard(StreamFrame)]`.
//!
//! # Compatibility
//!
//! Postcard enum discriminants for the original four variants are stable:
//! `Open=0`, `Data=1`, `HalfClose=2`, `Reset=3`. New variants are **appended**
//! so legacy peers can still decode historical frames. New peers must not send
//! extended frames until the remote side is known to support them (see
//! `protocol/idr-stream-v1.md`), or must tolerate legacy mode without `OpenOk`.

use serde::{Deserialize, Serialize};

use crate::errors::{ProtocolError, Result};
use crate::MAX_FRAME_BYTES;

/// Mux protocol major version carried in `Hello` / documented in the spec.
pub const STREAM_MUX_VERSION: u32 = 1;

/// Default per-stream receive window (bytes).
pub const INITIAL_STREAM_WINDOW: u32 = 256 * 1024;

/// Default connection-wide receive window (bytes).
pub const INITIAL_CONN_WINDOW: u32 = 16 * 1024 * 1024;

/// Feature token advertised in signaling / Hello.
pub const FEATURE_FLOW_CONTROL: &str = "flow_control_v1";
pub const FEATURE_OPEN_ACK: &str = "open_ack";
pub const FEATURE_PING: &str = "ping";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamKind {
    TlsPassthrough,
    HttpPassthrough,
    TcpConnect,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamOpenMeta {
    pub target_fqhn: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum OpenErrorCode {
    Unspecified = 0,
    ServiceNotFound = 1,
    Unauthorized = 2,
    ConnectionRefused = 3,
    ResourceExhausted = 4,
    InvalidArgument = 5,
    FqhnMismatch = 6,
}

/// Multiplexed DataChannel frame.
///
/// **Discriminant order is part of the wire ABI — only append new variants.**
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StreamFrame {
    Open {
        stream_id: u32,
        kind: StreamKind,
        meta: StreamOpenMeta,
    },
    Data {
        stream_id: u32,
        bytes: Vec<u8>,
    },
    HalfClose {
        stream_id: u32,
    },
    Reset {
        stream_id: u32,
        reason: u16,
    },
    /// Target accepted `Open` (or Source accepted Target-initiated open).
    OpenOk {
        stream_id: u32,
        /// Initial receive window credit granted to the peer for this stream.
        initial_window: u32,
    },
    OpenError {
        stream_id: u32,
        code: u16,
        message: String,
    },
    /// Credit the peer's send window (connection-level when `stream_id == 0`).
    WindowUpdate {
        stream_id: u32,
        credit: u32,
    },
    Ping {
        opaque: u64,
    },
    Pong {
        opaque: u64,
    },
    /// Sender will not accept new streams; `last_stream_id` is the highest id allowed.
    GoAway {
        last_stream_id: u32,
        error_code: u16,
        message: String,
    },
    AuthRefresh {
        token: Vec<u8>,
    },
    /// Connection-level capability / version handshake (optional; prefer signaling).
    Hello {
        version: u32,
        features: Vec<String>,
        /// Proposed connection receive window.
        conn_window: u32,
    },
    HelloAck {
        version: u32,
        features: Vec<String>,
        conn_window: u32,
    },
}

impl StreamFrame {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let payload =
            postcard::to_allocvec(self).map_err(|e| ProtocolError::Serialization(e.to_string()))?;
        if payload.len() > MAX_FRAME_BYTES {
            return Err(ProtocolError::FrameTooLarge(payload.len()));
        }
        let mut out = Vec::with_capacity(4 + payload.len());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
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
        postcard::from_bytes(&bytes[4..]).map_err(|e| ProtocolError::Serialization(e.to_string()))
    }

    pub fn stream_id(&self) -> Option<u32> {
        match self {
            Self::Open { stream_id, .. }
            | Self::Data { stream_id, .. }
            | Self::HalfClose { stream_id }
            | Self::Reset { stream_id, .. }
            | Self::OpenOk { stream_id, .. }
            | Self::OpenError { stream_id, .. }
            | Self::WindowUpdate { stream_id, .. } => Some(*stream_id),
            Self::Ping { .. }
            | Self::Pong { .. }
            | Self::GoAway { .. }
            | Self::AuthRefresh { .. }
            | Self::Hello { .. }
            | Self::HelloAck { .. } => None,
        }
    }

    /// Frames that legacy (pre–flow-control) peers understand.
    pub fn is_legacy_compatible(&self) -> bool {
        matches!(
            self,
            Self::Open { .. } | Self::Data { .. } | Self::HalfClose { .. } | Self::Reset { .. }
        )
    }
}

/// Which mux feature set is active on a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MuxProfile {
    /// Only Open/Data/HalfClose/Reset; Open succeeds without OpenOk.
    #[default]
    Legacy,
    /// OpenOk required; window updates enforced.
    FlowControlV1,
}

impl MuxProfile {
    pub fn from_features(features: &[String]) -> Self {
        if features.iter().any(|f| f == FEATURE_FLOW_CONTROL) {
            Self::FlowControlV1
        } else {
            Self::Legacy
        }
    }

    pub fn advertised_features(self) -> Vec<String> {
        match self {
            Self::Legacy => vec![],
            Self::FlowControlV1 => vec![
                FEATURE_FLOW_CONTROL.into(),
                FEATURE_OPEN_ACK.into(),
                FEATURE_PING.into(),
            ],
        }
    }
}

pub fn stream_kind_label(kind: StreamKind) -> &'static str {
    match kind {
        StreamKind::TlsPassthrough => "tls_passthrough",
        StreamKind::HttpPassthrough => "http_passthrough",
        StreamKind::TcpConnect => "tcp_connect",
    }
}

pub fn parse_stream_kind(s: &str) -> Option<StreamKind> {
    match s {
        "tls_passthrough" => Some(StreamKind::TlsPassthrough),
        "http_passthrough" => Some(StreamKind::HttpPassthrough),
        "tcp_connect" => Some(StreamKind::TcpConnect),
        _ => None,
    }
}

/// Source-initiated stream ids are odd; Target-initiated are even (0 reserved).
pub fn is_source_initiated_stream_id(id: u32) -> bool {
    id != 0 && id % 2 == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_frame_roundtrip() {
        let frame = StreamFrame::Open {
            stream_id: 1,
            kind: StreamKind::TlsPassthrough,
            meta: StreamOpenMeta {
                target_fqhn: "host.idr.to".into(),
                host: None,
                port: None,
            },
        };
        let enc = frame.encode().unwrap();
        let dec = StreamFrame::decode(&enc).unwrap();
        assert_eq!(frame, dec);
    }

    #[test]
    fn data_frame_roundtrip() {
        let frame = StreamFrame::Data {
            stream_id: 7,
            bytes: vec![1, 2, 3, 4, 5],
        };
        let enc = frame.encode().unwrap();
        let dec = StreamFrame::decode(&enc).unwrap();
        assert_eq!(frame, dec);
    }

    #[test]
    fn extended_frames_roundtrip() {
        let frames = [
            StreamFrame::OpenOk {
                stream_id: 1,
                initial_window: INITIAL_STREAM_WINDOW,
            },
            StreamFrame::OpenError {
                stream_id: 3,
                code: OpenErrorCode::ServiceNotFound as u16,
                message: "nope".into(),
            },
            StreamFrame::WindowUpdate {
                stream_id: 1,
                credit: 4096,
            },
            StreamFrame::Ping { opaque: 42 },
            StreamFrame::Pong { opaque: 42 },
            StreamFrame::GoAway {
                last_stream_id: 9,
                error_code: 0,
                message: "drain".into(),
            },
            StreamFrame::Hello {
                version: STREAM_MUX_VERSION,
                features: MuxProfile::FlowControlV1.advertised_features(),
                conn_window: INITIAL_CONN_WINDOW,
            },
            StreamFrame::HelloAck {
                version: STREAM_MUX_VERSION,
                features: MuxProfile::FlowControlV1.advertised_features(),
                conn_window: INITIAL_CONN_WINDOW,
            },
            StreamFrame::AuthRefresh {
                token: vec![9, 9, 9],
            },
        ];
        for frame in frames {
            let enc = frame.encode().unwrap();
            assert_eq!(StreamFrame::decode(&enc).unwrap(), frame);
            assert!(!frame.is_legacy_compatible());
        }
    }

    #[test]
    fn legacy_open_still_discriminant_zero() {
        // Ensure Open remains first variant (postcard index 0) for wire compat.
        let open = StreamFrame::Open {
            stream_id: 1,
            kind: StreamKind::HttpPassthrough,
            meta: StreamOpenMeta {
                target_fqhn: "t.idr.to".into(),
                host: None,
                port: None,
            },
        };
        let payload = postcard::to_allocvec(&open).unwrap();
        assert_eq!(payload[0], 0, "Open must stay postcard variant index 0");
    }

    #[test]
    fn odd_even_stream_ids() {
        assert!(is_source_initiated_stream_id(1));
        assert!(!is_source_initiated_stream_id(2));
        assert!(!is_source_initiated_stream_id(0));
    }
}
