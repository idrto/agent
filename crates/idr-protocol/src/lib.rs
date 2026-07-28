//! Shared IDR protocol types and framing.
//!
//! Canonical copy lives in the agent monorepo (idr-protocol). Keep presence and relay copies in sync until they depend on this crate.
//! Keep all copies in sync; see docs/PROTOCOL.md for the specification.

pub mod billing_party;
pub mod crypto;
pub mod discovery;
pub mod errors;
pub mod framing;
pub mod fqhn;
pub mod placement;
pub mod quic_control;
pub mod signaling;
pub mod signaling_json;
pub mod stream_mux;
pub mod tunnel;
pub mod webrtc_ice;
pub mod webrtc_signaling;

pub use billing_party::BillingPartyPair;

pub const PROTOCOL_VERSION: u32 = 1;
pub const ALPN_IDR_RELAY_V1: &[u8] = b"idr-relay-v1";
pub const ALPN_IDR_PRESENCE_V1: &[u8] = b"idr-presence-v1";
/// Relay→Presence control plane (mTLS, IPv6). Not used by Target agents.
pub const ALPN_IDR_PRESENCE_RELAY_V1: &[u8] = b"idr-presence-relay-v1";
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_SIGNALING_BYTES: usize = 16 * 1024;
pub const MAX_WEBRTC_SIGNALING_BYTES: usize = 256 * 1024;
pub const MAX_SDP_BYTES: usize = 128 * 1024;
pub const MAX_ICE_CANDIDATE_BYTES: usize = 8 * 1024;
