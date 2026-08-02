//! Presence discovery + ephemeral WebRTC signaling (no Relay / Target deps).

pub mod discovery;
pub mod ephemeral;
pub mod mock;
pub mod pep;

pub use discovery::{DiscoveryClient, DiscoveryConfig};
pub use ephemeral::{EphemeralSignaling, SessionPending, SignalingMessage, WebRtcSignalingClient};
pub use pep::{PepClient, PepClientConfig, PepSession};
