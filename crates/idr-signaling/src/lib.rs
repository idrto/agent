//! Presence discovery + ephemeral WebRTC signaling (no Relay / Target deps).

pub mod ephemeral;
pub mod mock;
pub mod place;

#[cfg(feature = "native")]
pub mod discovery;
#[cfg(feature = "native")]
pub mod pep;
#[cfg(feature = "quic")]
pub mod presence_quic;

pub use ephemeral::{EphemeralSignaling, SessionPending, SignalingMessage, WebRtcSignalingClient};
pub use place::{place, place_servers, place_wss_servers};

#[cfg(feature = "native")]
pub use discovery::{DiscoveryClient, DiscoveryConfig};
#[cfg(feature = "native")]
pub use pep::{PepClient, PepClientConfig, PepSession};
#[cfg(feature = "quic")]
pub use presence_quic::PresenceQuicSignalingClient;
