//! Presence PEP transport: QUIC first, WSS fallback (Source-safe).

mod client;
mod endpoint;
mod quic;
mod session;
mod wss;

pub use client::{PepClient, PepClientConfig};
pub use endpoint::{
    build_transport_attempts, transport_label, PresenceNetworkCaps, PresenceTransportChoice,
};
pub use session::PepSession;
