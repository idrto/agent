pub mod dedup;
pub mod discovery;
pub mod endpoint;
pub mod outbox;
pub mod placement;
pub mod protocol;
pub mod quic_client;
pub mod registration;
pub mod websocket;

pub use dedup::CommandDedup;
pub use discovery::DiscoveryService;
pub use quic_client::PresenceQuicClient;
pub use websocket::PresenceWebSocketClient;
