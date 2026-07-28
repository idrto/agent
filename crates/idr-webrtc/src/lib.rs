//! WebRTC transport abstraction — no libdatachannel types in the public API.

pub mod mock;
pub mod recording;
pub mod transport;

pub use recording::RecordingPeer;
pub use transport::{PeerConnectRequest, PeerEvent, PeerRole, PeerTransport};
