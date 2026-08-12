//! WebRTC transport abstraction — no libdatachannel types in the public API.

pub mod mock;
#[cfg(feature = "native")]
pub mod native;
pub mod recording;
pub mod transport;

#[cfg(feature = "native")]
pub use native::NativePeer;
pub use recording::RecordingPeer;
pub use transport::{PeerConnectRequest, PeerEvent, PeerRole, PeerTransport};
