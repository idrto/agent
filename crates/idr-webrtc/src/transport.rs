//! Transport-independent peer connection trait.

use async_trait::async_trait;

use idr_core::error::Result;

/// Whether this agent creates the offer or the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRole {
    Offerer,
    Answerer,
}

#[derive(Debug, Clone)]
pub struct PeerConnectRequest {
    pub role: PeerRole,
    pub ice_servers_json: Option<String>,
}

#[derive(Debug, Clone)]
pub enum PeerEvent {
    LocalDescription { sdp_type: String, sdp: String },
    LocalCandidate { candidate: String, mid: String },
    GatheringComplete,
    DataChannelOpen,
    DataChannelClosed,
    BinaryMessage(Vec<u8>),
    ConnectionFailed,
    Closed,
}

/// Abstraction over a WebRTC peer (libdatachannel, mock, or browser JS host).
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg(not(target_arch = "wasm32"))]
pub trait PeerTransport: Send {
    async fn start(&mut self, request: PeerConnectRequest) -> Result<()>;

    async fn set_remote_description(&mut self, sdp_type: &str, sdp: &str) -> Result<()>;

    async fn create_local_description(&mut self) -> Result<()>;

    fn add_remote_candidate(&mut self, candidate: &str, mid: &str) -> Result<()>;

    fn send_binary(&mut self, message: &[u8]) -> Result<()>;

    async fn next_event(&mut self) -> Result<PeerEvent>;

    fn close(&mut self);

    /// Apply ICE servers after start (e.g. Presence `webrtc_session_pending`).
    fn set_ice_servers_json(&mut self, _json: &str) -> Result<()> {
        Ok(())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg(target_arch = "wasm32")]
pub trait PeerTransport {
    async fn start(&mut self, request: PeerConnectRequest) -> Result<()>;

    async fn set_remote_description(&mut self, sdp_type: &str, sdp: &str) -> Result<()>;

    async fn create_local_description(&mut self) -> Result<()>;

    fn add_remote_candidate(&mut self, candidate: &str, mid: &str) -> Result<()>;

    fn send_binary(&mut self, message: &[u8]) -> Result<()>;

    async fn next_event(&mut self) -> Result<PeerEvent>;

    fn close(&mut self);

    fn set_ice_servers_json(&mut self, _json: &str) -> Result<()> {
        Ok(())
    }
}
