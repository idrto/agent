//! Ephemeral WebRTC signaling channel abstraction.

use async_trait::async_trait;
use idr_core::error::Result;
use idr_protocol::webrtc_ice::SessionIceConfig;
use idr_protocol::webrtc_signaling::{
    WebRtcAnswer, WebRtcIceCandidate, WebRtcSessionRequest, WebRtcSessionResultCode,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Messages Source may receive on the ephemeral Presence channel.
#[derive(Debug, Clone)]
pub enum SignalingMessage {
    Pending(SessionPending),
    Answer(WebRtcAnswer),
    IceCandidate(WebRtcIceCandidate),
    IceComplete { session_id: Uuid },
    SessionAck {
        session_id: Uuid,
        result: WebRtcSessionResultCode,
        detail: Option<String>,
    },
    Error { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPending {
    pub session_id: Uuid,
    #[serde(default)]
    pub ice: Option<SessionIceConfig>,
}

/// Client that opens an ephemeral Presence session for WebRTC negotiation.
#[async_trait]
pub trait WebRtcSignalingClient: Send {
    /// Send session request and return the signaling channel handle.
    async fn begin_session(
        &mut self,
        request: WebRtcSessionRequest,
    ) -> Result<Box<dyn EphemeralSignaling>>;
}

#[async_trait]
pub trait EphemeralSignaling: Send {
    async fn next_message(&mut self) -> Result<SignalingMessage>;

    async fn send_ice(&mut self, candidate: WebRtcIceCandidate) -> Result<()>;

    async fn send_json(&mut self, json: &str) -> Result<()>;

    async fn close(&mut self) -> Result<()>;
}
