//! In-memory signaling for Source unit tests (no real Presence).

use std::collections::VecDeque;

use async_trait::async_trait;
use idr_core::error::{IdrError, IdrErrorKind, Result};
use idr_protocol::webrtc_ice::{IceRelayMode, IceTransportPolicy, SessionIceConfig, StunPolicy};
use idr_protocol::webrtc_signaling::{
    SessionDescription, WebRtcAnswer, WebRtcIceCandidate, WebRtcSessionRequest,
    WebRtcSessionResultCode,
};
use idr_protocol::{signaling::SignalingMessageType, PROTOCOL_VERSION};
use uuid::Uuid;

use crate::ephemeral::{
    EphemeralSignaling, SessionPending, SignalingMessage, WebRtcSignalingClient,
};

/// Scripted Presence stand-in: returns pending + canned answer after request.
pub struct MockSignalingClient {
    pub answer_sdp: String,
}

impl Default for MockSignalingClient {
    fn default() -> Self {
        Self {
            answer_sdp: "mock-answer".into(),
        }
    }
}

#[async_trait]
impl WebRtcSignalingClient for MockSignalingClient {
    async fn begin_session(
        &mut self,
        request: WebRtcSessionRequest,
    ) -> Result<Box<dyn EphemeralSignaling>> {
        let mut inbox = VecDeque::new();
        inbox.push_back(SignalingMessage::Pending(SessionPending {
            session_id: request.session_id,
            ice: Some(SessionIceConfig {
                relay_mode: IceRelayMode::Platform,
                stun_policy: StunPolicy::GoogleAndIdr,
                stun_servers: None,
                turn: None,
                byor: None,
                ice_transport_policy: IceTransportPolicy::default(),
            }),
        }));
        inbox.push_back(SignalingMessage::Answer(WebRtcAnswer {
            version: PROTOCOL_VERSION,
            message_type: SignalingMessageType::WebRtcAnswer,
            message_id: Uuid::new_v4(),
            session_id: request.session_id,
            sdp: SessionDescription {
                sdp_type: "answer".into(),
                sdp: self.answer_sdp.clone(),
            },
            signature: String::new(),
        }));
        inbox.push_back(SignalingMessage::SessionAck {
            session_id: request.session_id,
            result: WebRtcSessionResultCode::Active,
            detail: None,
        });
        Ok(Box::new(MockEphemeral { inbox }))
    }
}

struct MockEphemeral {
    inbox: VecDeque<SignalingMessage>,
}

#[async_trait]
impl EphemeralSignaling for MockEphemeral {
    async fn next_message(&mut self) -> Result<SignalingMessage> {
        self.inbox.pop_front().ok_or_else(|| {
            IdrError::new(IdrErrorKind::SignalingFailed, "mock signaling exhausted")
        })
    }

    async fn send_ice(&mut self, _candidate: WebRtcIceCandidate) -> Result<()> {
        Ok(())
    }

    async fn send_json(&mut self, _json: &str) -> Result<()> {
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        self.inbox.clear();
        Ok(())
    }
}
