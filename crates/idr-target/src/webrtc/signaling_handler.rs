use std::sync::Arc;

use chrono::Utc;
use ed25519_dalek::VerifyingKey;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::config::{NginxConfig, WebRtcConfig, WebRtcPolicyConfig};
use crate::identity::TargetIdentity;
use crate::presence::outbox::PresenceSignalingOutbox;
use idr_protocol::signaling::SignalingMessageType;
use idr_protocol::webrtc_ice::{build_rtc_ice_servers, validate_session_ice};
use idr_protocol::webrtc_signaling::{
    WebRtcIceCandidate, WebRtcSessionOffer, WebRtcSessionOfferAck, WebRtcSessionResultCode,
};
use idr_protocol::{MAX_ICE_CANDIDATE_BYTES, MAX_SDP_BYTES, MAX_WEBRTC_SIGNALING_BYTES, PROTOCOL_VERSION};
use crate::webrtc::session_manager::{SessionError, WebRtcSessionManager};

#[derive(Clone)]
pub struct WebRtcSignalingHandler {
    cfg: WebRtcConfig,
    fqhn: String,
    identity: TargetIdentity,
    presence_key: VerifyingKey,
    sessions: Arc<WebRtcSessionManager>,
    nginx: NginxConfig,
    policy: WebRtcPolicyConfig,
}

impl WebRtcSignalingHandler {
    pub fn new(
        cfg: WebRtcConfig,
        fqhn: String,
        identity: TargetIdentity,
        presence_key: VerifyingKey,
        sessions: Arc<WebRtcSessionManager>,
        nginx: NginxConfig,
        policy: WebRtcPolicyConfig,
    ) -> Self {
        Self {
            cfg,
            fqhn,
            identity,
            presence_key,
            sessions,
            nginx,
            policy,
        }
    }

    pub async fn handle_offer(
        &self,
        offer: WebRtcSessionOffer,
        outbox: &PresenceSignalingOutbox,
    ) -> anyhow::Result<()> {
        let fail = |code: WebRtcSessionResultCode, detail: Option<String>| {
            let session_id = offer.session_id;
            async move {
                self.send_offer_ack(outbox, session_id, code, detail).await
            }
        };

        if offer.target_fqhn != self.fqhn {
            fail(WebRtcSessionResultCode::Failed, Some("fqhn mismatch".into())).await?;
            return Ok(());
        }
        if Utc::now() > offer.expires_at {
            fail(WebRtcSessionResultCode::Expired, None).await?;
            return Ok(());
        }
        if offer.sdp.sdp.len() > MAX_SDP_BYTES {
            fail(
                WebRtcSessionResultCode::Failed,
                Some("SDP too large".into()),
            )
            .await?;
            return Ok(());
        }
        if serde_json::to_vec(&offer).map(|b| b.len()).unwrap_or(0) > MAX_WEBRTC_SIGNALING_BYTES {
            fail(
                WebRtcSessionResultCode::Failed,
                Some("offer too large".into()),
            )
            .await?;
            return Ok(());
        }
        if offer.session_token.is_empty() {
            fail(
                WebRtcSessionResultCode::Failed,
                Some("missing session_token".into()),
            )
            .await?;
            return Ok(());
        }

        if let Err(e) = offer.verify_presence_signature(&self.presence_key) {
            fail(
                WebRtcSessionResultCode::Failed,
                Some(format!("offer signature: {e}")),
            )
            .await?;
            return Ok(());
        }
        if let Err(e) = validate_session_ice(&offer.ice) {
            fail(
                WebRtcSessionResultCode::Failed,
                Some(format!("invalid ice: {e}")),
            )
            .await?;
            return Ok(());
        }

        let guard = match self.sessions.try_acquire(offer.session_id) {
            Ok(g) => g,
            Err(SessionError::Busy) => {
                fail(WebRtcSessionResultCode::Busy, None).await?;
                return Ok(());
            }
            Err(SessionError::Duplicate) => {
                fail(
                    WebRtcSessionResultCode::Busy,
                    Some("duplicate session".into()),
                )
                .await?;
                return Ok(());
            }
            Err(e) => {
                fail(WebRtcSessionResultCode::Failed, Some(e.to_string())).await?;
                return Ok(());
            }
        };

        self.send_offer_ack(
            outbox,
            offer.session_id,
            WebRtcSessionResultCode::Received,
            None,
        )
        .await?;

        let stun_override = self
            .cfg
            .stun
            .urls
            .iter()
            .map(|url| idr_protocol::webrtc_ice::IceServer {
                urls: vec![url.clone()],
                username: None,
                credential: None,
            })
            .collect::<Vec<_>>();

        let ice_servers = match build_rtc_ice_servers(&offer.ice, &stun_override) {
            Ok(s) => s,
            Err(e) => {
                fail(
                    WebRtcSessionResultCode::Failed,
                    Some(format!("ice merge: {e}")),
                )
                .await?;
                return Ok(());
            }
        };
        debug!(
            session_id = %offer.session_id,
            ice_count = ice_servers.len(),
            "merged ICE servers for WebRTC session"
        );

        #[cfg(feature = "webrtc")]
        {
            use crate::webrtc::session::{run_responder_session, SessionRuntime};
            let runtime = SessionRuntime {
                ice_transport_policy: offer.ice.ice_transport_policy,
                offer,
                ice_servers,
                outbox: outbox.clone(),
                identity: self.identity.clone(),
                sessions: self.sessions.clone(),
                nginx: self.nginx.clone(),
                policy: self.policy.clone(),
                fqhn: self.fqhn.clone(),
            };
            guard.keep_alive();
            tokio::spawn(async move {
                if let Err(e) = run_responder_session(runtime).await {
                    warn!(error = %e, "WebRTC responder session ended with error");
                }
            });
        }

        #[cfg(not(feature = "webrtc"))]
        {
            let _ = ice_servers;
            warn!(
                session_id = %offer.session_id,
                "webrtc feature disabled; cannot complete SDP answer"
            );
            self.send_offer_ack(
                outbox,
                offer.session_id,
                WebRtcSessionResultCode::Failed,
                Some("webrtc feature not enabled".into()),
            )
            .await?;
            drop(guard);
        }

        Ok(())
    }

    pub async fn handle_ice_candidate(
        &self,
        msg: WebRtcIceCandidate,
        _outbox: &PresenceSignalingOutbox,
    ) -> anyhow::Result<()> {
        if msg.candidate.len() > MAX_ICE_CANDIDATE_BYTES {
            anyhow::bail!("ICE candidate too large");
        }
        if !self.sessions.contains(msg.session_id) {
            debug!(session_id = %msg.session_id, "ICE for unknown session");
            return Ok(());
        }
        self.sessions.touch(msg.session_id);
        if let Some(inbox) = self.sessions.ice_inbox(msg.session_id) {
            inbox
                .add_candidate(msg.candidate, msg.mid)
                .await?;
        }
        Ok(())
    }

    pub async fn handle_session_end(
        &self,
        session_id: Uuid,
        outbox: &PresenceSignalingOutbox,
    ) -> anyhow::Result<()> {
        self.sessions.end_session(session_id);
        let ack = idr_protocol::webrtc_signaling::WebRtcSessionAck {
            version: PROTOCOL_VERSION,
            message_type: SignalingMessageType::WebRtcSessionAck,
            message_id: Uuid::new_v4(),
            session_id,
            result: WebRtcSessionResultCode::Failed,
            detail: Some("ended".into()),
        };
        outbox.send_json(&serde_json::to_string(&ack)?).await
    }

    async fn send_offer_ack(
        &self,
        outbox: &PresenceSignalingOutbox,
        session_id: Uuid,
        result: WebRtcSessionResultCode,
        detail: Option<String>,
    ) -> anyhow::Result<()> {
        let ack = WebRtcSessionOfferAck {
            version: PROTOCOL_VERSION,
            message_type: SignalingMessageType::WebRtcSessionOfferAck,
            message_id: Uuid::new_v4(),
            session_id,
            result,
            detail,
        };
        outbox.send_json(&serde_json::to_string(&ack)?).await
    }
}
