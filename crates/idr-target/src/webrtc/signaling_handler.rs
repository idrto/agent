use std::sync::Arc;

use chrono::Utc;
use ed25519_dalek::VerifyingKey;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::config::{NginxConfig, WebRtcConfig, WebRtcPolicyConfig};
use crate::identity::TargetIdentity;
use crate::presence::outbox::PresenceSignalingOutbox;
use crate::webrtc::session_manager::{SessionError, WebRtcSessionManager};
use idr_core::ConnectorRegistry;
use idr_protocol::signaling::SignalingMessageType;
use idr_protocol::webrtc_ice::{build_rtc_ice_servers, validate_session_ice};
use idr_protocol::webrtc_signaling::{
    WebRtcIceCandidate, WebRtcSessionOffer, WebRtcSessionOfferAck, WebRtcSessionResultCode,
};
use idr_protocol::{
    MAX_ICE_CANDIDATE_BYTES, MAX_SDP_BYTES, MAX_WEBRTC_SIGNALING_BYTES, PROTOCOL_VERSION,
};

#[derive(Clone)]
pub struct WebRtcSignalingHandler {
    cfg: WebRtcConfig,
    fqhn: String,
    identity: TargetIdentity,
    presence_key: VerifyingKey,
    sessions: Arc<WebRtcSessionManager>,
    nginx: NginxConfig,
    policy: WebRtcPolicyConfig,
    connectors: Arc<ConnectorRegistry>,
    insecure_dev: bool,
    transfers: Option<Arc<crate::webrtc::local::TransferEndpoint>>,
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
        connectors: Arc<ConnectorRegistry>,
        insecure_dev: bool,
    ) -> Self {
        Self {
            cfg,
            fqhn,
            identity,
            presence_key,
            sessions,
            nginx,
            policy,
            connectors,
            insecure_dev,
            transfers: None,
        }
    }

    /// Enable peer binding and file transfer on sessions this handler starts.
    pub fn with_transfers(mut self, transfers: Option<Arc<crate::webrtc::local::TransferEndpoint>>) -> Self {
        self.transfers = transfers;
        self
    }

    pub async fn handle_offer(
        &self,
        offer: WebRtcSessionOffer,
        outbox: &PresenceSignalingOutbox,
    ) -> anyhow::Result<()> {
        tracing::info!(event = "webrtc.auto_accepting_webrtc_session_offer", session_id = %offer.connection_id, fqhn = %offer.target_fqhn, sdp_len = offer.sdp.sdp.len());
        let fail = |code: WebRtcSessionResultCode, detail: Option<String>| {
            let session_id = offer.connection_id;
            async move { self.send_offer_ack(outbox, session_id, code, detail).await }
        };

        if offer.target_fqhn != self.fqhn {
            fail(
                WebRtcSessionResultCode::Failed,
                Some("fqhn mismatch".into()),
            )
            .await?;
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
        if offer.session_token.expose().is_empty() {
            fail(
                WebRtcSessionResultCode::Failed,
                Some("missing session_token".into()),
            )
            .await?;
            return Ok(());
        }

        if let Err(e) = offer.verify_presence_signature(&self.presence_key) {
            if self.insecure_dev {
                warn!(event = "webrtc.insecure_dev_accepting_offer_despite_presence", error.message = %e, session_id = %offer.connection_id);
            } else {
                fail(
                    WebRtcSessionResultCode::Failed,
                    Some(format!("offer signature: {e}")),
                )
                .await?;
                return Ok(());
            }
        }
        if let Err(e) = validate_session_ice(&offer.ice) {
            fail(
                WebRtcSessionResultCode::Failed,
                Some(format!("invalid ice: {e}")),
            )
            .await?;
            return Ok(());
        }
        if offer.ice.has_turn_credentials() {
            tracing::info!(event = "webrtc.received_turn_credentials", session_id = %offer.connection_id);
        }

        let guard = match self.sessions.try_acquire(offer.connection_id) {
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
            offer.connection_id,
            WebRtcSessionResultCode::Received,
            None,
        )
        .await?;
        tracing::info!(event = "webrtc.offer_ack_received_sent_starting_webrtc", session_id = %offer.connection_id);

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
        debug!(event = "webrtc.merged_ice_servers_for_webrtc_session", session_id = %offer.connection_id, ice_count = ice_servers.len());

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
                connectors: self.connectors.clone(),
                transfers: self.transfers.clone(),
            };
            guard.keep_alive();
            tokio::spawn(async move {
                if let Err(e) = run_responder_session(runtime).await {
                    warn!(event = "webrtc.webrtc_responder_session_ended_with_error", error.message = %e);
                }
            });
        }

        #[cfg(not(feature = "webrtc"))]
        {
            let _ = ice_servers;
            warn!(event = "webrtc.webrtc_feature_disabled_cannot_complete_sdp", session_id = %offer.connection_id);
            self.send_offer_ack(
                outbox,
                offer.connection_id,
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
        if !self.sessions.contains(msg.connection_id) {
            debug!(event = "webrtc.ice_for_unknown_session", session_id = %msg.connection_id);
            return Ok(());
        }
        self.sessions.touch(msg.connection_id);
        if let Some(inbox) = self.sessions.ice_inbox(msg.connection_id) {
            inbox.add_candidate(msg.candidate, msg.mid).await?;
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
            connection_id: session_id,
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
            connection_id: session_id,
            result,
            detail,
        };
        outbox.send_json(&serde_json::to_string(&ack)?).await
    }
}
