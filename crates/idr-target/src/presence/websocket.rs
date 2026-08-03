use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use futures::{SinkExt, StreamExt};
use tokio::io::AsyncReadExt;
use tokio::time::{sleep, sleep_until, Instant};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, Message},
};
use tracing::{debug, error, info, warn};

use crate::auth::mint_agent_token;
use crate::config::{Config, PresenceConfig};
use crate::identity::TargetIdentity;
use crate::network::NetworkCapabilities;
use crate::presence::dedup::{CachedCommandResult, CommandDedup, DedupAction};
use crate::presence::endpoint::{
    build_transport_attempts, transport_label, PresenceNetworkCaps, PresenceTransportChoice,
};
use crate::presence::outbox::PresenceSignalingOutbox;
use crate::presence::quic_client::PresenceQuicClient;
use crate::presence::registration::build_registration;
use crate::relay::descriptor::{ConnectionAuthorization, StableRelayDescriptor};
use crate::relay::RelayConnectionManager;
use crate::shutdown::ShutdownCoordinator;
use crate::telemetry::Metrics;
use crate::webrtc::probe::{send_probe_request, spawn_probe_on_push, ProbeScheduler};
use crate::webrtc::{WebRtcSessionManager, WebRtcSignalingHandler};
use idr_dp::DeviceIdentity;
use idr_protocol::discovery::PresenceServer;
use idr_protocol::signaling::{
    CommandResultCode, EnsureRelayConnectionCommand, SignalingMessageType,
};
use idr_protocol::signaling_json;
use idr_protocol::webrtc_signaling::{
    RegisterTargetAck, TurnProbeCandidates, WebRtcIceCandidate, WebRtcSessionOffer,
};
use tokio::sync::Mutex;

struct PresentedEntitlement {
    token: String,
    refresh_at: Option<Instant>,
}

fn token_refresh_delay(ttl_seconds: u64) -> Duration {
    if ttl_seconds <= 60 {
        Duration::from_secs((ttl_seconds / 2).max(1))
    } else {
        Duration::from_secs(ttl_seconds - 30)
    }
}

pub struct PresenceWebSocketClient {
    server: PresenceServer,
    role: idr_protocol::signaling::PresenceRole,
    identity: TargetIdentity,
    fqhn: String,
    cfg: PresenceConfig,
    reg_cfg: Config,
    metrics: Metrics,
    shutdown: ShutdownCoordinator,
    relay_manager: Arc<RelayConnectionManager>,
    dedup: Arc<CommandDedup>,
    relay_verify_key: VerifyingKey,
    connection_epoch: u64,
    discovery_generation: u64,
    quic_client: Arc<PresenceQuicClient>,
    webrtc_sessions: Arc<WebRtcSessionManager>,
    signaling_outbox: Arc<Mutex<Option<PresenceSignalingOutbox>>>,
    /// DP DeviceIdentity for agent entitlement JWT mint (and Presence mTLS).
    device_identity: Option<Arc<DeviceIdentity>>,
}

impl PresenceWebSocketClient {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: PresenceServer,
        role: idr_protocol::signaling::PresenceRole,
        identity: TargetIdentity,
        fqhn: String,
        cfg: PresenceConfig,
        reg_cfg: Config,
        metrics: Metrics,
        shutdown: ShutdownCoordinator,
        relay_manager: Arc<RelayConnectionManager>,
        dedup: Arc<CommandDedup>,
        relay_verify_key: VerifyingKey,
        connection_epoch: u64,
        discovery_generation: u64,
        quic_client: Arc<PresenceQuicClient>,
        webrtc_sessions: Arc<WebRtcSessionManager>,
        device_identity: Option<Arc<DeviceIdentity>>,
    ) -> Self {
        Self {
            server,
            role,
            identity,
            fqhn,
            cfg,
            reg_cfg,
            metrics,
            shutdown,
            relay_manager,
            dedup,
            relay_verify_key,
            connection_epoch,
            discovery_generation,
            quic_client,
            webrtc_sessions,
            signaling_outbox: Arc::new(Mutex::new(None)),
            device_identity,
        }
    }

    /// Mint a Presence entitlement JWT when DP identity is available.
    async fn mint_entitlement_jwt(&self) -> Result<Option<PresentedEntitlement>> {
        let Some(identity) = self.device_identity.as_ref() else {
            if self.reg_cfg.auth.required {
                anyhow::bail!(
                    "auth.required=true but no DP DeviceIdentity loaded; set [dp].identity_path or --identity"
                );
            }
            return Ok(None);
        };
        let target_identity = self.identity.public_key_base64url();
        let using_party = (!self.reg_cfg.billing_party.using_party.is_empty()
            && self.reg_cfg.billing_party.using_party != "unconfigured@local")
            .then_some(self.reg_cfg.billing_party.using_party.as_str());
        match mint_agent_token(
            &self.reg_cfg.auth,
            identity.as_ref(),
            Some(&target_identity),
            using_party,
        )
        .await
        {
            Ok(tok) => {
                info!(
                    ski = %identity.ski,
                    expires_in = ?tok.expires_in,
                    "minted Presence entitlement JWT"
                );
                Ok(Some(PresentedEntitlement {
                    token: tok.token,
                    refresh_at: tok
                        .expires_in
                        .map(token_refresh_delay)
                        .map(|delay| Instant::now() + delay),
                }))
            }
            Err(e) if self.reg_cfg.auth.required => Err(e).context("mint agent entitlement JWT"),
            Err(e) => {
                warn!(error = %e, "agent JWT mint failed; registering without entitlement_jwt");
                Ok(None)
            }
        }
    }

    pub async fn run(&self) -> Result<()> {
        let role_label = match self.role {
            idr_protocol::signaling::PresenceRole::Primary => "primary",
            idr_protocol::signaling::PresenceRole::Secondary => "secondary",
        };
        let mut backoff = self.cfg.reconnect_initial();
        let mut last_caps = NetworkCapabilities::detect();
        loop {
            if self.shutdown.is_draining() {
                break;
            }
            let caps = NetworkCapabilities::detect();
            let caps_changed = caps != last_caps;
            if caps_changed {
                last_caps = caps;
            }
            self.relay_manager.refresh_network_caps(caps);
            if caps_changed && self.reg_cfg.webrtc.enabled && self.reg_cfg.webrtc.turn_probe_enabled
            {
                if let Some(outbox) = self.signaling_outbox.lock().await.clone() {
                    let identity = self.identity.clone();
                    let fqhn = self.fqhn.clone();
                    let role = self.role;
                    if let Err(e) =
                        send_probe_request(&outbox, &identity, &fqhn, role, "network_change").await
                    {
                        warn!(error = %e, "network-change TURN reprobe request failed");
                    }
                }
            }
            let network = PresenceNetworkCaps::from_detect(&caps);
            match self.connect_with_fallback(role_label, &network).await {
                Ok(()) => {
                    backoff = self.cfg.reconnect_initial();
                    if self.shutdown.is_draining() {
                        break;
                    }
                }
                Err(err) => {
                    warn!(role = role_label, error = %err, "presence session error");
                    backoff = (backoff * 2).min(self.cfg.reconnect_max());
                }
            }
            *self.signaling_outbox.lock().await = None;
            self.metrics
                .presence_connected
                .with_label_values(&[role_label])
                .set(0);
            sleep(backoff).await;
        }
        Ok(())
    }

    async fn connect_with_fallback(
        &self,
        role_label: &'static str,
        network: &PresenceNetworkCaps,
    ) -> Result<()> {
        let attempts = build_transport_attempts(&self.server, network, self.cfg.prefer_quic);
        if attempts.is_empty() {
            anyhow::bail!("no compatible presence transports");
        }

        let entitlement = self.mint_entitlement_jwt().await?;
        let refresh_at = entitlement.as_ref().and_then(|token| token.refresh_at);
        let reg = build_registration(
            &self.identity,
            &self.fqhn,
            self.connection_epoch,
            self.discovery_generation,
            self.role,
            &self.reg_cfg,
            entitlement.map(|token| token.token),
        )?;
        let reg_json = serde_json::to_string(&reg)?;

        let mut last_err = None;
        for (i, choice) in attempts.into_iter().enumerate() {
            if i > 0 {
                sleep(self.cfg.transport_fallback_delay()).await;
            }
            let label = transport_label(choice);
            debug!(
                transport = label,
                role = role_label,
                "attempting presence connect"
            );
            let result = match choice {
                PresenceTransportChoice::Quic(addr) => {
                    self.connect_quic_and_serve(role_label, addr, &reg_json, refresh_at)
                        .await
                }
                PresenceTransportChoice::Wss => {
                    self.connect_wss_and_serve(role_label, &reg_json, refresh_at)
                        .await
                }
            };
            match result {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!(transport = label, error = %e, "presence transport failed");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("all presence transports failed")))
    }

    async fn connect_quic_and_serve(
        &self,
        role_label: &'static str,
        addr: std::net::SocketAddr,
        reg_json: &str,
        refresh_at: Option<Instant>,
    ) -> Result<()> {
        let connection = self
            .quic_client
            .connect_persistent(&self.server, addr, reg_json, self.cfg.connect_timeout())
            .await?;
        self.metrics
            .presence_connected
            .with_label_values(&[role_label])
            .set(1);
        info!(
            role = role_label,
            presence_id = %self.server.presence_id,
            transport = "quic",
            "presence connected"
        );
        self.on_presence_registered(role_label);

        let outbox = PresenceSignalingOutbox::from_quic(connection.clone());
        *self.signaling_outbox.lock().await = Some(outbox.clone());

        let shutdown = self.shutdown.clone();
        let client = self.clone_for_task(outbox);

        loop {
            tokio::select! {
                uni = connection.accept_uni() => {
                    match uni {
                        Ok(recv) => {
                            let client = client.clone();
                            tokio::spawn(async move {
                                if let Err(e) = client.read_quic_push(recv).await {
                                    error!(error = %e, "QUIC push read failed");
                                }
                            });
                        }
                        Err(e) => {
                            debug!(?e, "presence QUIC accept_uni ended");
                            break;
                        }
                    }
                }
                reason = connection.closed() => {
                    debug!(?reason, "presence QUIC closed");
                    break;
                }
                _ = async {
                    match refresh_at {
                        Some(deadline) => sleep_until(deadline).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    info!("refreshing Presence entitlement JWT");
                    connection.close(0u32.into(), b"entitlement refresh");
                    break;
                }
                _ = shutdown.wait_for_drain() => break,
            }
        }
        Ok(())
    }

    async fn connect_wss_and_serve(
        &self,
        role_label: &'static str,
        reg_json: &str,
        refresh_at: Option<Instant>,
    ) -> Result<()> {
        let mut request = self
            .server
            .wss_url
            .as_str()
            .into_client_request()
            .context("build websocket request")?;
        request.headers_mut().insert(
            "Host",
            self.server
                .server_name
                .parse()
                .context("parse Host header")?,
        );

        let (ws, _) = connect_async(request).await.context("websocket connect")?;
        self.metrics
            .presence_connected
            .with_label_values(&[role_label])
            .set(1);
        info!(
            role = role_label,
            presence_id = %self.server.presence_id,
            transport = "wss",
            "presence connected"
        );
        self.on_presence_registered(role_label);

        let (write, mut read) = ws.split();
        let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let outbox = PresenceSignalingOutbox::from_wss(out_tx.clone());
        *self.signaling_outbox.lock().await = Some(outbox.clone());

        let mut write_sink = write;
        tokio::spawn(async move {
            while let Some(msg) = out_rx.recv().await {
                if write_sink.send(Message::Text(msg)).await.is_err() {
                    break;
                }
            }
        });

        out_tx
            .send(reg_json.to_string())
            .map_err(|_| anyhow::anyhow!("wss outbox closed"))?;

        while !self.shutdown.is_draining() {
            tokio::select! {
                msg = read.next() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            if let Err(e) = self.clone_for_task(outbox.clone()).handle_message(&text).await {
                                error!(error = %e, "handle presence message failed");
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => break,
                        Some(Err(e)) => return Err(e.into()),
                        _ => {}
                    }
                }
                _ = async {
                    match refresh_at {
                        Some(deadline) => sleep_until(deadline).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    info!("refreshing Presence entitlement JWT");
                    break;
                }
                _ = self.shutdown.wait_for_drain() => break,
            }
        }
        Ok(())
    }

    fn on_presence_registered(&self, role_label: &'static str) {
        if role_label == "primary" {
            self.relay_manager.spawn_warm_reconnect();
        }
    }

    fn clone_for_task(&self, outbox: PresenceSignalingOutbox) -> PresenceClientTask {
        let probe = if self.reg_cfg.webrtc.enabled {
            Some(ProbeScheduler::new(
                self.reg_cfg.webrtc.clone(),
                self.fqhn.clone(),
                self.role,
                self.reg_cfg.target.agent_region.clone(),
                self.identity.clone(),
            ))
        } else {
            None
        };
        let webrtc = if self.reg_cfg.webrtc.enabled {
            Some(WebRtcSignalingHandler::new(
                self.reg_cfg.webrtc.clone(),
                self.fqhn.clone(),
                self.identity.clone(),
                self.relay_verify_key,
                self.webrtc_sessions.clone(),
                self.reg_cfg.nginx.clone(),
                self.reg_cfg.webrtc.policy.clone(),
            ))
        } else {
            None
        };
        PresenceClientTask {
            relay_verify_key: self.relay_verify_key,
            relay_manager: self.relay_manager.clone(),
            dedup: self.dedup.clone(),
            identity: self.identity.clone(),
            metrics: self.metrics.clone(),
            outbox,
            probe,
            webrtc,
            reg_cfg: self.reg_cfg.clone(),
        }
    }

    async fn handle_message(&self, text: &str) -> Result<()> {
        if let Some(outbox) = self.signaling_outbox.lock().await.clone() {
            self.clone_for_task(outbox).handle_message(text).await
        } else {
            Ok(())
        }
    }
}

#[derive(Clone)]
struct PresenceClientTask {
    relay_verify_key: VerifyingKey,
    relay_manager: Arc<RelayConnectionManager>,
    dedup: Arc<CommandDedup>,
    identity: TargetIdentity,
    metrics: Metrics,
    outbox: PresenceSignalingOutbox,
    probe: Option<ProbeScheduler>,
    webrtc: Option<WebRtcSignalingHandler>,
    reg_cfg: Config,
}

impl PresenceClientTask {
    async fn read_quic_push(&self, mut recv: quinn::RecvStream) -> Result<()> {
        let buf = recv
            .read_to_end(idr_protocol::MAX_WEBRTC_SIGNALING_BYTES)
            .await
            .context("read push stream")?;
        let json_bytes = signaling_json::decode_json_frame_auto(&buf)
            .map_err(|e| anyhow::anyhow!("decode push frame: {e}"))?;
        let text = std::str::from_utf8(&json_bytes).context("push utf8")?;
        self.handle_message(text).await
    }

    async fn handle_message(&self, text: &str) -> Result<()> {
        let value: serde_json::Value = serde_json::from_str(text)?;
        let Some(msg_type) = value.get("message_type").and_then(|v| v.as_str()) else {
            return Ok(());
        };
        if msg_type != "ensure_relay_connection" {
            return self.handle_webrtc_message(msg_type, text).await;
        }
        let cmd: EnsureRelayConnectionCommand = serde_json::from_value(value)?;
        if cmd.message_type != SignalingMessageType::EnsureRelayConnection {
            return Ok(());
        }

        cmd.verify(&self.relay_verify_key)
            .map_err(|e| anyhow::anyhow!("command verify failed: {e}"))?;

        let command_id = cmd.command_id;
        let digest = idr_protocol::crypto::content_digest(&serde_json::to_value(&cmd)?);

        match self
            .dedup
            .check_or_register(&cmd)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?
        {
            DedupAction::Cached(_result) => {
                self.metrics.signaling_duplicates_total.inc();
                self.metrics.inc_signaling_result("duplicate");
            }
            DedupAction::Wait(in_flight) => {
                self.metrics.signaling_duplicates_total.inc();
                let _ = in_flight.wait().await;
            }
            DedupAction::Process(_in_flight) => {
                self.metrics.inc_signaling_result("received");
                let result = self.process_command(cmd).await;
                match result {
                    Ok(r) => {
                        self.dedup.complete(command_id, digest, r.clone()).await;
                        self.metrics.inc_signaling_result(result_label(r.result));
                    }
                    Err(e) => {
                        self.dedup.fail(command_id, e.to_string()).await;
                        self.metrics.inc_signaling_result("failed");
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_webrtc_message(&self, msg_type: &str, text: &str) -> Result<()> {
        match msg_type {
            "turn_probe_candidates" => {
                if let (Some(probe), Ok(msg)) = (
                    self.probe.as_ref(),
                    serde_json::from_str::<TurnProbeCandidates>(text),
                ) {
                    if let Err(e) = msg.verify(&self.relay_verify_key) {
                        warn!(error = %e, "turn_probe_candidates signature rejected");
                    } else {
                        spawn_probe_on_push(probe.clone(), self.outbox.clone(), msg);
                    }
                }
            }
            "webrtc_session_offer" => {
                if let (Some(handler), Ok(offer)) = (
                    self.webrtc.as_ref(),
                    serde_json::from_str::<WebRtcSessionOffer>(text),
                ) {
                    let outbox = self.outbox.clone();
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handler.handle_offer(offer, &outbox).await {
                            error!(error = %e, "WebRTC offer handling failed");
                        }
                    });
                }
            }
            "webrtc_ice_candidate" => {
                if let (Some(handler), Ok(candidate)) = (
                    self.webrtc.as_ref(),
                    serde_json::from_str::<WebRtcIceCandidate>(text),
                ) {
                    let outbox = self.outbox.clone();
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        let _ = handler.handle_ice_candidate(candidate, &outbox).await;
                    });
                }
            }
            "webrtc_session_end" => {
                if let (Some(handler), Ok(value)) = (
                    self.webrtc.as_ref(),
                    serde_json::from_str::<serde_json::Value>(text),
                ) {
                    if let Some(session_id) = value
                        .get("session_id")
                        .and_then(|v| v.as_str())
                        .and_then(|s| uuid::Uuid::parse_str(s).ok())
                    {
                        let outbox = self.outbox.clone();
                        let handler = handler.clone();
                        tokio::spawn(async move {
                            let _ = handler.handle_session_end(session_id, &outbox).await;
                        });
                    }
                }
            }
            "turn_probe_ack" => {
                debug!("received turn_probe_ack");
            }
            "register_target_ack" => match serde_json::from_str::<RegisterTargetAck>(text) {
                Ok(ack) => {
                    if ack.turn_mint_allowed {
                        info!(
                            target_fqhn = %ack.target_fqhn,
                            fallback = %ack.webrtc_fallback,
                            "register_target_ack: platform TURN available"
                        );
                    } else if ack.target_allows_p2p {
                        warn!(
                            target_fqhn = %ack.target_fqhn,
                            fallback = %ack.webrtc_fallback,
                            reason = ack.reason.as_deref().unwrap_or("data_transfer_exhausted"),
                            "register_target_ack: no TURN mint; WebRTC sessions will be P2P-only"
                        );
                    } else {
                        warn!(
                            target_fqhn = %ack.target_fqhn,
                            reason = ack.reason.as_deref().unwrap_or("payment_required"),
                            "register_target_ack: TURN unavailable and Target forbids P2P"
                        );
                    }
                }
                Err(e) => warn!(error = %e, "invalid register_target_ack"),
            },
            _ => {}
        }
        Ok(())
    }

    async fn process_command(
        &self,
        cmd: EnsureRelayConnectionCommand,
    ) -> Result<CachedCommandResult> {
        let descriptor = StableRelayDescriptor::from(cmd.relay.clone());
        let auth = ConnectionAuthorization {
            session_id: cmd.session_id,
            target_fqhn: cmd.target_fqhn.clone(),
            target_identity: self.identity.public_key_base64url(),
            connection_token: cmd.connection_token,
            connection_epoch: cmd.connection_epoch,
            command_id: cmd.command_id,
            expires_at: Some(cmd.expires_at),
        };

        match self.relay_manager.get_or_connect(descriptor, auth).await {
            Ok(_conn) => Ok(CachedCommandResult {
                result: CommandResultCode::Active,
                detail: None,
            }),
            Err(e) => Ok(CachedCommandResult {
                result: CommandResultCode::Failed,
                detail: Some(e.to_string()),
            }),
        }
    }
}

fn result_label(code: CommandResultCode) -> &'static str {
    match code {
        CommandResultCode::Received => "received",
        CommandResultCode::Connecting => "connecting",
        CommandResultCode::Active => "active",
        CommandResultCode::Failed => "failed",
        CommandResultCode::Expired => "expired",
        CommandResultCode::Offline => "offline",
    }
}

#[cfg(test)]
mod auth_lifecycle_tests {
    use super::*;

    #[test]
    fn refreshes_before_normal_token_expiry() {
        assert_eq!(token_refresh_delay(3600), Duration::from_secs(3570));
    }

    #[test]
    fn short_lived_tokens_refresh_halfway() {
        assert_eq!(token_refresh_delay(60), Duration::from_secs(30));
        assert_eq!(token_refresh_delay(1), Duration::from_secs(1));
    }
}
