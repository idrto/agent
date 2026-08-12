use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use futures::{SinkExt, StreamExt};
use tokio::io::AsyncReadExt;
use tokio::time::sleep;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, Message},
};
use tracing::{debug, error, info, warn};

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
use idr_protocol::discovery::PresenceServer;
use idr_protocol::signaling::{
    CommandResultCode, EnsureRelayConnectionCommand, SignalingMessageType,
};
use idr_protocol::signaling_json;
use idr_protocol::webrtc_signaling::{
    RegisterTargetAck, TurnProbeCandidates, WebRtcIceCandidate, WebRtcSessionOffer,
};
use tokio::sync::Mutex;

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
    connectors: Arc<idr_core::ConnectorRegistry>,
    signaling_outbox: Arc<Mutex<Option<PresenceSignalingOutbox>>>,
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
        connectors: Arc<idr_core::ConnectorRegistry>,
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
            connectors,
            signaling_outbox: Arc::new(Mutex::new(None)),
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
                    if self.shutdown.is_draining() {
                        break;
                    }
                }
                Err(err) => {
                    warn!(role = role_label, error = %err, "presence session error");
                }
            }
            self.metrics
                .presence_connected
                .with_label_values(&[role_label])
                .set(0);
            sleep(backoff).await;
            backoff = (backoff * 2).min(self.cfg.reconnect_max());
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

        let named = self.connectors.service_names();
        let reg = build_registration(
            &self.identity,
            &self.fqhn,
            self.connection_epoch,
            self.discovery_generation,
            self.role,
            &self.reg_cfg,
            &named,
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
                    self.connect_quic_and_serve(role_label, addr, &reg_json)
                        .await
                }
                PresenceTransportChoice::Wss => {
                    self.connect_wss_and_serve(role_label, &reg_json).await
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
                _ = shutdown.wait_for_drain() => break,
            }
        }
        Ok(())
    }

    async fn connect_wss_and_serve(&self, role_label: &'static str, reg_json: &str) -> Result<()> {
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
                self.connectors.clone(),
                self.reg_cfg.presence.insecure_dev,
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
        info!(bytes = json_bytes.len(), "presence QUIC push received");
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

        info!(
            target_fqhn = %cmd.target_fqhn,
            command_id = %cmd.command_id,
            relay_id = %cmd.relay.relay_id,
            relay_ipv4 = ?cmd.relay.ipv4,
            relay_port = cmd.relay.port,
            server_name = %cmd.relay.server_name,
            "received ensure_relay_connection"
        );

        cmd.verify(&self.relay_verify_key).or_else(|e| {
            if self.reg_cfg.presence.insecure_dev {
                warn!(
                    error = %e,
                    "insecure_dev: accepting ensure command despite signature verify failure"
                );
                Ok(())
            } else {
                Err(anyhow::anyhow!("command verify failed: {e}"))
            }
        })?;

        let command_id = cmd.command_id;
        let digest = idr_protocol::crypto::content_digest(&serde_json::to_value(&cmd)?);

        match self
            .dedup
            .check_or_register(&cmd)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?
        {
            DedupAction::Cached(_result) => {
                info!(command_id = %command_id, "ensure ignored: duplicate (cached)");
                self.metrics.signaling_duplicates_total.inc();
                self.metrics.inc_signaling_result("duplicate");
            }
            DedupAction::Wait(in_flight) => {
                info!(command_id = %command_id, "ensure waiting on in-flight connect");
                self.metrics.signaling_duplicates_total.inc();
                let _ = in_flight.wait().await;
            }
            DedupAction::Process(_in_flight) => {
                self.metrics.inc_signaling_result("received");
                let result = self.process_command(cmd).await;
                match result {
                    Ok(r) => {
                        info!(
                            command_id = %command_id,
                            result = ?r.result,
                            detail = ?r.detail,
                            "ensure connect finished"
                        );
                        self.dedup.complete(command_id, digest, r.clone()).await;
                        self.metrics.inc_signaling_result(result_label(r.result));
                    }
                    Err(e) => {
                        error!(command_id = %command_id, error = %e, "ensure processing failed");
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
                match (
                    self.webrtc.as_ref(),
                    serde_json::from_str::<WebRtcSessionOffer>(text),
                ) {
                    (Some(handler), Ok(offer)) => {
                        let outbox = self.outbox.clone();
                        let handler = handler.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handler.handle_offer(offer, &outbox).await {
                                error!(error = %e, "WebRTC offer handling failed");
                            }
                        });
                    }
                    (None, _) => {
                        warn!("webrtc_session_offer received but WebRTC handler not configured");
                    }
                    (Some(_), Err(e)) => {
                        warn!(error = %e, "failed to parse webrtc_session_offer");
                    }
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
            "register_target_ack" => {
                match serde_json::from_str::<RegisterTargetAck>(text) {
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
                }
            }
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

        info!(
            relay_id = %cmd.relay.relay_id,
            relay_ipv4 = ?cmd.relay.ipv4,
            relay_port = cmd.relay.port,
            "ensure: dialing relay QUIC"
        );
        match self.relay_manager.get_or_connect(descriptor, auth).await {
            Ok(_conn) => {
                info!(relay_id = %cmd.relay.relay_id, "ensure: relay QUIC session active");
                Ok(CachedCommandResult {
                    result: CommandResultCode::Active,
                    detail: None,
                })
            }
            Err(e) => {
                error!(error = %e, relay_id = %cmd.relay.relay_id, "relay connect after ensure failed");
                Ok(CachedCommandResult {
                    result: CommandResultCode::Failed,
                    detail: Some(e.to_string()),
                })
            }
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
