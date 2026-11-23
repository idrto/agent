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
use crate::presence::registration::{build_registration, build_unregistration};
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
    transfers: Option<Arc<crate::webrtc::local::TransferEndpoint>>,
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
            transfers: None,
        }
    }

    /// Enable peer binding and file transfer on WebRTC sessions.
    pub fn with_transfers(mut self, transfers: Option<Arc<crate::webrtc::local::TransferEndpoint>>) -> Self {
        self.transfers = transfers;
        self
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
                        warn!(event = "presence.network_change_turn_reprobe_request_failed", error.message = %e);
                    }
                }
            }
            let network = PresenceNetworkCaps::from_detect(&caps);
            match self.connect_with_fallback(role_label, &network).await {
                Ok(true) => {
                    // Presence drops a closed connection's registration about 1s later,
                    // keyed by identity only: wait that out so it can't drop the new one.
                    backoff = self.cfg.reconnect_initial();
                    sleep(Duration::from_secs(2)).await;
                    continue;
                }
                Ok(false) => {
                    if self.shutdown.is_draining() {
                        break;
                    }
                }
                Err(err) => {
                    warn!(event = "presence.presence_session_error", role = role_label, error.message = %err);
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

    /// `Ok(true)`: the entitlement JWT was rotated and the connection closed to
    /// re-register with it.
    async fn connect_with_fallback(
        &self,
        role_label: &'static str,
        network: &PresenceNetworkCaps,
    ) -> Result<bool> {
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
        let jwt = reg.entitlement_jwt.as_deref();

        let mut last_err = None;
        for (i, choice) in attempts.into_iter().enumerate() {
            if i > 0 {
                sleep(self.cfg.transport_fallback_delay()).await;
            }
            let label = transport_label(choice);
            debug!(event = "presence.attempting_presence_connect", transport = label, role = role_label);
            let result = match choice {
                PresenceTransportChoice::Quic(addr) => {
                    self.connect_quic_and_serve(role_label, addr, &reg_json, jwt)
                        .await
                }
                PresenceTransportChoice::Wss => {
                    self.connect_wss_and_serve(role_label, &reg_json, jwt).await
                }
            };
            match result {
                Ok(rotated) => return Ok(rotated),
                Err(e) => {
                    warn!(event = "presence.presence_transport_failed", transport = label, error.message = %e);
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
        jwt: Option<&str>,
    ) -> Result<bool> {
        let connection = self
            .quic_client
            .connect_persistent(&self.server, addr, reg_json, self.cfg.connect_timeout())
            .await?;
        self.metrics
            .presence_connected
            .with_label_values(&[role_label])
            .set(1);
        info!(event = "presence.presence_connected", role = role_label, presence_id = %self.server.presence_id, transport = "quic");
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
                                    error!(event = "presence.quic_push_read_failed", error.message = %e);
                                }
                            });
                        }
                        Err(e) => {
                            debug!(event = "presence.presence_quic_accept_uni_ended", error.message = ?e);
                            break;
                        }
                    }
                }
                reason = connection.closed() => {
                    debug!(event = "presence.presence_quic_closed", reason = ?reason);
                    break;
                }
                _ = self.entitlement_rotated(jwt) => {
                    connection.close(0u32.into(), b"entitlement rotated");
                    return Ok(true);
                }
                _ = shutdown.wait_for_drain() => {
                    self.send_unregister_if_connected().await;
                    break;
                }
            }
        }
        Ok(false)
    }

    /// Resolves once the entitlement JWT on disk differs from the registered one.
    /// The app re-mints short-lived JWTs into that file; Presence keeps the claims
    /// from registration, so the connection must re-register (WebRTC sessions stay up).
    async fn entitlement_rotated(&self, registered: Option<&str>) {
        loop {
            sleep(Duration::from_secs(10)).await;
            if let Ok(current) = self.reg_cfg.resolve_entitlement_jwt() {
                if current.as_deref() != registered {
                    info!(event = "presence.entitlement_jwt_rotated_re_registering_with");
                    return;
                }
            }
        }
    }

    async fn connect_wss_and_serve(
        &self,
        role_label: &'static str,
        reg_json: &str,
        jwt: Option<&str>,
    ) -> Result<bool> {
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
        info!(event = "presence.presence_connected", role = role_label, presence_id = %self.server.presence_id, transport = "wss");
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
                                error!(event = "presence.handle_presence_message_failed", error.message = %e);
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => break,
                        Some(Err(e)) => return Err(e.into()),
                        _ => {}
                    }
                }
                _ = self.entitlement_rotated(jwt) => {
                    // Last sender gone: the writer task ends and the socket closes now.
                    *self.signaling_outbox.lock().await = None;
                    return Ok(true);
                }
                _ = self.shutdown.wait_for_drain() => {
                    self.send_unregister_if_connected().await;
                    break;
                }
            }
        }
        Ok(false)
    }

    async fn send_unregister_if_connected(&self) {
        let Some(outbox) = self.signaling_outbox.lock().await.clone() else {
            return;
        };
        if !outbox.is_connected() {
            debug!(event = "presence.skip_unregister_target_presence_connection_already");
            return;
        }
        let msg = match build_unregistration(
            &self.identity,
            &self.fqhn,
            self.connection_epoch,
            self.role,
        ) {
            Ok(m) => m,
            Err(e) => {
                warn!(event = "presence.build_unregister_target_failed", error.message = %e);
                return;
            }
        };
        let json = match serde_json::to_string(&msg) {
            Ok(j) => j,
            Err(e) => {
                warn!(event = "presence.serialize_unregister_target_failed", error.message = %e);
                return;
            }
        };
        match outbox.send_json(&json).await {
            Ok(()) => info!(event = "presence.sent_unregister_target", fqhn = %self.fqhn),
            Err(e) => debug!(event = "presence.skip_unregister_target_presence_not_writable", error.message = %e),
        }
        outbox.close();
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
                self.presence_push_verify_key(),
                self.webrtc_sessions.clone(),
                self.reg_cfg.nginx.clone(),
                self.reg_cfg.webrtc.policy.clone(),
                self.connectors.clone(),
                self.reg_cfg.presence.insecure_dev,
            )
            .with_transfers(self.transfers.clone()))
        } else {
            None
        };
        PresenceClientTask {
            relay_verify_key: self.presence_push_verify_key(),
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

    /// Key Presence uses after re-signing ensure pushes: this node's discovery `public_key`.
    fn presence_push_verify_key(&self) -> VerifyingKey {
        if !self.server.public_key.is_empty() {
            if let Ok(key) =
                idr_protocol::crypto::KeyPair::from_base64url_public(&self.server.public_key)
            {
                return key;
            }
        }
        self.relay_verify_key
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
        info!(event = "presence.presence_quic_push_received", bytes = json_bytes.len());
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

        info!(event = "presence.received_ensure_relay_connection", target_fqhn = %cmd.target_fqhn, command_id = %cmd.command_id, relay_id = %cmd.relay.relay_id, relay_ipv4 = ?cmd.relay.ipv4, relay_port = cmd.relay.port, server_name = %cmd.relay.server_name);

        cmd.verify(&self.relay_verify_key).or_else(|e| {
            if self.reg_cfg.presence.insecure_dev {
                warn!(event = "presence.insecure_dev_accepting_ensure_command_despite", error.message = %e);
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
                info!(event = "presence.ensure_ignored_duplicate_cached", command_id = %command_id);
                self.metrics.signaling_duplicates_total.inc();
                self.metrics.inc_signaling_result("duplicate");
            }
            DedupAction::Wait(in_flight) => {
                info!(event = "presence.ensure_waiting_on_in_flight_connect", command_id = %command_id);
                self.metrics.signaling_duplicates_total.inc();
                let _ = in_flight.wait().await;
            }
            DedupAction::Process(_in_flight) => {
                self.metrics.inc_signaling_result("received");
                let result = self.process_command(cmd).await;
                match result {
                    Ok(r) => {
                        info!(event = "presence.ensure_connect_finished", command_id = %command_id, result = ?r.result, detail = ?r.detail);
                        self.dedup.complete(command_id, digest, r.clone()).await;
                        self.metrics.inc_signaling_result(result_label(r.result));
                    }
                    Err(e) => {
                        error!(event = "presence.ensure_processing_failed", command_id = %command_id, error.message = %e);
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
                        warn!(event = "presence.turn_probe_candidates_signature_rejected", error.message = %e);
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
                                error!(event = "presence.webrtc_offer_handling_failed", error.message = %e);
                            }
                        });
                    }
                    (None, _) => {
                        warn!(event = "presence.webrtc_session_offer_received_but_webrtc");
                    }
                    (Some(_), Err(e)) => {
                        warn!(event = "presence.failed_to_parse_webrtc_session_offer", error.message = %e);
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
                debug!(event = "presence.received_turn_probe_ack");
            }
            "register_target_ack" => {
                match serde_json::from_str::<RegisterTargetAck>(text) {
                    Ok(ack) => {
                        if ack.turn_mint_allowed {
                            info!(event = "presence.register_target_ack_platform_turn_available", target_fqhn = %ack.target_fqhn, fallback = %ack.webrtc_fallback);
                        } else if ack.target_allows_p2p {
                            warn!(event = "presence.register_target_ack_no_turn_mint", target_fqhn = %ack.target_fqhn, fallback = %ack.webrtc_fallback, reason = ack.reason.as_deref().unwrap_or("data_transfer_exhausted"));
                        } else {
                            warn!(event = "presence.register_target_ack_turn_unavailable_and", target_fqhn = %ack.target_fqhn, reason = ack.reason.as_deref().unwrap_or("payment_required"));
                        }
                    }
                    Err(e) => warn!(event = "presence.invalid_register_target_ack", error.message = %e),
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
            session_id: cmd.connection_id,
            target_fqhn: cmd.target_fqhn.clone(),
            target_identity: self.identity.public_key_base64url(),
            connection_token: cmd.connection_token,
            connection_epoch: cmd.connection_epoch,
            command_id: cmd.command_id,
            expires_at: Some(cmd.expires_at),
        };

        info!(event = "presence.ensure_dialing_relay_quic", relay_id = %cmd.relay.relay_id, relay_ipv4 = ?cmd.relay.ipv4, relay_port = cmd.relay.port);
        match self.relay_manager.get_or_connect(descriptor, auth).await {
            Ok(_conn) => {
                info!(event = "presence.ensure_relay_quic_session_active", relay_id = %cmd.relay.relay_id);
                Ok(CachedCommandResult {
                    result: CommandResultCode::Active,
                    detail: None,
                })
            }
            Err(e) => {
                error!(event = "presence.relay_connect_after_ensure_failed", error.message = %e, relay_id = %cmd.relay.relay_id);
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
