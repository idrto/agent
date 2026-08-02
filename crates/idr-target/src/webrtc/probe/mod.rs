mod stun_binding;

use std::time::Duration;

use chrono::Utc;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::config::WebRtcConfig;
use crate::identity::TargetIdentity;
use crate::presence::outbox::PresenceSignalingOutbox;
use idr_protocol::signaling::{PresenceRole, SignalingMessageType};
use idr_protocol::webrtc_signaling::{
    AddressFamily, ProbeMethod, TurnProbeCandidates, TurnProbeReport, TurnProbeReportUnsigned,
    TurnProbeResult,
};
use idr_protocol::PROTOCOL_VERSION;

pub struct ProbeScheduler {
    cfg: WebRtcConfig,
    fqhn: String,
    role: PresenceRole,
    agent_region: String,
    identity: TargetIdentity,
    last_generation: std::sync::atomic::AtomicU64,
}

impl Clone for ProbeScheduler {
    fn clone(&self) -> Self {
        Self {
            cfg: self.cfg.clone(),
            fqhn: self.fqhn.clone(),
            role: self.role,
            agent_region: self.agent_region.clone(),
            identity: self.identity.clone(),
            last_generation: std::sync::atomic::AtomicU64::new(
                self.last_generation
                    .load(std::sync::atomic::Ordering::Relaxed),
            ),
        }
    }
}

impl ProbeScheduler {
    pub fn new(
        cfg: WebRtcConfig,
        fqhn: String,
        role: PresenceRole,
        agent_region: String,
        identity: TargetIdentity,
    ) -> Self {
        Self {
            cfg,
            fqhn,
            role,
            agent_region,
            identity,
            last_generation: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub async fn handle_candidates(
        &self,
        msg: TurnProbeCandidates,
        outbox: &PresenceSignalingOutbox,
    ) -> anyhow::Result<()> {
        if !self.cfg.turn_probe_enabled {
            return Ok(());
        }
        let prev = self
            .last_generation
            .load(std::sync::atomic::Ordering::SeqCst);
        if msg.probe_generation <= prev {
            debug!(
                generation = msg.probe_generation,
                "skipping stale probe generation"
            );
            return Ok(());
        }
        self.last_generation
            .store(msg.probe_generation, std::sync::atomic::Ordering::SeqCst);

        let timeout = Duration::from_secs(2);
        let mut results = Vec::new();
        for candidate in msg.candidates {
            if candidate.probe_method != ProbeMethod::StunBinding {
                continue;
            }
            if let Some(v6) = candidate.ipv6.as_deref() {
                if let Ok(addr) = format!("[{v6}]:{}", candidate.port).parse() {
                    if let Some(latency_ms) =
                        stun_binding::measure_stun_binding_rtt(addr, 3, timeout).await
                    {
                        results.push(TurnProbeResult {
                            turn_node_id: candidate.turn_node_id.clone(),
                            latency_ms,
                            reachable: true,
                            address_family: AddressFamily::Ipv6,
                            error: None,
                        });
                        continue;
                    }
                }
            }
            if let Some(v4) = candidate.ipv4.as_deref() {
                if let Ok(addr) = format!("{v4}:{}", candidate.port).parse() {
                    match stun_binding::measure_stun_binding_rtt(addr, 3, timeout).await {
                        Some(latency_ms) => results.push(TurnProbeResult {
                            turn_node_id: candidate.turn_node_id,
                            latency_ms,
                            reachable: true,
                            address_family: AddressFamily::Ipv4,
                            error: None,
                        }),
                        None => results.push(TurnProbeResult {
                            turn_node_id: candidate.turn_node_id,
                            latency_ms: u32::MAX,
                            reachable: false,
                            address_family: AddressFamily::Ipv4,
                            error: Some("timeout".into()),
                        }),
                    }
                }
            }
        }

        results.sort_by_key(|r| if r.reachable { r.latency_ms } else { u32::MAX });
        let unsigned = TurnProbeReportUnsigned {
            version: PROTOCOL_VERSION,
            message_type: SignalingMessageType::TurnProbeReport,
            message_id: Uuid::new_v4(),
            probe_generation: msg.probe_generation,
            target_fqhn: self.fqhn.clone(),
            role: self.role,
            agent_region: self.agent_region.clone(),
            results,
            probed_at: Utc::now(),
            signature: String::new(),
        };
        let report = TurnProbeReport::sign(unsigned, self.identity.signing_key())?;
        let json = serde_json::to_string(&report)?;
        outbox.send_json(&json).await?;
        debug!(generation = msg.probe_generation, "sent turn probe report");
        Ok(())
    }

    pub fn should_request_reprobe(&self) -> bool {
        self.cfg.turn_probe_enabled
    }
}

pub async fn send_probe_request(
    outbox: &PresenceSignalingOutbox,
    identity: &TargetIdentity,
    fqhn: &str,
    role: PresenceRole,
    reason: &str,
) -> anyhow::Result<()> {
    use idr_protocol::webrtc_signaling::{TurnProbeRequest, TurnProbeRequestUnsigned};
    let unsigned = TurnProbeRequestUnsigned {
        version: PROTOCOL_VERSION,
        message_type: SignalingMessageType::TurnProbeRequest,
        message_id: Uuid::new_v4(),
        target_fqhn: fqhn.to_string(),
        role,
        reason: reason.to_string(),
        signature: String::new(),
    };
    let req = TurnProbeRequest::sign(unsigned, identity.signing_key())?;
    outbox.send_json(&serde_json::to_string(&req)?).await?;
    Ok(())
}

pub fn spawn_probe_on_push(
    scheduler: ProbeScheduler,
    outbox: PresenceSignalingOutbox,
    msg: TurnProbeCandidates,
) {
    tokio::spawn(async move {
        if let Err(e) = scheduler.handle_candidates(msg, &outbox).await {
            warn!(error = %e, "TURN probe failed");
        }
    });
}
