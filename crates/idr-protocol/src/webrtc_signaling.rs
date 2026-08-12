//! WebRTC signaling messages and target registration extensions.

use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto;
use crate::errors::{ProtocolError, Result};
use crate::signaling::{PresenceRole, SignalingMessageType};
use crate::stream_mux;
use crate::webrtc_ice::{self, SessionIceConfig, TurnProbeSnapshot};
use crate::{MAX_SIGNALING_BYTES, MAX_WEBRTC_SIGNALING_BYTES, PROTOCOL_VERSION};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetWebRtcRegistration {
    pub agent_region: String,
    pub relay_mode: webrtc_ice::IceRelayMode,
    pub stun_policy: webrtc_ice::StunPolicy,
    pub capabilities: TargetWebRtcCapabilities,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byor: Option<BringYourOwnRelay>,
    #[serde(default = "default_true")]
    pub turn_probe_supported: bool,
    /// Target's preferred ICE transport. `relay` means P2P is not allowed.
    #[serde(default)]
    pub ice_transport_policy: crate::webrtc_ice::IceTransportPolicy,
}

/// Presence → Target after successful `register_target`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterTargetAck {
    pub version: u32,
    pub message_type: SignalingMessageType,
    pub message_id: Uuid,
    pub target_fqhn: String,
    pub role: PresenceRole,
    /// Platform TURN mint currently allowed for this Target's paying party.
    pub turn_mint_allowed: bool,
    /// `full` when TURN available; `p2p_only` when Data Transfer exhausted.
    pub webrtc_fallback: String,
    /// Whether this Target's registration allows host/srflx (P2P) candidates.
    pub target_allows_p2p: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetWebRtcCapabilities {
    pub data_channel_label: String,
    pub data_channel_protocol: String,
    pub max_concurrent_sessions: u32,
    pub supported_stream_kinds: Vec<String>,
    /// Mux feature tokens (e.g. `flow_control_v1`). Empty = legacy mux only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mux_features: Vec<String>,
    /// Named Target services advertised to Source (catalog), e.g. `http`, `ollama`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub named_services: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BringYourOwnRelay {
    pub tenant_id: String,
    #[serde(default)]
    pub stun_servers: Vec<ByorIceServer>,
    pub turn_servers: Vec<ByorIceServer>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ByorIceServer {
    pub urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceAuthMode {
    /// Mutual TLS device identity (future).
    Mtls,
    /// better-auth / api session bearer.
    Bearer,
    /// Long-lived device token issued by api.
    DeviceToken,
    /// Forbidden on product paths; Presence denies when billing is required.
    Anonymous,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceAgentIdentity {
    pub auth_mode: SourceAuthMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdk_version: Option<String>,
    /// Session or device bearer presented to Presence / api entitlement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionDescription {
    pub sdp_type: String,
    pub sdp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebRtcSessionOffer {
    pub version: u32,
    pub message_type: SignalingMessageType,
    pub message_id: Uuid,
    pub session_id: Uuid,
    pub target_fqhn: String,
    pub source: SourceAgentIdentity,
    pub sdp: SessionDescription,
    pub ice: SessionIceConfig,
    pub session_token: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub presence_generation: u64,
    pub signature: String,
}

impl WebRtcSessionOffer {
    /// Verify Presence Ed25519 signature over the canonical unsigned offer body.
    /// Must match Presence `WebRtcSessionOffer` signing (signature field empty in payload).
    pub fn verify_presence_signature(&self, key: &VerifyingKey) -> Result<()> {
        #[derive(Serialize)]
        struct WebRtcSessionOfferUnsigned<'a> {
            version: u32,
            message_type: SignalingMessageType,
            message_id: Uuid,
            session_id: Uuid,
            target_fqhn: &'a str,
            source: &'a SourceAgentIdentity,
            sdp: &'a SessionDescription,
            ice: &'a SessionIceConfig,
            session_token: &'a str,
            issued_at: DateTime<Utc>,
            expires_at: DateTime<Utc>,
            presence_generation: u64,
            #[serde(default, skip_serializing_if = "str::is_empty")]
            signature: &'a str,
        }
        let unsigned = WebRtcSessionOfferUnsigned {
            version: self.version,
            message_type: self.message_type,
            message_id: self.message_id,
            session_id: self.session_id,
            target_fqhn: &self.target_fqhn,
            source: &self.source,
            sdp: &self.sdp,
            ice: &self.ice,
            session_token: &self.session_token,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            presence_generation: self.presence_generation,
            signature: "",
        };
        let value = serde_json::to_value(&unsigned)
            .map_err(|e| ProtocolError::Serialization(e.to_string()))?;
        crypto::verify_json_canonical(&value, &self.signature, key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebRtcSessionOfferAck {
    pub version: u32,
    pub message_type: SignalingMessageType,
    pub message_id: Uuid,
    pub session_id: Uuid,
    pub result: WebRtcSessionResultCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum WebRtcSessionResultCode {
    Received = 0,
    Negotiating = 1,
    Active = 2,
    Failed = 3,
    Expired = 4,
    Busy = 5,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebRtcAnswer {
    pub version: u32,
    pub message_type: SignalingMessageType,
    pub message_id: Uuid,
    pub session_id: Uuid,
    pub sdp: SessionDescription,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebRtcIceCandidate {
    pub version: u32,
    pub message_type: SignalingMessageType,
    pub message_id: Uuid,
    pub session_id: Uuid,
    pub candidate: String,
    pub mid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebRtcIceComplete {
    pub version: u32,
    pub message_type: SignalingMessageType,
    pub message_id: Uuid,
    pub session_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebRtcSessionEnd {
    pub version: u32,
    pub message_type: SignalingMessageType,
    pub message_id: Uuid,
    pub session_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebRtcSessionAck {
    pub version: u32,
    pub message_type: SignalingMessageType,
    pub message_id: Uuid,
    pub session_id: Uuid,
    pub result: WebRtcSessionResultCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebRtcSessionRequest {
    pub version: u32,
    pub message_type: SignalingMessageType,
    pub message_id: Uuid,
    pub session_id: Uuid,
    pub target_fqhn: String,
    pub source: SourceAgentIdentity,
    pub source_region: String,
    pub sdp: SessionDescription,
    /// Source preferred ICE transport. `relay` means P2P is not acceptable.
    #[serde(default)]
    pub ice_transport_policy: crate::webrtc_ice::IceTransportPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProbeMethod {
    #[default]
    StunBinding,
    UdpReachability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TurnProbeCandidate {
    pub turn_node_id: String,
    pub region: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
    pub port: u16,
    #[serde(default)]
    pub probe_method: ProbeMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TurnProbeCandidates {
    pub version: u32,
    pub message_type: SignalingMessageType,
    pub message_id: Uuid,
    pub probe_generation: u64,
    pub issued_at: DateTime<Utc>,
    pub candidates: Vec<TurnProbeCandidate>,
    pub signature: String,
}

impl TurnProbeCandidates {
    pub fn verify(&self, presence_key: &VerifyingKey) -> Result<()> {
        if self.candidates.len() > 32 {
            return Err(ProtocolError::MalformedDocument(
                "too many probe candidates".into(),
            ));
        }
        let unsigned = TurnProbeCandidatesUnsigned {
            version: self.version,
            message_type: self.message_type,
            message_id: self.message_id,
            probe_generation: self.probe_generation,
            issued_at: self.issued_at,
            candidates: self.candidates.clone(),
            signature: String::new(),
        };
        let value = serde_json::to_value(&unsigned)
            .map_err(|e| ProtocolError::Serialization(e.to_string()))?;
        crypto::verify_json_canonical(&value, &self.signature, presence_key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TurnProbeCandidatesUnsigned {
    version: u32,
    message_type: SignalingMessageType,
    message_id: Uuid,
    probe_generation: u64,
    issued_at: DateTime<Utc>,
    candidates: Vec<TurnProbeCandidate>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TurnProbeResult {
    pub turn_node_id: String,
    pub latency_ms: u32,
    pub reachable: bool,
    pub address_family: AddressFamily,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TurnProbeReport {
    pub version: u32,
    pub message_type: SignalingMessageType,
    pub message_id: Uuid,
    pub probe_generation: u64,
    pub target_fqhn: String,
    pub role: PresenceRole,
    pub agent_region: String,
    pub results: Vec<TurnProbeResult>,
    pub probed_at: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TurnProbeAck {
    pub version: u32,
    pub message_type: SignalingMessageType,
    pub message_id: Uuid,
    pub probe_generation: u64,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TurnProbeRequest {
    pub version: u32,
    pub message_type: SignalingMessageType,
    pub message_id: Uuid,
    pub target_fqhn: String,
    pub role: PresenceRole,
    pub reason: String,
    pub signature: String,
}

impl WebRtcAnswer {
    pub fn sign(mut answer: WebRtcAnswerUnsigned, key: &SigningKey) -> Result<Self> {
        answer.signature = String::new();
        let value = serde_json::to_value(&answer)
            .map_err(|e| ProtocolError::Serialization(e.to_string()))?;
        let sig = crypto::sign_json_canonical(&value, key)?;
        Ok(Self {
            version: answer.version,
            message_type: answer.message_type,
            message_id: answer.message_id,
            session_id: answer.session_id,
            sdp: answer.sdp,
            signature: sig,
        })
    }

    pub fn verify(&self, target_key: &VerifyingKey) -> Result<()> {
        validate_webrtc_signaling_size(self)?;
        let unsigned = WebRtcAnswerUnsigned {
            version: self.version,
            message_type: self.message_type,
            message_id: self.message_id,
            session_id: self.session_id,
            sdp: self.sdp.clone(),
            signature: String::new(),
        };
        let value = serde_json::to_value(&unsigned)
            .map_err(|e| ProtocolError::Serialization(e.to_string()))?;
        crypto::verify_json_canonical(&value, &self.signature, target_key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebRtcAnswerUnsigned {
    pub version: u32,
    pub message_type: SignalingMessageType,
    pub message_id: Uuid,
    pub session_id: Uuid,
    pub sdp: SessionDescription,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

impl TurnProbeReport {
    pub fn sign(mut report: TurnProbeReportUnsigned, key: &SigningKey) -> Result<Self> {
        report.signature = String::new();
        let value = serde_json::to_value(&report)
            .map_err(|e| ProtocolError::Serialization(e.to_string()))?;
        let sig = crypto::sign_json_canonical(&value, key)?;
        Ok(Self {
            version: report.version,
            message_type: report.message_type,
            message_id: report.message_id,
            probe_generation: report.probe_generation,
            target_fqhn: report.target_fqhn,
            role: report.role,
            agent_region: report.agent_region,
            results: report.results,
            probed_at: report.probed_at,
            signature: sig,
        })
    }

    pub fn verify(&self, target_key: &VerifyingKey) -> Result<()> {
        validate_signaling_size(self)?;
        let unsigned = TurnProbeReportUnsigned {
            version: self.version,
            message_type: self.message_type,
            message_id: self.message_id,
            probe_generation: self.probe_generation,
            target_fqhn: self.target_fqhn.clone(),
            role: self.role,
            agent_region: self.agent_region.clone(),
            results: self.results.clone(),
            probed_at: self.probed_at,
            signature: String::new(),
        };
        let value = serde_json::to_value(&unsigned)
            .map_err(|e| ProtocolError::Serialization(e.to_string()))?;
        crypto::verify_json_canonical(&value, &self.signature, target_key)
    }

    pub fn to_snapshot(&self) -> TurnProbeSnapshot {
        let mut ordered_node_ids = Vec::new();
        let mut latencies_ms = std::collections::HashMap::new();
        for result in &self.results {
            if result.reachable {
                ordered_node_ids.push(result.turn_node_id.clone());
                latencies_ms.insert(result.turn_node_id.clone(), result.latency_ms);
            }
        }
        TurnProbeSnapshot {
            probe_generation: self.probe_generation,
            probed_at: self.probed_at,
            ordered_node_ids,
            latencies_ms,
            source_probes: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TurnProbeReportUnsigned {
    pub version: u32,
    pub message_type: SignalingMessageType,
    pub message_id: Uuid,
    pub probe_generation: u64,
    pub target_fqhn: String,
    pub role: PresenceRole,
    pub agent_region: String,
    pub results: Vec<TurnProbeResult>,
    pub probed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

impl TurnProbeRequest {
    pub fn sign(mut req: TurnProbeRequestUnsigned, key: &SigningKey) -> Result<Self> {
        req.signature = String::new();
        let value = serde_json::to_value(&req)
            .map_err(|e| ProtocolError::Serialization(e.to_string()))?;
        let sig = crypto::sign_json_canonical(&value, key)?;
        Ok(Self {
            version: req.version,
            message_type: req.message_type,
            message_id: req.message_id,
            target_fqhn: req.target_fqhn,
            role: req.role,
            reason: req.reason,
            signature: sig,
        })
    }

    pub fn verify(&self, target_key: &VerifyingKey) -> Result<()> {
        validate_signaling_size(self)?;
        let unsigned = TurnProbeRequestUnsigned {
            version: self.version,
            message_type: self.message_type,
            message_id: self.message_id,
            target_fqhn: self.target_fqhn.clone(),
            role: self.role,
            reason: self.reason.clone(),
            signature: String::new(),
        };
        let value = serde_json::to_value(&unsigned)
            .map_err(|e| ProtocolError::Serialization(e.to_string()))?;
        crypto::verify_json_canonical(&value, &self.signature, target_key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TurnProbeRequestUnsigned {
    pub version: u32,
    pub message_type: SignalingMessageType,
    pub message_id: Uuid,
    pub target_fqhn: String,
    pub role: PresenceRole,
    pub reason: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

fn validate_signaling_size<T: Serialize>(msg: &T) -> Result<()> {
    let bytes = serde_json::to_vec(msg).map_err(|e| ProtocolError::Serialization(e.to_string()))?;
    if bytes.len() > MAX_SIGNALING_BYTES {
        return Err(ProtocolError::FrameTooLarge(bytes.len()));
    }
    Ok(())
}

fn validate_webrtc_signaling_size<T: Serialize>(msg: &T) -> Result<()> {
    let bytes = serde_json::to_vec(msg).map_err(|e| ProtocolError::Serialization(e.to_string()))?;
    if bytes.len() > MAX_WEBRTC_SIGNALING_BYTES {
        return Err(ProtocolError::FrameTooLarge(bytes.len()));
    }
    Ok(())
}

pub fn default_webrtc_capabilities(max_sessions: u32) -> TargetWebRtcCapabilities {
    TargetWebRtcCapabilities {
        data_channel_label: webrtc_ice::WEBRTC_DC_LABEL.into(),
        data_channel_protocol: webrtc_ice::WEBRTC_DC_PROTOCOL.into(),
        max_concurrent_sessions: max_sessions,
        supported_stream_kinds: vec![
            "tls_passthrough".into(),
            "http_passthrough".into(),
            "tcp_connect".into(),
        ],
        mux_features: stream_mux::MuxProfile::FlowControlV1.advertised_features(),
        named_services: Vec::new(),
    }
}
