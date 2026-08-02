use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::billing_party::BillingPartyPair;
use crate::crypto;
use crate::errors::{ProtocolError, Result};
use crate::MAX_SIGNALING_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalingMessageType {
    RegisterTarget,
    EnsureRelayConnection,
    EnsureRelayConnectionAck,
    ResolveDomainAlias,
    ResolveDomainAliasAck,
    Drain,
    TurnProbeCandidates,
    TurnProbeReport,
    TurnProbeAck,
    TurnProbeRequest,
    WebRtcSessionOffer,
    WebRtcSessionOfferAck,
    WebRtcSessionRequest,
    WebRtcAnswer,
    WebRtcIceCandidate,
    WebRtcIceComplete,
    WebRtcSessionEnd,
    WebRtcSessionAck,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayDescriptor {
    pub relay_id: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub port: u16,
    pub server_name: String,
    pub alpn: String,
    #[serde(default)]
    pub region: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnsureRelayConnectionCommand {
    pub version: u32,
    pub message_type: SignalingMessageType,
    pub message_id: Uuid,
    pub command_id: Uuid,
    pub session_id: Uuid,
    pub target_fqhn: String,
    pub relay: RelayDescriptor,
    pub connection_token: String,
    pub connection_epoch: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub presence_generation: u64,
    /// Billing using_party (SSO/login). Echoed on Relay usage reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub using_party: Option<String>,
    /// Billing paying_party. Echoed on Relay usage reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paying_party: Option<String>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnsureRelayConnectionAck {
    pub version: u32,
    pub message_type: SignalingMessageType,
    pub message_id: Uuid,
    pub command_id: Uuid,
    pub session_id: Uuid,
    pub result: CommandResultCode,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum CommandResultCode {
    Received = 0,
    Connecting = 1,
    Active = 2,
    Failed = 3,
    Expired = 4,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetRegistration {
    pub version: u32,
    pub message_type: SignalingMessageType,
    pub target_fqhn: String,
    pub target_identity: String,
    pub connection_epoch: u64,
    pub discovery_generation: u64,
    pub role: PresenceRole,
    pub supported_transports: Vec<String>,
    /// SSO / login of the party using this Target (required).
    pub using_party: String,
    /// Optional payer login; when omitted, equals `using_party`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paying_party: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webrtc: Option<crate::webrtc_signaling::TargetWebRtcRegistration>,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceRole {
    Primary,
    Secondary,
}

impl TargetRegistration {
    pub fn billing_parties(&self) -> Result<BillingPartyPair> {
        BillingPartyPair::new(self.using_party.clone(), self.paying_party.clone())
    }

    pub fn verify(&self) -> Result<()> {
        validate_signaling_size(self)?;
        if self.message_type != SignalingMessageType::RegisterTarget {
            return Err(ProtocolError::MalformedDocument(
                "wrong message type".into(),
            ));
        }
        let _ = self.billing_parties()?;
        let target_key = crypto::KeyPair::from_base64url_public(&self.target_identity)?;
        let mut unsigned = self.clone();
        unsigned.signature = String::new();
        let value = serde_json::to_value(&unsigned)
            .map_err(|e| ProtocolError::Serialization(e.to_string()))?;
        crypto::verify_json_canonical(&value, &self.signature, &target_key)
    }
}

impl EnsureRelayConnectionCommand {
    pub fn sign(mut cmd: EnsureRelayConnectionUnsigned, key: &SigningKey) -> Result<Self> {
        cmd.signature = String::new();
        let value =
            serde_json::to_value(&cmd).map_err(|e| ProtocolError::Serialization(e.to_string()))?;
        let sig = crypto::sign_json_canonical(&value, key)?;
        Ok(Self {
            version: cmd.version,
            message_type: cmd.message_type,
            message_id: cmd.message_id,
            command_id: cmd.command_id,
            session_id: cmd.session_id,
            target_fqhn: cmd.target_fqhn,
            relay: cmd.relay,
            connection_token: cmd.connection_token,
            connection_epoch: cmd.connection_epoch,
            issued_at: cmd.issued_at,
            expires_at: cmd.expires_at,
            presence_generation: cmd.presence_generation,
            using_party: cmd.using_party,
            paying_party: cmd.paying_party,
            signature: sig,
        })
    }

    pub fn verify(&self, relay_key: &VerifyingKey) -> Result<()> {
        validate_signaling_size(self)?;
        if self.message_type != SignalingMessageType::EnsureRelayConnection {
            return Err(ProtocolError::MalformedDocument(
                "wrong message type".into(),
            ));
        }
        if Utc::now() > self.expires_at {
            return Err(ProtocolError::CommandExpired);
        }
        let unsigned = EnsureRelayConnectionUnsigned {
            version: self.version,
            message_type: self.message_type,
            message_id: self.message_id,
            command_id: self.command_id,
            session_id: self.session_id,
            target_fqhn: self.target_fqhn.clone(),
            relay: self.relay.clone(),
            connection_token: self.connection_token.clone(),
            connection_epoch: self.connection_epoch,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            presence_generation: self.presence_generation,
            using_party: self.using_party.clone(),
            paying_party: self.paying_party.clone(),
            signature: String::new(),
        };
        let value = serde_json::to_value(&unsigned)
            .map_err(|e| ProtocolError::Serialization(e.to_string()))?;
        crypto::verify_json_canonical(&value, &self.signature, relay_key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnsureRelayConnectionUnsigned {
    pub version: u32,
    pub message_type: SignalingMessageType,
    pub message_id: Uuid,
    pub command_id: Uuid,
    pub session_id: Uuid,
    pub target_fqhn: String,
    pub relay: RelayDescriptor,
    pub connection_token: String,
    pub connection_epoch: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub presence_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub using_party: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paying_party: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

/// Relay → Presence: resolve a customer CNAME (custom domain) to a Target FQHN.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolveDomainAliasRequest {
    pub version: u32,
    pub message_type: SignalingMessageType,
    pub message_id: Uuid,
    pub custom_domain: String,
}

/// Presence → Relay: alias resolution result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolveDomainAliasAck {
    pub version: u32,
    pub message_type: SignalingMessageType,
    pub message_id: Uuid,
    pub custom_domain: String,
    pub found: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_fqhn: Option<String>,
}

fn validate_signaling_size<T: Serialize>(msg: &T) -> Result<()> {
    let bytes = serde_json::to_vec(msg).map_err(|e| ProtocolError::Serialization(e.to_string()))?;
    if bytes.len() > MAX_SIGNALING_BYTES {
        return Err(ProtocolError::FrameTooLarge(bytes.len()));
    }
    Ok(())
}
