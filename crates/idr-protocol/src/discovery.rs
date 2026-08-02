use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use crate::crypto::{self, KeyPair};
use crate::errors::{ProtocolError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresenceDiscoveryDocument {
    pub version: u32,
    pub generation: u64,
    pub valid_until: DateTime<Utc>,
    pub presence_servers: Vec<PresenceServer>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresenceServer {
    pub presence_id: String,
    pub wss_url: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub server_name: String,
    pub region: String,
    pub public_key: String,
    #[serde(default)]
    pub quic_port: Option<u16>,
    #[serde(default = "default_transports")]
    pub transports: Vec<String>,
}

fn default_transports() -> Vec<String> {
    vec!["quic".into(), "wss".into()]
}

impl PresenceServer {
    pub fn supports_quic(&self) -> bool {
        self.transports.iter().any(|t| t == "quic")
    }

    pub fn supports_wss(&self) -> bool {
        self.transports.iter().any(|t| t == "wss")
    }

    pub fn quic_port(&self) -> u16 {
        self.quic_port.unwrap_or(4433)
    }

    pub fn parse_quic_endpoints(&self) -> (Option<SocketAddr>, Option<SocketAddr>) {
        let port = self.quic_port();
        let v4 = self
            .ipv4
            .as_ref()
            .and_then(|ip| parse_socket(ip, port, false));
        let v6 = self
            .ipv6
            .as_ref()
            .and_then(|ip| parse_socket(ip, port, true));
        (v4, v6)
    }

    /// IPv6 endpoint for the Relay mTLS control plane (separate UDP port from Target QUIC).
    pub fn parse_relay_quic_endpoint(&self, relay_quic_port: u16) -> Option<SocketAddr> {
        self.ipv6
            .as_ref()
            .and_then(|ip| parse_socket(ip, relay_quic_port, true))
    }
}

/// Extract relay node index from the lower 64 bits of a control-plane source IPv6 address.
///
/// Convention: `2001:db8:idr:relay::N` → index `N`. Used for logging and O(1) slot assignment
/// after mTLS has authenticated the peer.
pub fn relay_node_index_from_ipv6(addr: Ipv6Addr) -> Option<u32> {
    let iface = u128::from_be_bytes(addr.octets()) & 0xffff_ffff_ffff_ffff;
    u32::try_from(iface).ok()
}

fn parse_socket(ip: &str, port: u16, v6: bool) -> Option<SocketAddr> {
    if v6 {
        Ipv6Addr::from_str(ip)
            .ok()
            .map(|a| SocketAddr::new(IpAddr::V6(a), port))
    } else {
        Ipv4Addr::from_str(ip)
            .ok()
            .map(|a| SocketAddr::new(IpAddr::V4(a), port))
    }
}

impl PresenceDiscoveryDocument {
    pub fn sign(mut doc: PresenceDiscoveryUnsigned, key: &KeyPair) -> Result<Self> {
        doc.signature = String::new();
        let value =
            serde_json::to_value(&doc).map_err(|e| ProtocolError::Serialization(e.to_string()))?;
        let sig = crypto::sign_json_canonical(&value, &key.signing_key)?;
        Ok(PresenceDiscoveryDocument {
            version: doc.version,
            generation: doc.generation,
            valid_until: doc.valid_until,
            presence_servers: doc.presence_servers,
            signature: sig,
        })
    }

    pub fn verify(&self, discovery_key: &VerifyingKey) -> Result<()> {
        if self.version != crate::PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        if self.signature.is_empty() {
            return Err(ProtocolError::InvalidSignature);
        }
        let mut unsigned = PresenceDiscoveryUnsigned {
            version: self.version,
            generation: self.generation,
            valid_until: self.valid_until,
            presence_servers: self.presence_servers.clone(),
            signature: String::new(),
        };
        let value = serde_json::to_value(&unsigned)
            .map_err(|e| ProtocolError::Serialization(e.to_string()))?;
        crypto::verify_json_canonical(&value, &self.signature, discovery_key)?;
        if Utc::now() > self.valid_until {
            return Err(ProtocolError::DocumentExpired);
        }
        if self.presence_servers.is_empty() {
            return Err(ProtocolError::MalformedDocument(
                "no presence servers".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresenceDiscoveryUnsigned {
    pub version: u32,
    pub generation: u64,
    pub valid_until: DateTime<Utc>,
    pub presence_servers: Vec<PresenceServer>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
}
