use chrono::{DateTime, TimeDelta, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use crate::crypto::{self, KeyPair};
use crate::errors::{ProtocolError, Result};

/// DNS name used for Presence TLS SNI / Host when live discovery lists only IPs.
pub const LIVE_PRESENCE_SERVER_NAME: &str = "presence.idr.to";
/// Live Presence WSS listen port (plain WS; TLS is on QUIC).
pub const LIVE_PRESENCE_WSS_PORT: u16 = 8080;
/// Default Target QUIC port when live discovery omits `quic_port`.
pub const LIVE_PRESENCE_QUIC_PORT: u16 = 4433;

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

/// Parse full agent discovery **or** live slim IP list from `public.idr.to`.
pub fn parse_discovery_document(bytes: &[u8]) -> Result<PresenceDiscoveryDocument> {
    if let Ok(doc) = serde_json::from_slice::<PresenceDiscoveryDocument>(bytes) {
        if doc.presence_servers.is_empty() {
            return Err(ProtocolError::MalformedDocument(
                "discovery has no presence servers".into(),
            ));
        }
        return Ok(doc);
    }

    let live: LiveDiscoveryDocument = serde_json::from_slice(bytes)
        .map_err(|e| ProtocolError::MalformedDocument(e.to_string()))?;
    expand_live_discovery(live)
}

#[derive(Debug, Deserialize)]
struct LiveDiscoveryDocument {
    version: u32,
    generation: u64,
    updated_at: DateTime<Utc>,
    presence_servers: Vec<LivePresenceServer>,
    #[serde(default)]
    signature: String,
}

#[derive(Debug, Deserialize)]
struct LivePresenceServer {
    ipv4: Option<String>,
    ipv6: Option<String>,
}

fn expand_live_discovery(live: LiveDiscoveryDocument) -> Result<PresenceDiscoveryDocument> {
    if live.presence_servers.is_empty() {
        return Err(ProtocolError::MalformedDocument(
            "live discovery has no presence servers".into(),
        ));
    }
    let presence_servers = live
        .presence_servers
        .into_iter()
        .enumerate()
        .map(|(idx, s)| materialize_live_server(idx, s))
        .collect::<Result<Vec<_>>>()?;

    // Live docs publish `updated_at` (no `valid_until`); keep cache usable for a year.
    let valid_until = live
        .updated_at
        .checked_add_signed(TimeDelta::days(365))
        .unwrap_or(live.updated_at);

    Ok(PresenceDiscoveryDocument {
        version: live.version,
        generation: live.generation,
        valid_until,
        presence_servers,
        signature: live.signature,
    })
}

fn materialize_live_server(idx: usize, s: LivePresenceServer) -> Result<PresenceServer> {
    let ipv4 = s.ipv4.filter(|v| !v.is_empty());
    let ipv6 = s.ipv6.filter(|v| !v.is_empty());
    if ipv4.is_none() && ipv6.is_none() {
        return Err(ProtocolError::MalformedDocument(format!(
            "live presence server[{idx}] has neither ipv4 nor ipv6"
        )));
    }

    let wss_url = if let Some(ref v4) = ipv4 {
        format!("ws://{v4}:{LIVE_PRESENCE_WSS_PORT}/v1/presence")
    } else {
        let v6 = ipv6.as_deref().unwrap();
        format!("ws://[{v6}]:{LIVE_PRESENCE_WSS_PORT}/v1/presence")
    };

    Ok(PresenceServer {
        presence_id: format!("presence-{:04}", idx + 1),
        wss_url,
        ipv4,
        ipv6,
        server_name: LIVE_PRESENCE_SERVER_NAME.into(),
        region: "live".into(),
        public_key: String::new(),
        quic_port: Some(LIVE_PRESENCE_QUIC_PORT),
        transports: vec!["quic".into(), "wss".into()],
    })
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
        let unsigned = PresenceDiscoveryUnsigned {
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

#[cfg(test)]
mod tests {
    use super::*;

    const LIVE_JSON: &str = r#"{
  "version": 1,
  "generation": 5,
  "updated_at": "2026-08-02T08:19:40Z",
  "presence_servers": [
    { "ipv4": "46.62.246.148", "ipv6": "2a01:4f9:c013:f81e::1" },
    { "ipv4": "169.58.110.93", "ipv6": "2a02:c207:2348:0439::1" }
  ],
  "signature": "M00PRzQ0FqozqWG5_fbkkJ2rPsVAn3GmNRa5MVOnio_cn7mpHPCIq5XqtXRx_CCE2apCh1sphQZIEDrSYl2xAg"
}"#;

    #[test]
    fn parses_live_slim_discovery() {
        let doc = parse_discovery_document(LIVE_JSON.as_bytes()).unwrap();
        assert_eq!(doc.generation, 5);
        assert_eq!(doc.presence_servers.len(), 2);
        assert_eq!(doc.presence_servers[0].ipv4.as_deref(), Some("46.62.246.148"));
        assert_eq!(
            doc.presence_servers[0].wss_url,
            "ws://46.62.246.148:8080/v1/presence"
        );
        assert_eq!(doc.presence_servers[0].server_name, LIVE_PRESENCE_SERVER_NAME);
        assert_eq!(doc.presence_servers[1].presence_id, "presence-0002");
    }
}
