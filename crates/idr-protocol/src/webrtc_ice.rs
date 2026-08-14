//! ICE server configuration, STUN policy, and rtc ice_servers merge rules.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::errors::{ProtocolError, Result};
use crate::webrtc_signaling::BringYourOwnRelay;

pub const STUN_GOOGLE: &str = "stun:stun.l.google.com:19302";
pub const STUN_IDR: &str = "stun:stun.idr.to:3478";
pub const WEBRTC_DC_LABEL: &str = "idr-stream-v1";
pub const WEBRTC_DC_PROTOCOL: &str = "idr.stream/1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum StunPolicy {
    #[default]
    GoogleAndIdr,
    IdrOnly,
    GoogleOnly,
    Explicit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum IceRelayMode {
    #[default]
    Platform,
    Byor,
    Hybrid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum IceTransportPolicy {
    #[default]
    All,
    Relay,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IceServer {
    pub urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TurnAllocation {
    pub turn_node_id: String,
    pub region: String,
    pub servers: Vec<IceServer>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionIceConfig {
    pub relay_mode: IceRelayMode,
    pub stun_policy: StunPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stun_servers: Option<Vec<IceServer>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn: Option<TurnAllocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byor: Option<BringYourOwnRelay>,
    #[serde(default)]
    pub ice_transport_policy: IceTransportPolicy,
    /// When true, platform TURN is omitted (STUN / P2P only) — e.g. Data Transfer exhausted.
    #[serde(default)]
    pub p2p_only: bool,
}

impl SessionIceConfig {
    /// True when platform or BYOR TURN entries include username and credential.
    /// Does not return or format secret values.
    pub fn has_turn_credentials(&self) -> bool {
        let platform = self.turn.as_ref().is_some_and(|t| {
            t.servers.iter().any(|s| {
                s.username.as_deref().is_some_and(|u| !u.is_empty())
                    && s.credential.as_deref().is_some_and(|c| !c.is_empty())
            })
        });
        let byor = self.byor.as_ref().is_some_and(|b| {
            b.turn_servers.iter().any(|s| {
                s.username.as_deref().is_some_and(|u| !u.is_empty())
                    && s.credential.as_deref().is_some_and(|c| !c.is_empty())
            })
        });
        platform || byor
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IceBuildError {
    MissingTurn,
    MissingExplicitStun,
    IncompleteTurnCredentials,
    TurnEntryLooksLikeStun,
    EmptyByorTurn,
}

impl std::fmt::Display for IceBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingTurn => write!(f, "platform TURN missing from session ice config"),
            Self::MissingExplicitStun => write!(f, "explicit STUN policy requires stun_servers"),
            Self::IncompleteTurnCredentials => write!(f, "TURN entry missing username or credential"),
            Self::TurnEntryLooksLikeStun => write!(f, "TURN entry contains stun: URL"),
            Self::EmptyByorTurn => write!(f, "BYOR mode requires turn_servers"),
        }
    }
}

impl std::error::Error for IceBuildError {}

pub fn default_stun_for_policy(policy: StunPolicy) -> Vec<IceServer> {
    match policy {
        StunPolicy::GoogleAndIdr => vec![
            ice_server_stun(STUN_GOOGLE),
            ice_server_stun(STUN_IDR),
        ],
        StunPolicy::IdrOnly => vec![ice_server_stun(STUN_IDR)],
        StunPolicy::GoogleOnly => vec![ice_server_stun(STUN_GOOGLE)],
        StunPolicy::Explicit => Vec::new(),
    }
}

fn ice_server_stun(url: &str) -> IceServer {
    IceServer {
        urls: vec![url.to_string()],
        username: None,
        credential: None,
    }
}

pub fn build_rtc_ice_servers(
    offer: &SessionIceConfig,
    local_stun_override: &[IceServer],
) -> std::result::Result<Vec<IceServer>, IceBuildError> {
    let mut out: Vec<IceServer> = Vec::new();

    let stun = match offer.relay_mode {
        IceRelayMode::Byor => resolve_byor_stun(offer)?,
        _ if !local_stun_override.is_empty() => local_stun_override.to_vec(),
        _ => resolve_platform_stun(offer)?,
    };
    out.extend(stun);

    match offer.relay_mode {
        IceRelayMode::Byor => {
            let byor = offer.byor.as_ref().ok_or(IceBuildError::EmptyByorTurn)?;
            if byor.turn_servers.is_empty() {
                return Err(IceBuildError::EmptyByorTurn);
            }
            out.extend(byor_turn_to_ice(byor));
        }
        IceRelayMode::Hybrid => {
            if let Some(turn) = &offer.turn {
                out.extend(validate_turn_servers(&turn.servers)?);
            }
            if let Some(byor) = &offer.byor {
                out.extend(byor_turn_to_ice(byor));
            }
            if !offer.p2p_only
                && offer.turn.is_none()
                && offer.byor.as_ref().is_none_or(|b| b.turn_servers.is_empty())
            {
                return Err(IceBuildError::MissingTurn);
            }
        }
        IceRelayMode::Platform => {
            if offer.p2p_only {
                // STUN already added — no platform TURN.
            } else {
                let turn = offer.turn.as_ref().ok_or(IceBuildError::MissingTurn)?;
                out.extend(validate_turn_servers(&turn.servers)?);
            }
        }
    }

    Ok(dedupe_ice_servers(out))
}

fn resolve_byor_stun(offer: &SessionIceConfig) -> std::result::Result<Vec<IceServer>, IceBuildError> {
    if let Some(byor) = &offer.byor {
        if !byor.stun_servers.is_empty() {
            return Ok(byor_stun_to_ice(byor));
        }
    }
    if offer.stun_policy == StunPolicy::Explicit {
        return offer
            .stun_servers
            .clone()
            .ok_or(IceBuildError::MissingExplicitStun);
    }
    Ok(default_stun_for_policy(offer.stun_policy))
}

fn resolve_platform_stun(
    offer: &SessionIceConfig,
) -> std::result::Result<Vec<IceServer>, IceBuildError> {
    match offer.stun_policy {
        StunPolicy::Explicit => offer
            .stun_servers
            .clone()
            .ok_or(IceBuildError::MissingExplicitStun),
        policy => Ok(default_stun_for_policy(policy)),
    }
}

fn byor_stun_to_ice(byor: &BringYourOwnRelay) -> Vec<IceServer> {
    byor.stun_servers
        .iter()
        .map(|s| IceServer {
            urls: s.urls.clone(),
            username: s.username.clone(),
            credential: s.credential.clone(),
        })
        .collect()
}

fn byor_turn_to_ice(byor: &BringYourOwnRelay) -> Vec<IceServer> {
    byor.turn_servers
        .iter()
        .map(|s| IceServer {
            urls: s.urls.clone(),
            username: s.username.clone(),
            credential: s.credential.clone(),
        })
        .collect()
}

fn validate_turn_servers(servers: &[IceServer]) -> std::result::Result<Vec<IceServer>, IceBuildError> {
    if servers.is_empty() {
        return Err(IceBuildError::MissingTurn);
    }
    for turn in servers {
        if turn.username.as_deref().unwrap_or("").is_empty()
            || turn.credential.as_deref().unwrap_or("").is_empty()
        {
            return Err(IceBuildError::IncompleteTurnCredentials);
        }
        for url in &turn.urls {
            if url.starts_with("stun:") {
                return Err(IceBuildError::TurnEntryLooksLikeStun);
            }
        }
    }
    Ok(servers.to_vec())
}

pub fn dedupe_ice_servers(servers: Vec<IceServer>) -> Vec<IceServer> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for s in servers {
        let key = canonical_ice_server_key(&s);
        if seen.insert(key) {
            out.push(s);
        }
    }
    out
}

fn canonical_ice_server_key(server: &IceServer) -> String {
    let mut urls = server.urls.clone();
    urls.sort();
    format!(
        "{:?}|{}|{}",
        urls,
        server.username.as_deref().unwrap_or(""),
        server.credential.as_deref().unwrap_or("")
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TurnProbeSnapshot {
    pub probe_generation: u64,
    pub probed_at: chrono::DateTime<chrono::Utc>,
    pub ordered_node_ids: Vec<String>,
    #[serde(default)]
    pub latencies_ms: std::collections::HashMap<String, u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_probes: Option<std::collections::HashMap<String, SourceProbeSnapshot>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceProbeSnapshot {
    pub ordered_node_ids: Vec<String>,
    #[serde(default)]
    pub latencies_ms: std::collections::HashMap<String, u32>,
    pub probed_at: chrono::DateTime<chrono::Utc>,
}

/// Validates session ice config structure (Presence-side helper).
pub fn validate_session_ice(ice: &SessionIceConfig) -> Result<()> {
    if ice.stun_policy == StunPolicy::Explicit
        && ice.stun_servers.as_ref().is_none_or(|s| s.is_empty())
        && ice.relay_mode != IceRelayMode::Byor
    {
        return Err(ProtocolError::MalformedDocument(
            "explicit STUN requires stun_servers".into(),
        ));
    }
    match ice.relay_mode {
        IceRelayMode::Byor => {
            if ice.byor.as_ref().is_none_or(|b| b.turn_servers.is_empty()) {
                return Err(ProtocolError::MalformedDocument(
                    "BYOR mode requires byor.turn_servers".into(),
                ));
            }
        }
        IceRelayMode::Platform => {
            if !ice.p2p_only && ice.turn.as_ref().is_none_or(|t| t.servers.is_empty()) {
                return Err(ProtocolError::MalformedDocument(
                    "platform mode requires turn servers".into(),
                ));
            }
        }
        IceRelayMode::Hybrid => {
            let has_platform = ice.turn.as_ref().is_some_and(|t| !t.servers.is_empty());
            let has_byor = ice
                .byor
                .as_ref()
                .is_some_and(|b| !b.turn_servers.is_empty());
            if !ice.p2p_only && !has_platform && !has_byor {
                return Err(ProtocolError::MalformedDocument(
                    "hybrid mode requires platform turn or byor turn".into(),
                ));
            }
        }
    }
    if let Some(turn) = &ice.turn {
        for server in &turn.servers {
            for url in &server.urls {
                if !url.starts_with("turn:") && !url.starts_with("turns:") {
                    return Err(ProtocolError::MalformedDocument(format!(
                        "invalid TURN URL scheme: {url}"
                    )));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webrtc_signaling::{BringYourOwnRelay, ByorIceServer};

    fn platform_turn() -> TurnAllocation {
        TurnAllocation {
            turn_node_id: "turn-eu-1".into(),
            region: "eu-central".into(),
            servers: vec![IceServer {
                urls: vec!["turn:203.0.113.5:3478".into()],
                username: Some("user".into()),
                credential: Some("pass".into()),
            }],
        }
    }

    #[test]
    fn platform_merge_includes_stun_and_turn() {
        let ice = SessionIceConfig {
            relay_mode: IceRelayMode::Platform,
            stun_policy: StunPolicy::GoogleAndIdr,
            stun_servers: None,
            turn: Some(platform_turn()),
            byor: None,
            ice_transport_policy: IceTransportPolicy::All,
            p2p_only: false,
        };
        assert!(ice.has_turn_credentials());
        let merged = build_rtc_ice_servers(&ice, &[]).unwrap();
        assert_eq!(merged.len(), 3);
        assert!(merged[0].urls[0].starts_with("stun:"));
        assert!(merged[2].urls[0].starts_with("turn:"));
    }

    #[test]
    fn byor_merge_uses_customer_turn() {
        let ice = SessionIceConfig {
            relay_mode: IceRelayMode::Byor,
            stun_policy: StunPolicy::Explicit,
            stun_servers: None,
            turn: None,
            byor: Some(BringYourOwnRelay {
                tenant_id: "acme".into(),
                stun_servers: vec![ByorIceServer {
                    urls: vec!["stun:stun.acme.corp:3478".into()],
                    username: None,
                    credential: None,
                    region: None,
                }],
                turn_servers: vec![ByorIceServer {
                    urls: vec!["turn:turn.acme.corp:3478".into()],
                    username: Some("u".into()),
                    credential: Some("p".into()),
                    region: Some("eu".into()),
                }],
            }),
            ice_transport_policy: IceTransportPolicy::All,
            p2p_only: false,
        };
        assert!(ice.has_turn_credentials());
        let merged = build_rtc_ice_servers(&ice, &[]).unwrap();
        assert_eq!(merged.len(), 2);
        assert!(merged[1].urls[0].contains("acme.corp"));
    }

    #[test]
    fn platform_without_turn_is_stun_only() {
        let ice = SessionIceConfig {
            relay_mode: IceRelayMode::Platform,
            stun_policy: StunPolicy::GoogleAndIdr,
            stun_servers: None,
            turn: None,
            byor: None,
            ice_transport_policy: IceTransportPolicy::All,
            p2p_only: false,
        };
        let merged = build_rtc_ice_servers(&ice, &[]).unwrap();
        assert_eq!(merged.len(), 2);
        assert!(merged.iter().all(|s| s.urls.iter().all(|u| u.starts_with("stun:"))));
    }

    #[test]
    fn platform_p2p_only_omits_turn() {
        let ice = SessionIceConfig {
            relay_mode: IceRelayMode::Platform,
            stun_policy: StunPolicy::GoogleAndIdr,
            stun_servers: None,
            turn: None,
            byor: None,
            ice_transport_policy: IceTransportPolicy::All,
            p2p_only: true,
        };
        assert!(!ice.has_turn_credentials());
        let merged = build_rtc_ice_servers(&ice, &[]).unwrap();
        assert!(merged.iter().all(|s| s.urls.iter().all(|u| u.starts_with("stun:"))));
    }
}
