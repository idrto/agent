use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct SourceConfig {
    pub source: SourceSection,
    pub presence: PresenceSection,
    #[serde(default)]
    pub dp: DpSection,
    #[serde(default)]
    pub daemon: DaemonSection,
    #[serde(default)]
    pub file_transfer: FileTransferSection,
}

/// `source-agent run`: which Targets to keep sessions with, and where state lives.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DaemonSection {
    /// Holds the transfer outbox. Default: `./source-agent-data`.
    pub data_dir: Option<PathBuf>,
    #[serde(default)]
    pub targets: Vec<String>,
}

/// File transfer on this Source. Off unless enabled; incoming offers are denied
/// unless a peer rule (keyed by the Target's verified SKI) auto-accepts them.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FileTransferSection {
    #[serde(default)]
    pub enabled: bool,
    pub receive_dir: Option<PathBuf>,
    /// PEM of the entity root CA. Default: the root at the end of this device's chain.
    pub entity_root_path: Option<PathBuf>,
    /// Ask the local user (`transfer accept` / `reject`) for offers no rule
    /// auto-accepts. False (headless): such offers are denied.
    #[serde(default)]
    pub interactive: bool,
    /// Directories `transfer accept --out` may choose (besides `receive_dir`).
    #[serde(default)]
    pub permitted_dirs: Vec<PathBuf>,
    #[serde(default)]
    pub peers: Vec<PeerSection>,
    /// Authorization lease for a transfer, minutes (default 15, at least 5).
    pub lease_minutes: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PeerSection {
    pub ski: String,
    #[serde(default)]
    pub auto_accept: bool,
    pub auto_accept_max_bytes: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SourceSection {
    pub source_id: String,
    #[serde(default = "default_region")]
    pub source_region: String,
}

fn default_region() -> String {
    "unknown".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct PresenceSection {
    pub discovery_url: String,
    #[serde(default)]
    pub discovery_key: String,
    #[serde(default = "default_true")]
    pub prefer_quic: bool,
    #[serde(default = "default_fallback_ms")]
    pub transport_fallback_delay_ms: u64,
    #[serde(default = "default_timeout_secs")]
    pub connect_timeout_seconds: u64,
}

fn default_true() -> bool {
    true
}
fn default_fallback_ms() -> u64 {
    150
}
fn default_timeout_secs() -> u64 {
    10
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DpSection {
    /// Path to DeviceIdentity JSON. Prefer Dart flutter_secure_storage when embedded.
    pub identity_path: Option<PathBuf>,
}

impl SourceConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let cfg: Self = toml::from_str(&raw).context("parse source config TOML")?;
        Ok(cfg)
    }
}

/// This device's DP identity as a binding identity (key + chain).
pub fn local_identity(id: &dp_rust_mtls::DeviceIdentity) -> Result<idr_transfer::bind::LocalIdentity> {
    let d = id.private_jwk.get("d").and_then(|v| v.as_str()).context("identity has no private key")?;
    let chain = id
        .chain_pem
        .as_deref()
        .or(id.cert_pem.as_deref())
        .context("identity has no issued certificate (enroll first)")?;
    idr_transfer::bind::LocalIdentity::from_jwk(d, &id.ski, chain).context("identity private key is not Ed25519")
}

/// Entity root(s) Targets must chain to: the configured PEM, else the root at
/// the end of this device's own chain (root-issued devices).
pub fn entity_roots(ft: &FileTransferSection, me: &idr_transfer::bind::LocalIdentity) -> Result<Vec<Vec<u8>>> {
    let pem = match &ft.entity_root_path {
        Some(p) => Some(fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?),
        None => None,
    };
    idr_transfer::bind::entity_roots(pem.as_deref(), &me.chain_pem)
        .context("no entity root: set [file_transfer].entity_root_path")
}
