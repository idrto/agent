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
