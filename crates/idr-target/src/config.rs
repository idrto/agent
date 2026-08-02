use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub target: TargetConfig,
    pub presence: PresenceConfig,
    #[serde(default)]
    pub relay_connections: RelayConnectionsConfig,
    #[serde(default)]
    pub nginx: NginxConfig,
    #[serde(default)]
    pub acme: AcmeConfig,
    #[serde(default)]
    pub sqlite: SqliteConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub shutdown: ShutdownConfig,
    #[serde(default)]
    pub webrtc: WebRtcConfig,
    #[serde(default)]
    pub billing_party: BillingPartyConfig,
    /// Optional DP DeviceIdentity for Presence PEP mTLS (QUIC / WSS).
    #[serde(default)]
    pub dp: DpConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DpConfig {
    /// Path to DeviceIdentity JSON (ski, private_jwk, credential).
    pub identity_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BillingPartyConfig {
    /// SSO / login of the party using this Target.
    #[serde(default = "default_using_party")]
    pub using_party: String,
    /// Optional payer login; defaults to using_party when omitted.
    #[serde(default)]
    pub paying_party: Option<String>,
}

fn default_using_party() -> String {
    "unconfigured@local".into()
}

impl Default for BillingPartyConfig {
    fn default() -> Self {
        Self {
            using_party: default_using_party(),
            paying_party: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TargetConfig {
    pub fqhn: String,
    pub identity_key_path: Option<PathBuf>,
    #[serde(default = "default_agent_region")]
    pub agent_region: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PresenceConfig {
    pub discovery_url: String,
    pub discovery_key: String,
    #[serde(default = "default_reconnect_initial_ms")]
    pub reconnect_initial_ms: u64,
    #[serde(default = "default_reconnect_max_seconds")]
    pub reconnect_max_seconds: u64,
    #[serde(default = "default_prefer_quic")]
    pub prefer_quic: bool,
    #[serde(default = "default_transport_fallback_delay_ms")]
    pub transport_fallback_delay_ms: u64,
    #[serde(default = "default_presence_connect_timeout_seconds")]
    pub connect_timeout_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelayConnectionsConfig {
    #[serde(default = "default_initial_table_capacity")]
    pub initial_table_capacity: usize,
    #[serde(default = "default_max_table_capacity")]
    pub max_table_capacity: usize,
    #[serde(default = "default_max_active")]
    pub max_active: usize,
    #[serde(default = "default_idle_timeout_seconds")]
    pub idle_timeout_seconds: u64,
    #[serde(default = "default_connect_timeout_seconds")]
    pub connect_timeout_seconds: u64,
    #[serde(default = "default_prefer_ipv6")]
    pub prefer_ipv6: bool,
    #[serde(default = "default_ipv4_fallback_delay_ms")]
    pub ipv4_fallback_delay_ms: u64,
    #[serde(default = "default_failed_retry_initial_ms")]
    pub failed_retry_initial_ms: u64,
    #[serde(default = "default_failed_retry_max_seconds")]
    pub failed_retry_max_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SqliteConfig {
    #[serde(default = "default_sqlite_path")]
    pub path: PathBuf,
    #[serde(default = "default_cache_kib")]
    pub cache_kib: i32,
    #[serde(default = "default_wal_autocheckpoint_pages")]
    pub wal_autocheckpoint_pages: i32,
    #[serde(default = "default_journal_size_limit_bytes")]
    pub journal_size_limit_bytes: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TelemetryConfig {
    #[serde(default = "default_metrics_listen")]
    pub metrics_listen: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub log_json: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ShutdownConfig {
    #[serde(default = "default_grace_period_seconds")]
    pub grace_period_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NginxConfig {
    #[serde(default = "default_nginx_tls_upstream")]
    pub tls_upstream: std::net::SocketAddr,
    #[serde(default = "default_nginx_http_upstream")]
    pub http_upstream: std::net::SocketAddr,
    #[serde(default = "default_tunnel_enabled")]
    pub tunnel_enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AcmeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_acme_email")]
    pub email: String,
    #[serde(default = "default_acme_webroot")]
    pub webroot: PathBuf,
    #[serde(default = "default_acme_cert_dir")]
    pub cert_dir: PathBuf,
    #[serde(default)]
    pub staging: bool,
    #[serde(default = "default_acme_renew_days")]
    pub renew_before_days: u64,
    #[serde(default = "default_nginx_reload")]
    pub nginx_reload_command: Option<String>,
    /// Custom domains for Let's Encrypt only (not `*.idr.to` FQHNs).
    /// Native IDR names use the Relay wildcard cert; ACME is refused for them.
    #[serde(default)]
    pub domains: Vec<String>,
}

impl Default for NginxConfig {
    fn default() -> Self {
        Self {
            tls_upstream: default_nginx_tls_upstream(),
            http_upstream: default_nginx_http_upstream(),
            tunnel_enabled: default_tunnel_enabled(),
        }
    }
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            email: default_acme_email(),
            webroot: default_acme_webroot(),
            cert_dir: default_acme_cert_dir(),
            staging: false,
            renew_before_days: default_acme_renew_days(),
            nginx_reload_command: default_nginx_reload(),
            domains: Vec::new(),
        }
    }
}

impl Default for RelayConnectionsConfig {
    fn default() -> Self {
        Self {
            initial_table_capacity: default_initial_table_capacity(),
            max_table_capacity: default_max_table_capacity(),
            max_active: default_max_active(),
            idle_timeout_seconds: default_idle_timeout_seconds(),
            connect_timeout_seconds: default_connect_timeout_seconds(),
            prefer_ipv6: default_prefer_ipv6(),
            ipv4_fallback_delay_ms: default_ipv4_fallback_delay_ms(),
            failed_retry_initial_ms: default_failed_retry_initial_ms(),
            failed_retry_max_seconds: default_failed_retry_max_seconds(),
        }
    }
}

impl Default for SqliteConfig {
    fn default() -> Self {
        Self {
            path: default_sqlite_path(),
            cache_kib: default_cache_kib(),
            wal_autocheckpoint_pages: default_wal_autocheckpoint_pages(),
            journal_size_limit_bytes: default_journal_size_limit_bytes(),
        }
    }
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            metrics_listen: default_metrics_listen(),
            log_level: default_log_level(),
            log_json: false,
        }
    }
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            grace_period_seconds: default_grace_period_seconds(),
        }
    }
}

impl RelayConnectionsConfig {
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_seconds)
    }

    pub fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_seconds)
    }

    pub fn ipv4_fallback_delay(&self) -> Duration {
        Duration::from_millis(self.ipv4_fallback_delay_ms)
    }

    pub fn failed_retry_initial(&self) -> Duration {
        Duration::from_millis(self.failed_retry_initial_ms)
    }

    pub fn failed_retry_max(&self) -> Duration {
        Duration::from_secs(self.failed_retry_max_seconds)
    }
}

impl PresenceConfig {
    pub fn reconnect_initial(&self) -> Duration {
        Duration::from_millis(self.reconnect_initial_ms)
    }

    pub fn reconnect_max(&self) -> Duration {
        Duration::from_secs(self.reconnect_max_seconds)
    }

    pub fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_seconds)
    }

    pub fn transport_fallback_delay(&self) -> Duration {
        Duration::from_millis(self.transport_fallback_delay_ms)
    }
}

impl ShutdownConfig {
    pub fn grace_period(&self) -> Duration {
        Duration::from_secs(self.grace_period_seconds)
    }
}

fn default_agent_region() -> String {
    "local".into()
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebRtcConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_relay_mode")]
    pub relay_mode: String,
    #[serde(default = "default_stun_policy")]
    pub stun_policy: String,
    #[serde(default = "default_webrtc_max_sessions")]
    pub max_sessions: u32,
    #[serde(default = "default_turn_probe_enabled")]
    pub turn_probe_enabled: bool,
    #[serde(default = "default_webrtc_negotiation_timeout_seconds")]
    pub negotiation_timeout_seconds: u64,
    #[serde(default = "default_webrtc_idle_timeout_seconds")]
    pub idle_timeout_seconds: u64,
    #[serde(default)]
    pub byor: Option<WebRtcByorConfig>,
    #[serde(default)]
    pub stun: WebRtcStunOverrideConfig,
    #[serde(default)]
    pub policy: WebRtcPolicyConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct WebRtcStunOverrideConfig {
    #[serde(default)]
    pub urls: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebRtcByorConfig {
    pub tenant_id: String,
    #[serde(default)]
    pub stun_servers: Vec<WebRtcByorServerConfig>,
    #[serde(default)]
    pub turn_servers: Vec<WebRtcByorServerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebRtcByorServerConfig {
    pub urls: Vec<String>,
    pub username: Option<String>,
    pub credential: Option<String>,
    pub region: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebRtcPolicyConfig {
    #[serde(default = "default_true")]
    pub deny_private_ips: bool,
    #[serde(default)]
    pub allowed_tcp_connect_suffixes: Vec<String>,
}

impl Default for WebRtcPolicyConfig {
    fn default() -> Self {
        Self {
            deny_private_ips: true,
            allowed_tcp_connect_suffixes: Vec::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_relay_mode() -> String {
    "platform".into()
}

fn default_stun_policy() -> String {
    "google_and_idr".into()
}

fn default_webrtc_max_sessions() -> u32 {
    64
}

fn default_turn_probe_enabled() -> bool {
    true
}

fn default_webrtc_negotiation_timeout_seconds() -> u64 {
    45
}

fn default_webrtc_idle_timeout_seconds() -> u64 {
    300
}

impl Default for WebRtcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            relay_mode: default_relay_mode(),
            stun_policy: default_stun_policy(),
            max_sessions: default_webrtc_max_sessions(),
            turn_probe_enabled: default_turn_probe_enabled(),
            negotiation_timeout_seconds: default_webrtc_negotiation_timeout_seconds(),
            idle_timeout_seconds: default_webrtc_idle_timeout_seconds(),
            byor: None,
            stun: WebRtcStunOverrideConfig::default(),
            policy: WebRtcPolicyConfig::default(),
        }
    }
}

impl WebRtcConfig {
    pub fn relay_mode(&self) -> idr_protocol::webrtc_ice::IceRelayMode {
        match self.relay_mode.as_str() {
            "byor" => idr_protocol::webrtc_ice::IceRelayMode::Byor,
            "hybrid" => idr_protocol::webrtc_ice::IceRelayMode::Hybrid,
            _ => idr_protocol::webrtc_ice::IceRelayMode::Platform,
        }
    }

    pub fn stun_policy(&self) -> idr_protocol::webrtc_ice::StunPolicy {
        match self.stun_policy.as_str() {
            "idr_only" => idr_protocol::webrtc_ice::StunPolicy::IdrOnly,
            "google_only" => idr_protocol::webrtc_ice::StunPolicy::GoogleOnly,
            "explicit" => idr_protocol::webrtc_ice::StunPolicy::Explicit,
            _ => idr_protocol::webrtc_ice::StunPolicy::GoogleAndIdr,
        }
    }

    pub fn negotiation_timeout(&self) -> Duration {
        Duration::from_secs(self.negotiation_timeout_seconds)
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_seconds)
    }
}

fn default_reconnect_initial_ms() -> u64 {
    250
}
fn default_reconnect_max_seconds() -> u64 {
    30
}
fn default_prefer_quic() -> bool {
    true
}
fn default_transport_fallback_delay_ms() -> u64 {
    150
}
fn default_presence_connect_timeout_seconds() -> u64 {
    10
}
fn default_initial_table_capacity() -> usize {
    1024
}
fn default_max_table_capacity() -> usize {
    4096
}
fn default_max_active() -> usize {
    64
}
fn default_idle_timeout_seconds() -> u64 {
    120
}
fn default_connect_timeout_seconds() -> u64 {
    5
}
fn default_prefer_ipv6() -> bool {
    true
}
fn default_ipv4_fallback_delay_ms() -> u64 {
    150
}
fn default_failed_retry_initial_ms() -> u64 {
    250
}
fn default_failed_retry_max_seconds() -> u64 {
    30
}
fn default_sqlite_path() -> PathBuf {
    PathBuf::from("target-quic.db")
}
fn default_cache_kib() -> i32 {
    1024
}
fn default_wal_autocheckpoint_pages() -> i32 {
    256
}
fn default_journal_size_limit_bytes() -> i64 {
    8_388_608
}
fn default_metrics_listen() -> String {
    "127.0.0.1:9090".into()
}
fn default_log_level() -> String {
    "info".into()
}
fn default_grace_period_seconds() -> u64 {
    10
}
fn default_nginx_tls_upstream() -> std::net::SocketAddr {
    "127.0.0.1:443".parse().unwrap()
}
fn default_nginx_http_upstream() -> std::net::SocketAddr {
    "127.0.0.1:80".parse().unwrap()
}
fn default_tunnel_enabled() -> bool {
    true
}
fn default_acme_email() -> String {
    "admin@idr.to".into()
}
fn default_acme_webroot() -> PathBuf {
    PathBuf::from("/var/www/acme")
}
fn default_acme_cert_dir() -> PathBuf {
    PathBuf::from("/etc/idr/certs")
}
fn default_acme_renew_days() -> u64 {
    30
}
fn default_nginx_reload() -> Option<String> {
    Some("nginx -s reload".into())
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        let mut cfg: Config = toml::from_str(&raw).context("parse config TOML")?;
        cfg.apply_env_overrides();
        Ok(cfg)
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("IDR_TARGET_FQHN") {
            self.target.fqhn = v;
        }
        if let Ok(v) = std::env::var("IDR_TARGET_IDENTITY_KEY_PATH") {
            self.target.identity_key_path = Some(PathBuf::from(v));
        }
        if let Ok(v) = std::env::var("IDR_PRESENCE_DISCOVERY_URL") {
            self.presence.discovery_url = v;
        }
        if let Ok(v) = std::env::var("IDR_PRESENCE_DISCOVERY_KEY") {
            self.presence.discovery_key = v;
        }
        if let Ok(v) = std::env::var("IDR_SQLITE_PATH") {
            self.sqlite.path = PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("IDR_METRICS_LISTEN") {
            self.telemetry.metrics_listen = v;
        }
        if let Ok(v) = std::env::var("IDR_LOG_LEVEL") {
            self.telemetry.log_level = v;
        }
        if let Ok(v) = std::env::var("IDR_LOG_JSON") {
            self.telemetry.log_json = matches!(v.as_str(), "1" | "true" | "TRUE" | "yes");
        }
        if let Ok(v) = std::env::var("IDR_RELAY_MAX_ACTIVE") {
            if let Ok(n) = v.parse() {
                self.relay_connections.max_active = n;
            }
        }
        if let Ok(v) = std::env::var("IDR_RELAY_IDLE_TIMEOUT_SECONDS") {
            if let Ok(n) = v.parse() {
                self.relay_connections.idle_timeout_seconds = n;
            }
        }
        if let Ok(v) = std::env::var("IDR_ACME_DOMAINS") {
            self.acme.domains = v
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
        }
    }
}
