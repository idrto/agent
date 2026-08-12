//! IDR Source Agent — desktop service / CLI.
//!
//! Secrets: prefer Dart `flutter_secure_storage` when embedded. This binary accepts
//! an injected DP identity JSON path for headless service hosts.

mod config;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use idr_core::session::PeerSession;
use idr_dp::{device_identity_from_json, FileSecretStore, SecretStore};
use idr_signaling::{DiscoveryClient, DiscoveryConfig, PepClient, PepClientConfig};
use idr_source::SourceRuntime;
use idr_webrtc::RecordingPeer;
use tracing::{info, warn};

use crate::config::SourceConfig;

#[derive(Parser, Debug)]
#[command(
    name = "source-agent",
    version,
    about = "IDR Source Agent desktop service"
)]
struct Cli {
    /// Path to source TOML config (or set IDR_SOURCE_CONFIG).
    #[arg(short, long, global = true, env = "IDR_SOURCE_CONFIG")]
    config: Option<PathBuf>,

    /// Override DP identity JSON path (ski + private_jwk + credential).
    #[arg(long, global = true, env = "IDR_DP_IDENTITY")]
    identity: Option<PathBuf>,

    /// Log level (error|warn|info|debug|trace).
    #[arg(long, global = true, env = "IDR_LOG", default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run as a long-lived desktop service.
    Run {
        /// Keep process alive after startup even without active sessions.
        #[arg(long, default_value_t = true)]
        service: bool,
    },
    /// Connect once to a Target FQHN (debug / smoke).
    Connect {
        /// Target FQHN (e.g. cam1.acme.idr.to).
        target: String,
        /// Optional named service to open after connect.
        #[arg(long)]
        service: Option<String>,
    },
    /// Print resolved config + identity SKI (never prints private keys).
    Doctor,
    /// Print version and feature summary.
    Version,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log_level);

    match cli.command {
        Commands::Version => {
            println!("source-agent {}", env!("CARGO_PKG_VERSION"));
            println!("pep: quic (fallback wss)");
            println!("dp-sdk: dp-rust / dp-rust-mtls");
            println!("secrets: inject via --identity or Dart flutter_secure_storage");
            Ok(())
        }
        Commands::Doctor => {
            let cfg = load_config(cli.config.as_deref())?;
            let identity_path = cli
                .identity
                .clone()
                .or_else(|| cfg.dp.identity_path.clone());
            println!("config_ok=true");
            println!("source_id={}", cfg.source.source_id);
            println!("source_region={}", cfg.source.source_region);
            println!("discovery_url={}", cfg.presence.discovery_url);
            println!("prefer_quic={}", cfg.presence.prefer_quic);
            match identity_path {
                Some(path) => {
                    let store = FileSecretStore::new(&path);
                    match store.load_identity()? {
                        Some(id) => {
                            println!("identity_path={}", path.display());
                            println!("identity_ski={}", id.ski);
                            println!("identity_entity={}", id.credential.entity_id);
                        }
                        None => println!("identity_path={} (missing)", path.display()),
                    }
                }
                None => println!("identity_path=(none)"),
            }
            Ok(())
        }
        Commands::Run { service } => {
            let cfg = load_config(cli.config.as_deref())?;
            let runtime = build_runtime(&cfg, cli.identity.as_deref()).await?;
            info!(
                source_id = %cfg.source.source_id,
                mtls = runtime.identity().is_some(),
                "source-agent service starting"
            );
            let _runtime = runtime;
            if service {
                info!("source-agent running (ctrl-c to stop)");
                tokio::signal::ctrl_c().await?;
                info!("source-agent stopped");
            }
            Ok(())
        }
        Commands::Connect { target, service } => {
            let cfg = load_config(cli.config.as_deref())?;
            let mut runtime = build_runtime(&cfg, cli.identity.as_deref()).await?;
            info!(%target, "connecting");
            let mut session = runtime.connect(&target).await.context("connect")?;
            info!(%target, "connected");
            if let Some(svc) = service {
                let _stream = session
                    .open_named_stream(&svc)
                    .await
                    .with_context(|| format!("open service {svc}"))?;
                info!(service = %svc, "stream opened");
            }
            session.close().await?;
            Ok(())
        }
    }
}

fn init_tracing(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_new(level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

fn load_config(path: Option<&std::path::Path>) -> Result<SourceConfig> {
    let path = path
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config/source.example.toml"));
    SourceConfig::load(&path).with_context(|| format!("load {}", path.display()))
}

async fn build_runtime(
    cfg: &SourceConfig,
    identity_override: Option<&std::path::Path>,
) -> Result<SourceRuntime> {
    let discovery_cfg = DiscoveryConfig {
        discovery_url: cfg.presence.discovery_url.clone(),
        discovery_key_b64: cfg.presence.discovery_key.clone(),
        timeout: Duration::from_secs(cfg.presence.connect_timeout_seconds),
    };
    let mut discovery = DiscoveryClient::new(discovery_cfg)?;
    let doc = discovery.fetch().await.context("presence discovery")?;
    // PepClient dual-mod orders primary/secondary per Target FQHN on connect.
    let servers = doc.presence_servers.clone();

    let pep_cfg = PepClientConfig {
        prefer_quic: cfg.presence.prefer_quic,
        connect_timeout: Duration::from_secs(cfg.presence.connect_timeout_seconds),
        transport_fallback_delay: Duration::from_millis(cfg.presence.transport_fallback_delay_ms),
        insecure_dev: cfg.presence.discovery_key.is_empty(),
        ..PepClientConfig::default()
    };
    let mut pep = PepClient::new(servers, pep_cfg);

    let identity_path = identity_override
        .map(PathBuf::from)
        .or_else(|| cfg.dp.identity_path.clone());
    if let Some(path) = identity_path {
        let store = FileSecretStore::new(&path);
        if let Some(identity) = store.load_identity()? {
            pep = pep.with_identity(identity.clone())?;
            return Ok(SourceRuntime::new(
                Box::new(pep),
                || Box::new(RecordingPeer::new()),
                cfg.source.source_id.clone(),
                cfg.source.source_region.clone(),
            )
            .with_identity(identity));
        }
        warn!(path = %path.display(), "DP identity file missing; continuing anonymous");
    }

    Ok(SourceRuntime::new(
        Box::new(pep),
        || Box::new(RecordingPeer::new()),
        cfg.source.source_id.clone(),
        cfg.source.source_region.clone(),
    ))
}

#[allow(dead_code)]
fn load_identity_json(raw: &str) -> Result<idr_dp::DeviceIdentity> {
    Ok(device_identity_from_json(raw)?)
}
