//! IDR Source Agent — desktop service / CLI.
//!
//! Secrets: prefer Dart `flutter_secure_storage` when embedded. This binary accepts
//! an injected DP identity JSON path for headless service hosts.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use idr_core::session::PeerSession;
use idr_dp::{device_identity_from_json, FileSecretStore, SecretStore};
use idr_signaling::{DiscoveryClient, DiscoveryConfig, PepClient, PepClientConfig};
use idr_source::SourceRuntime;
use idr_webrtc::native::NativePeerConfig;
use idr_webrtc::NativePeer;
use tracing::{info, warn};

use source_agent::config::SourceConfig;

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
    /// Manage file transfers on the running agent.
    Transfer {
        /// Print JSON instead of text.
        #[arg(long)]
        json: bool,
        #[command(subcommand)]
        cmd: TransferCmd,
    },
    /// Print version and feature summary.
    Version,
}

#[derive(Subcommand, Debug)]
enum TransferCmd {
    /// Send files (repeat --file) or one folder (--dir) to a Target.
    Send {
        #[arg(long)]
        target: String,
        #[arg(long = "file")]
        files: Vec<PathBuf>,
        #[arg(long = "dir")]
        dirs: Vec<PathBuf>,
    },
    /// Transfers and pending offers.
    List,
    Status { id: String },
    /// Accept a pending incoming offer, optionally into a permitted directory.
    Accept {
        id: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Reject { id: String },
    Pause { id: String },
    Resume { id: String },
    Cancel { id: String },
    /// Re-send the entries that failed.
    RetryFailed { id: String },
    /// Peers with a bound session now (who `send --target` can reach).
    Peers,
}

fn ipc_addr(cfg: &SourceConfig) -> Result<idr_transfer::native::ipc::IpcAddr> {
    let dir = cfg.daemon.data_dir.clone().unwrap_or_else(|| "source-agent-data".into());
    std::fs::create_dir_all(&dir)?;
    Ok(idr_transfer::native::ipc::IpcAddr::for_agent("source-agent", &dir)?)
}

impl TransferCmd {
    fn request(self) -> Result<idr_transfer::native::ipc::Request> {
        use idr_transfer::native::ipc::Request;
        let abs = |p: PathBuf| std::fs::canonicalize(&p).with_context(|| format!("{}", p.display()));
        Ok(match self {
            TransferCmd::Send { target, files, dirs } => Request::Send {
                target,
                paths: files.into_iter().chain(dirs).map(abs).collect::<Result<_>>()?,
            },
            TransferCmd::List => Request::List,
            TransferCmd::Status { id } => Request::Status { id },
            TransferCmd::Accept { id, out } => Request::Accept { id, out: out.map(abs).transpose()? },
            TransferCmd::Reject { id } => Request::Reject { id },
            TransferCmd::Pause { id } => Request::Pause { id },
            TransferCmd::Resume { id } => Request::Resume { id },
            TransferCmd::Cancel { id } => Request::Cancel { id },
            TransferCmd::RetryFailed { id } => Request::RetryFailed { id },
            TransferCmd::Peers => Request::Peers,
        })
    }
}

async fn transfer_cmd(cfg: &SourceConfig, json: bool, cmd: TransferCmd) -> Result<()> {
    let ok = idr_transfer::native::control::run_cli(&ipc_addr(cfg)?, "source-agent", cmd.request()?, json)
        .await
        .map_err(anyhow::Error::msg)?;
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // rustls 0.23 needs an explicit process-wide CryptoProvider when aws-lc-rs and
    // ring are both linked (QUIC, Presence); without it the first connect panics.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
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
        Commands::Transfer { json, cmd } => {
            let cfg = load_config(cli.config.as_deref())?;
            transfer_cmd(&cfg, json, cmd).await
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
            let identity = load_identity(&cfg, cli.identity.as_deref())?;
            let factory = runtime_factory(&cfg, identity.clone()).await?;
            if !(cfg.file_transfer.enabled && !cfg.daemon.targets.is_empty()) {
                info!("source-agent running (no [daemon].targets with [file_transfer] enabled; idle)");
                if service {
                    tokio::signal::ctrl_c().await?;
                }
                return Ok(());
            }
            let id = identity.context("[file_transfer] needs a DP identity ([dp].identity_path)")?;
            let me = source_agent::config::local_identity(&id)?;
            let roots = source_agent::config::entity_roots(&cfg.file_transfer, &me)?;
            let mut policy = if cfg.file_transfer.interactive {
                idr_transfer::policy::ReceivePolicy::interactive()
            } else {
                idr_transfer::policy::ReceivePolicy::headless()
            };
            policy.lease = idr_transfer::policy::lease_from_minutes(cfg.file_transfer.lease_minutes);
            for p in &cfg.file_transfer.peers {
                policy.peers.insert(p.ski.clone(), idr_transfer::policy::PeerRule {
                    auto_accept: p.auto_accept,
                    auto_accept_max_bytes: p.auto_accept_max_bytes,
                    ..Default::default()
                });
            }
            let receive_dir = cfg
                .file_transfer
                .receive_dir
                .clone()
                .context("[file_transfer].receive_dir is required")?;
            let daemon = source_agent::daemon::Daemon::start(
                source_agent::daemon::DaemonConfig {
                    data_dir: cfg.daemon.data_dir.clone().unwrap_or_else(|| "source-agent-data".into()),
                    targets: cfg.daemon.targets.clone(),
                    identity: std::sync::Arc::new(me),
                    roots,
                    receive_dir,
                    receive_policy: policy,
                    send_policy: Default::default(),
                    limits: Default::default(),
                    reconnect_min: Duration::from_secs(1),
                    reconnect_max: Duration::from_secs(60),
                    ipc: Some(ipc_addr(&cfg)?),
                    permitted_dirs: cfg.file_transfer.permitted_dirs.clone(),
                    offer_expiry: Duration::from_secs(300),
                },
                factory,
            )?;
            info!(targets = cfg.daemon.targets.len(), "source-agent daemon running (ctrl-c to stop)");
            tokio::signal::ctrl_c().await?;
            daemon.shutdown().await;
            info!("source-agent stopped");
            Ok(())
        }
        Commands::Connect { target, service } => {
            let cfg = load_config(cli.config.as_deref())?;
            let identity = load_identity(&cfg, cli.identity.as_deref())?;
            let mut runtime = runtime_factory(&cfg, identity).await?();
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

fn load_identity(
    cfg: &SourceConfig,
    identity_override: Option<&std::path::Path>,
) -> Result<Option<idr_dp::DeviceIdentity>> {
    let Some(path) = identity_override.map(PathBuf::from).or_else(|| cfg.dp.identity_path.clone()) else {
        return Ok(None);
    };
    let id = FileSecretStore::new(&path).load_identity()?;
    if id.is_none() {
        warn!(path = %path.display(), "DP identity file missing; continuing unenrolled");
    }
    Ok(id)
}

/// Fresh Source runtimes on the native WebRTC stack (the one the C ABI uses):
/// Presence discovery once, then a Presence client and a libdatachannel peer per
/// connection attempt.
async fn runtime_factory(
    cfg: &SourceConfig,
    identity: Option<idr_dp::DeviceIdentity>,
) -> Result<source_agent::daemon::RuntimeFactory> {
    let mut discovery = DiscoveryClient::new(DiscoveryConfig {
        discovery_url: cfg.presence.discovery_url.clone(),
        discovery_key_b64: cfg.presence.discovery_key.clone(),
        timeout: Duration::from_secs(cfg.presence.connect_timeout_seconds),
    })?;
    let servers = discovery.fetch().await.context("presence discovery")?.presence_servers;
    let pep_cfg = PepClientConfig {
        prefer_quic: cfg.presence.prefer_quic,
        connect_timeout: Duration::from_secs(cfg.presence.connect_timeout_seconds),
        transport_fallback_delay: Duration::from_millis(cfg.presence.transport_fallback_delay_ms),
        insecure_dev: cfg.presence.discovery_key.is_empty(),
        ..PepClientConfig::default()
    };
    let (source_id, region) = (cfg.source.source_id.clone(), cfg.source.source_region.clone());
    Ok(std::sync::Arc::new(move || {
        // The device proves itself in each session request (`source_proof`), as the
        // engine does; Presence doesn't accept PepClient's in-band credential frame.
        let pep = PepClient::new(servers.clone(), pep_cfg.clone());
        let runtime = SourceRuntime::new(
            Box::new(pep),
            || Box::new(NativePeer::new(NativePeerConfig::default()).expect("native WebRTC peer")),
            source_id.clone(),
            region.clone(),
        );
        match &identity {
            Some(id) => runtime.with_identity(id.clone()),
            None => runtime,
        }
    }))
}

#[allow(dead_code)]
fn load_identity_json(raw: &str) -> Result<idr_dp::DeviceIdentity> {
    Ok(device_identity_from_json(raw)?)
}
