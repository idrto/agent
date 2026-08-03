use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use idr_dp::{materialize_mtls_client, FileSecretStore, SecretStore};
use prometheus::{Encoder, TextEncoder};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{error, info, warn};

use idr_target::acme::AcmeManager;
use idr_target::config::Config;
use idr_target::identity::TargetIdentity;
use idr_target::network::{quic_bind_addr, NetworkCapabilities};
use idr_target::presence::placement::select_primary_secondary;
use idr_target::presence::{
    CommandDedup, DiscoveryService, PresenceQuicClient, PresenceWebSocketClient,
};
use idr_target::protocol::fqhn;
use idr_target::protocol::signaling::PresenceRole;
use idr_target::quic::QuicClient;
use idr_target::relay::connector::RelayConnector;
use idr_target::relay::{IdleScheduler, RelayConnectionManager, RelayReadiness};
use idr_target::shutdown::ShutdownCoordinator;
use idr_target::storage::{Storage, StorageWriter};
use idr_target::telemetry::{init_tracing, Metrics};
use idr_target::webrtc::WebRtcSessionManager;

#[derive(Parser, Debug)]
#[command(name = "target-agent", version, about = "IDR Target Agent service")]
struct Cli {
    /// Path to target TOML config (or set IDR_CONFIG).
    #[arg(
        short,
        long,
        env = "IDR_CONFIG",
        default_value = "config/target.example.toml"
    )]
    config: PathBuf,

    /// Override DP identity JSON path for Presence PEP mTLS.
    #[arg(long, env = "IDR_DP_IDENTITY")]
    identity: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the Target Agent service (default when no subcommand).
    Run,
    /// Print version and transport summary.
    Version,
    /// Validate config + optional DP identity (no private key dump).
    Doctor,
    /// Generate keys / CSR, enroll (queued or --local instant), and pull
    /// the issued DeviceIdentity. See `idr identity enroll --help`.
    Identity(idr_enroll::cli::IdentityArgs),
    /// Admin: list / approve / reject enrollments; bootstrap a dev CA.
    Cert(idr_enroll::cli::CertArgs),
    /// Admin: bootstrap an Entity (Root + Root Admin credentials).
    Entity(idr_enroll::cli::EntityArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Commands::Run) {
        Commands::Version => {
            println!("target-agent {}", env!("CARGO_PKG_VERSION"));
            println!("pep: quic (fallback wss)");
            println!("dp-sdk: optional Presence mTLS via [dp].identity_path");
            Ok(())
        }
        Commands::Doctor => {
            let cfg = Config::load(&cli.config).context("load configuration")?;
            println!("config_ok=true");
            println!("fqhn={}", cfg.target.fqhn);
            println!("discovery_url={}", cfg.presence.discovery_url);
            println!("prefer_quic={}", cfg.presence.prefer_quic);
            let path = cli.identity.or(cfg.dp.identity_path.clone());
            match path {
                Some(p) => match FileSecretStore::new(&p).load_identity()? {
                    Some(id) => {
                        println!("dp_identity_path={}", p.display());
                        println!("dp_ski={}", id.ski);
                    }
                    None => println!("dp_identity_path={} (missing)", p.display()),
                },
                None => println!("dp_identity_path=(none)"),
            }
            Ok(())
        }
        Commands::Identity(args) => {
            let identity_path = resolve_identity_path(&cli.config, cli.identity.as_deref());
            idr_enroll::cli::dispatch_identity(args.command, "target", &identity_path).await
        }
        Commands::Cert(args) => idr_enroll::cli::dispatch_cert(args.command).await,
        Commands::Entity(args) => idr_enroll::cli::dispatch_entity(args.command).await,
        Commands::Run => run_service(cli.config, cli.identity).await,
    }
}

/// Resolve the DeviceIdentity JSON path for `identity`/`cert`/`entity`
/// subcommands: `--identity` wins, else `[dp].identity_path` from a
/// resolvable config, else `identity.dp.json` in cwd.
fn resolve_identity_path(config: &PathBuf, identity: Option<&std::path::Path>) -> PathBuf {
    if let Some(path) = identity {
        return path.to_path_buf();
    }
    if config.exists() {
        if let Ok(cfg) = Config::load(config) {
            if let Some(path) = cfg.dp.identity_path {
                return path;
            }
        }
    }
    PathBuf::from("identity.dp.json")
}

async fn run_service(config_path: PathBuf, identity_override: Option<PathBuf>) -> Result<()> {
    let cfg = Config::load(&config_path).context("load configuration")?;
    init_tracing(&cfg.telemetry.log_level, cfg.telemetry.log_json)?;

    let fqhn = fqhn::canonicalize(&cfg.target.fqhn).context("canonicalize target FQHN")?;
    info!(%fqhn, "starting target-agent");

    let identity = TargetIdentity::load_or_generate(cfg.target.identity_key_path.as_deref())?;
    let network_caps = NetworkCapabilities::detect();
    let metrics = Metrics::new();
    let shutdown = ShutdownCoordinator::new();

    let storage = Storage::open(&cfg.sqlite)?;
    let writer = StorageWriter::spawn(storage.clone(), metrics.clone());

    let discovery_key = DiscoveryService::discovery_key_from_config(&cfg.presence)?;
    let relay_verify_key = discovery_key;
    let discovery = DiscoveryService::new(
        cfg.presence.clone(),
        relay_verify_key,
        storage.clone(),
        writer.clone(),
    )?;
    let discovery_doc = discovery
        .fetch()
        .await
        .context("fetch presence discovery")?;
    let discovery_generation = discovery_doc.generation;

    let (primary_idx, secondary_idx) =
        select_primary_secondary(&fqhn, &discovery_doc.presence_servers)?;

    let bind: SocketAddr = quic_bind_addr(network_caps);
    let insecure_dev = cfg.presence.discovery_key.is_empty();

    let dp_path = identity_override.or_else(|| cfg.dp.identity_path.clone());
    let mut device_identity: Option<Arc<idr_dp::DeviceIdentity>> = None;
    let mtls_material = if let Some(path) = dp_path {
        match FileSecretStore::new(&path).load_identity()? {
            Some(id) => {
                info!(ski = %id.ski, "loaded DP identity for Presence mTLS + agent JWT");
                let material = materialize_mtls_client(&id).context("materialize DP mTLS")?;
                device_identity = Some(Arc::new(id));
                Some(material)
            }
            None => {
                warn!(path = %path.display(), "DP identity file missing");
                None
            }
        }
    } else {
        None
    };
    if cfg.auth.required && device_identity.is_none() {
        anyhow::bail!(
            "auth.required=true but no DP DeviceIdentity was loaded; configure [dp].identity_path, pass --identity, or explicitly set auth.required=false for local development"
        );
    }

    let quic = Arc::new(QuicClient::new(
        bind,
        identity.public_key_base64url(),
        insecure_dev,
    )?);

    let idle = Arc::new(IdleScheduler::new(metrics.clone()));
    let relay_connector = RelayConnector::new(
        quic,
        storage.clone(),
        network_caps,
        cfg.relay_connections.clone(),
        metrics.clone(),
    );
    let nginx = Arc::new(cfg.nginx.clone());
    let readiness = RelayReadiness::new();
    let relay_manager = Arc::new(RelayConnectionManager::new(
        cfg.relay_connections.clone(),
        relay_connector,
        metrics.clone(),
        idle.clone(),
        writer.clone(),
        Some(nginx),
        readiness.clone(),
        fqhn.clone(),
    ));
    relay_manager.spawn_idle_worker();

    let webrtc_sessions = WebRtcSessionManager::new(cfg.webrtc.clone());

    match AcmeManager::new(cfg.acme.clone(), readiness) {
        Ok(acme) => acme.spawn(),
        Err(e) => error!(error = %e, "ACME manager not started"),
    }

    let relay_verify_key_for_clients = relay_verify_key;
    let dedup = Arc::new(CommandDedup::new(
        std::time::Duration::from_secs(300),
        10_000,
        storage.clone(),
        writer.clone(),
    ));
    dedup.load_persisted();

    // Per-process epoch so same-identity reconnects replace cleanly without
    // colliding with other devices that share this FQHN (DNS multi-A model).
    let connection_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().max(1))
        .unwrap_or(1);
    let presence_cfg = cfg.presence.clone();
    let shutdown_presence = shutdown.clone();
    let metrics_presence = metrics.clone();

    let presence_quic = Arc::new(PresenceQuicClient::with_mtls(
        bind,
        insecure_dev,
        mtls_material.as_ref(),
    )?);

    let primary_server = discovery_doc.presence_servers[primary_idx].clone();
    let primary_client = PresenceWebSocketClient::new(
        primary_server,
        PresenceRole::Primary,
        identity.clone(),
        fqhn.clone(),
        presence_cfg.clone(),
        cfg.clone(),
        metrics_presence.clone(),
        shutdown_presence.clone(),
        relay_manager.clone(),
        dedup.clone(),
        relay_verify_key_for_clients,
        connection_epoch,
        discovery_generation,
        presence_quic.clone(),
        webrtc_sessions.clone(),
        device_identity.clone(),
    );

    let mut tasks = vec![tokio::spawn(async move { primary_client.run().await })];

    if let Some(secondary_idx) = secondary_idx {
        let secondary_server = discovery_doc.presence_servers[secondary_idx].clone();
        let secondary_client = PresenceWebSocketClient::new(
            secondary_server,
            PresenceRole::Secondary,
            identity,
            fqhn,
            presence_cfg,
            cfg.clone(),
            metrics_presence,
            shutdown_presence,
            relay_manager,
            dedup,
            relay_verify_key_for_clients,
            connection_epoch,
            discovery_generation,
            presence_quic,
            webrtc_sessions,
            device_identity,
        );
        tasks.push(tokio::spawn(async move { secondary_client.run().await }));
    }

    let metrics_listen = cfg.telemetry.metrics_listen.clone();
    let registry = metrics.registry().clone();
    tokio::spawn(async move {
        if let Err(e) = serve_metrics(&metrics_listen, registry).await {
            error!(error = %e, "metrics server failed");
        }
    });

    signal::ctrl_c().await?;
    shutdown.begin_drain();
    shutdown
        .wait_grace_period(cfg.shutdown.grace_period())
        .await;
    writer.shutdown().await?;
    for task in tasks {
        let _ = task.await;
    }
    info!("target-agent stopped");
    Ok(())
}

async fn serve_metrics(listen: &str, registry: prometheus::Registry) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind metrics on {listen}"))?;
    info!(listen, "metrics HTTP listening");
    loop {
        let (mut socket, _) = listener.accept().await?;
        let body = {
            let metric_families = registry.gather();
            let mut buffer = Vec::new();
            let encoder = TextEncoder::new();
            encoder.encode(&metric_families, &mut buffer)?;
            buffer
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        socket.write_all(response.as_bytes()).await?;
        socket.write_all(&body).await?;
    }
}
