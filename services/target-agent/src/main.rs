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
}

#[tokio::main]
async fn main() -> Result<()> {
    // rustls 0.23 needs an explicit process-wide CryptoProvider when aws-lc-rs and
    // ring are both linked (e.g. via tokio-tungstenite). Required in production too.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install rustls aws-lc-rs CryptoProvider");

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
        Commands::Run => run_service(cli.config, cli.identity).await,
    }
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
    let discovery = DiscoveryService::new(
        cfg.presence.clone(),
        discovery_key.clone(),
        storage.clone(),
        writer.clone(),
    )?;
    let discovery_doc = discovery
        .fetch()
        .await
        .context("fetch presence discovery")?;
    let discovery_generation = discovery_doc.generation;

    let insecure_dev = cfg.presence.insecure_dev || cfg.presence.discovery_key.is_empty();

    // Presence-signed ensure/relay commands use the discovery verify key, or a
    // per-server public_key from full discovery docs. Live slim CDN docs omit
    // keys — under insecure_dev continue with an ephemeral key (verify soft-fails).
    let relay_verify_key = match discovery_key {
        Some(k) => k,
        None => {
            let pk = discovery_doc
                .presence_servers
                .iter()
                .map(|s| s.public_key.as_str())
                .find(|p| !p.is_empty());
            match pk {
                Some(pk) => idr_target::protocol::crypto::KeyPair::from_base64url_public(pk)
                    .map_err(|e| anyhow::anyhow!("presence public_key: {e}"))?,
                None if insecure_dev => {
                    warn!(
                        "discovery has no presence public keys; insecure_dev: ephemeral verify key"
                    );
                    idr_target::protocol::crypto::KeyPair::generate().verifying_key
                }
                None => anyhow::bail!(
                    "discovery has no presence public_key; set presence.discovery_key \
                     or presence.insecure_dev = true"
                ),
            }
        }
    };

    let (primary_idx, secondary_idx) =
        select_primary_secondary(&fqhn, &discovery_doc.presence_servers)?;
    info!(
        primary_idx,
        secondary_idx = ?secondary_idx,
        primary_ipv4 = ?discovery_doc.presence_servers[primary_idx].ipv4,
        secondary_ipv4 = secondary_idx
            .and_then(|i| discovery_doc.presence_servers[i].ipv4.clone()),
        generation = discovery_generation,
        "live presence placement"
    );

    let bind: SocketAddr = quic_bind_addr(network_caps);

    let dp_path = identity_override.or_else(|| cfg.dp.identity_path.clone());
    let mtls_material = if let Some(path) = dp_path {
        match FileSecretStore::new(&path).load_identity()? {
            Some(id) => {
                info!(ski = %id.ski, "loaded DP identity for Presence mTLS");
                Some(materialize_mtls_client(&id).context("materialize DP mTLS")?)
            }
            None => {
                warn!(path = %path.display(), "DP identity file missing");
                None
            }
        }
    } else {
        None
    };

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
    let connectors = Arc::new(idr_target::plugins::build_connector_registry(&cfg, &fqhn));
    info!(
        services = ?connectors.service_names(),
        "connector registry ready"
    );

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
        connectors.clone(),
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
            connectors,
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
