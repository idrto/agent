use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use prometheus::{Encoder, TextEncoder};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{error, info};

use idr_target::acme::AcmeManager;
use idr_target::config::Config;
use idr_target::identity::TargetIdentity;
use idr_target::network::{quic_bind_addr, NetworkCapabilities};
use idr_target::presence::{CommandDedup, DiscoveryService, PresenceQuicClient, PresenceWebSocketClient};
use idr_target::presence::placement::select_primary_secondary;
use idr_target::protocol::fqhn;
use idr_target::protocol::signaling::PresenceRole;
use idr_target::quic::QuicClient;
use idr_target::relay::{IdleScheduler, RelayConnectionManager, RelayReadiness};
use idr_target::relay::connector::RelayConnector;
use idr_target::webrtc::WebRtcSessionManager;
use idr_target::shutdown::ShutdownCoordinator;
use idr_target::storage::{Storage, StorageWriter};
use idr_target::telemetry::{init_tracing, Metrics};

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = std::env::var("IDR_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("config/target.example.toml"));

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
    let discovery_doc = discovery.fetch().await.context("fetch presence discovery")?;
    let discovery_generation = discovery_doc.generation;

    let (primary_idx, secondary_idx) =
        select_primary_secondary(&fqhn, &discovery_doc.presence_servers)?;

    let bind: SocketAddr = quic_bind_addr(network_caps);
    let insecure_dev = cfg.presence.discovery_key.is_empty();
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

    let connection_epoch = 1u64;
    let presence_cfg = cfg.presence.clone();
    let shutdown_presence = shutdown.clone();
    let metrics_presence = metrics.clone();

    let presence_quic = Arc::new(PresenceQuicClient::new(bind, insecure_dev)?);

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
    );

    let mut tasks = vec![tokio::spawn(async move {
        primary_client.run().await
    })];

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
        );
        tasks.push(tokio::spawn(async move {
            secondary_client.run().await
        }));
    }

    let metrics_listen = cfg.telemetry.metrics_listen.clone();
    let registry = metrics.registry().clone();
    tokio::spawn(async move {
        if let Err(e) = serve_metrics(&metrics_listen, registry).await {
            error!(error = %e, "metrics server failed");
        }
    });

    tokio::spawn(async move {
        if signal::ctrl_c().await.is_ok() {
            info!("shutdown signal received");
        }
    });

    // Wait for ctrl-c
    signal::ctrl_c().await?;
    shutdown.begin_drain();
    shutdown.wait_grace_period(cfg.shutdown.grace_period()).await;
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
