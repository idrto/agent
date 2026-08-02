//! Mock Presence WebSocket server for local demo and integration tests.

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::Utc;
use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use idr_protocol::crypto::KeyPair;
use idr_protocol::signaling::{
    EnsureRelayConnectionCommand, EnsureRelayConnectionUnsigned, RelayDescriptor,
    SignalingMessageType,
};
use idr_protocol::webrtc_signaling::{
    ProbeMethod, TurnProbeCandidate, TurnProbeCandidates, TurnProbeReport,
};
use idr_protocol::PROTOCOL_VERSION;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let listen = env::var("MOCK_PRESENCE_LISTEN").unwrap_or_else(|_| "127.0.0.1:8081".into());
    let addr: SocketAddr = listen.parse().context("parse MOCK_PRESENCE_LISTEN")?;
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "mock presence server listening");

    let relay_key = Arc::new(KeyPair::generate());
    let presence_key = Arc::new(KeyPair::generate());
    info!(
        relay_public_key = %relay_key.public_key_base64url(),
        "generated relay signing key for demo commands"
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        let relay_key = relay_key.clone();
        let presence_key = presence_key.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, peer, relay_key, presence_key).await {
                warn!(error = %e, "mock presence client error");
            }
        });
    }
}

async fn handle_client(
    stream: TcpStream,
    peer: SocketAddr,
    relay_key: Arc<KeyPair>,
    presence_key: Arc<KeyPair>,
) -> Result<()> {
    let ws = accept_async(stream).await?;
    info!(%peer, "presence client connected");
    let (mut write, mut read) = ws.split();
    let mut registered = false;

    while let Some(msg) = read.next().await {
        match msg? {
            Message::Text(text) => {
                if !registered {
                    info!(%peer, "registration received: {} bytes", text.len());
                    registered = true;
                    let probe = sample_probe_candidates(&presence_key)?;
                    write.send(Message::Text(probe)).await?;
                } else if text.contains("turn_probe_report") {
                    let report: TurnProbeReport = serde_json::from_str(&text)?;
                    report.verify(&presence_key.verifying_key).ok();
                    info!(%peer, generation = report.probe_generation, "turn probe report accepted");
                } else if text.contains("webrtc_answer") {
                    info!(%peer, "webrtc answer received");
                } else {
                    let cmd = sample_command(&relay_key)?;
                    let json = serde_json::to_string(&cmd)?;
                    write.send(Message::Text(json)).await?;
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
    Ok(())
}

fn sample_probe_candidates(presence_key: &KeyPair) -> Result<String> {
    let unsigned = TurnProbeCandidatesUnsigned {
        version: PROTOCOL_VERSION,
        message_type: SignalingMessageType::TurnProbeCandidates,
        message_id: Uuid::new_v4(),
        probe_generation: 1,
        issued_at: Utc::now(),
        candidates: vec![TurnProbeCandidate {
            turn_node_id: "mock-turn".into(),
            region: "local".into(),
            ipv4: Some("127.0.0.1".into()),
            ipv6: None,
            port: 3478,
            probe_method: ProbeMethod::StunBinding,
        }],
        signature: String::new(),
    };
    let value = serde_json::to_value(&unsigned)?;
    let signature = idr_protocol::crypto::sign_json_canonical(&value, &presence_key.signing_key)?;
    let msg = TurnProbeCandidates {
        version: unsigned.version,
        message_type: unsigned.message_type,
        message_id: unsigned.message_id,
        probe_generation: unsigned.probe_generation,
        issued_at: unsigned.issued_at,
        candidates: unsigned.candidates,
        signature,
    };
    Ok(serde_json::to_string(&msg)?)
}

#[derive(serde::Serialize)]
struct TurnProbeCandidatesUnsigned {
    version: u32,
    message_type: SignalingMessageType,
    message_id: Uuid,
    probe_generation: u64,
    issued_at: chrono::DateTime<Utc>,
    candidates: Vec<TurnProbeCandidate>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    signature: String,
}

fn sample_command(relay_key: &KeyPair) -> Result<EnsureRelayConnectionCommand> {
    let unsigned = EnsureRelayConnectionUnsigned {
        version: PROTOCOL_VERSION,
        message_type: SignalingMessageType::EnsureRelayConnection,
        message_id: Uuid::new_v4(),
        command_id: Uuid::new_v4(),
        session_id: Uuid::new_v4(),
        target_fqhn: "device-01.example.idr.to".into(),
        relay: RelayDescriptor {
            relay_id: "relay-a".into(),
            ipv4: Some("127.0.0.1".into()),
            ipv6: None,
            port: 4433,
            server_name: "relay.example.idr.to".into(),
            alpn: "idr-relay-v1".into(),
            region: None,
        },
        connection_token: "demo-token".into(),
        connection_epoch: 1,
        issued_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::minutes(5),
        presence_generation: 1,
        using_party: None,
        paying_party: None,
        signature: String::new(),
    };
    let value = serde_json::to_value(&unsigned)?;
    let signature = idr_protocol::crypto::sign_json_canonical(&value, &relay_key.signing_key)?;
    Ok(EnsureRelayConnectionCommand {
        version: unsigned.version,
        message_type: unsigned.message_type,
        message_id: unsigned.message_id,
        command_id: unsigned.command_id,
        session_id: unsigned.session_id,
        target_fqhn: unsigned.target_fqhn,
        relay: unsigned.relay,
        connection_token: unsigned.connection_token,
        connection_epoch: unsigned.connection_epoch,
        issued_at: unsigned.issued_at,
        expires_at: unsigned.expires_at,
        presence_generation: unsigned.presence_generation,
        using_party: unsigned.using_party,
        paying_party: unsigned.paying_party,
        signature,
    })
}
