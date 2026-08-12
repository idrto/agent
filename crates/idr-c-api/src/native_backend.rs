//! Native (libdatachannel) Source backend.

use std::net::SocketAddr;
use std::time::Duration;

use idr_protocol::webrtc_signaling::SourceAuthMode;
use idr_signaling::discovery::{DiscoveryClient, DiscoveryConfig};
use idr_signaling::PresenceQuicSignalingClient;
use idr_source::SourceRuntime;
use idr_webrtc::NativePeer;

pub struct NativeBackendConfig {
    pub source_id: String,
    pub source_region: String,
    pub auth_mode: SourceAuthMode,
    pub auth_token: String,
    pub discovery_url: String,
    pub discovery_key_b64: String,
    pub insecure_dev: bool,
}

pub async fn native_runtime(cfg: NativeBackendConfig) -> idr_core::Result<SourceRuntime> {
    let mut discovery = DiscoveryClient::new(DiscoveryConfig {
        discovery_url: cfg.discovery_url,
        discovery_key_b64: cfg.discovery_key_b64,
        timeout: Duration::from_secs(15),
    })?;
    let doc = discovery.fetch().await?;
    let server = doc
        .presence_servers
        .first()
        .cloned()
        .ok_or_else(|| {
            idr_core::IdrError::new(
                idr_core::IdrErrorKind::SignalingFailed,
                "discovery has no presence servers",
            )
        })?;
    let (v4, v6) = server.parse_quic_endpoints();
    let addr = v4.or(v6).ok_or_else(|| {
        idr_core::IdrError::new(
            idr_core::IdrErrorKind::SignalingFailed,
            "presence server has no QUIC endpoint",
        )
    })?;
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let signaling = PresenceQuicSignalingClient::new(
        bind,
        server,
        addr,
        cfg.insecure_dev,
        Duration::from_secs(15),
    )?;
    Ok(SourceRuntime::with_auth(
        Box::new(signaling),
        || {
            Box::new(
                NativePeer::new(Default::default()).expect("NativePeer::new"),
            )
        },
        cfg.source_id,
        cfg.source_region,
        cfg.auth_mode,
        Some(cfg.auth_token),
    ))
}
