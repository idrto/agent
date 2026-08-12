//! Native (libdatachannel) Source backend.

use std::time::Duration;

use idr_protocol::webrtc_signaling::SourceAuthMode;
use idr_signaling::discovery::{DiscoveryClient, DiscoveryConfig};
use idr_signaling::{PepClient, PepClientConfig};
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
    if doc.presence_servers.is_empty() {
        return Err(idr_core::IdrError::new(
            idr_core::IdrErrorKind::SignalingFailed,
            "discovery has no presence servers",
        ));
    }

    // All live nodes; PepClient dual-mod orders primary/secondary per Target FQHN on connect.
    let pep_cfg = PepClientConfig {
        prefer_quic: true,
        connect_timeout: Duration::from_secs(15),
        insecure_dev: cfg.insecure_dev,
        ..PepClientConfig::default()
    };
    let pep = PepClient::new(doc.presence_servers, pep_cfg);

    Ok(SourceRuntime::with_auth(
        Box::new(pep),
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
