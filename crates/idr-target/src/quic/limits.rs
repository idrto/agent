use std::time::Duration;

use quinn::{IdleTimeout, TransportConfig, VarInt};

pub const MAX_CONCURRENT_BIDI_STREAMS: u32 = 64;
pub const MAX_CONCURRENT_UNI_STREAMS: u32 = 64;

pub fn apply_transport_limits(config: &mut TransportConfig) {
    config.max_concurrent_bidi_streams(VarInt::from_u32(MAX_CONCURRENT_BIDI_STREAMS));
    config.max_concurrent_uni_streams(VarInt::from_u32(MAX_CONCURRENT_UNI_STREAMS));
    config.max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_secs(120)).unwrap()));
}

/// Relay data-path client only — periodic PINGs keep NAT bindings alive on idle tunnels.
pub fn apply_relay_client_transport_limits(config: &mut TransportConfig) {
    apply_transport_limits(config);
    // Keepalive probes also help complete QUIC path validation after migration/rebind.
    config.keep_alive_interval(Some(Duration::from_secs(30)));
}
