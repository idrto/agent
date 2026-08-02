use prometheus::{
    opts, Gauge, Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
    Registry,
};

macro_rules! register_metric {
    ($registry:expr, $metric:expr) => {
        $registry
            .register(Box::new($metric.clone()))
            .expect("metric registration");
    };
}

#[derive(Clone)]
pub struct Metrics {
    registry: Registry,
    pub presence_connected: IntGaugeVec,
    pub signaling_commands_total: IntCounterVec,
    pub signaling_duplicates_total: IntCounter,
    pub relay_connections: IntGaugeVec,
    pub relay_connection_attempts_total: IntCounterVec,
    pub relay_lookup_probes: Histogram,
    pub relay_table_capacity: IntGauge,
    pub relay_table_tombstones: IntGauge,
    pub idle_connections_closed_total: IntCounter,
    pub sqlite_batch_size: Gauge,
    pub webrtc_sessions_active: IntGauge,
    pub webrtc_turn_probe_duration_seconds: Histogram,
    pub webrtc_turn_probe_unreachable_total: IntCounter,
    pub webrtc_ice_path_total: IntCounterVec,
    pub webrtc_byor_registration: IntCounterVec,
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        let presence_connected = IntGaugeVec::new(
            opts!(
                "idr_target_presence_connected",
                "Presence WebSocket connection state (1 connected, 0 disconnected)"
            ),
            &["role"],
        )
        .expect("create idr_target_presence_connected");
        register_metric!(registry, presence_connected);

        let signaling_commands_total = IntCounterVec::new(
            opts!(
                "idr_target_signaling_commands_total",
                "Signaling commands processed by result"
            ),
            &["result"],
        )
        .expect("create idr_target_signaling_commands_total");
        register_metric!(registry, signaling_commands_total);

        let signaling_duplicates_total = IntCounter::new(
            "idr_target_signaling_duplicates_total",
            "Duplicate signaling commands ignored",
        )
        .expect("create idr_target_signaling_duplicates_total");
        register_metric!(registry, signaling_duplicates_total);

        let relay_connections = IntGaugeVec::new(
            opts!("idr_target_relay_connections", "Relay connections by state"),
            &["state"],
        )
        .expect("create idr_target_relay_connections");
        register_metric!(registry, relay_connections);

        let relay_connection_attempts_total = IntCounterVec::new(
            opts!(
                "idr_target_relay_connection_attempts_total",
                "Relay connection attempts by result and address family"
            ),
            &["result", "family"],
        )
        .expect("create idr_target_relay_connection_attempts_total");
        register_metric!(registry, relay_connection_attempts_total);

        let relay_lookup_probes = Histogram::with_opts(HistogramOpts::new(
            "idr_target_relay_lookup_probes",
            "Probes required for relay table lookup",
        ))
        .expect("create idr_target_relay_lookup_probes");
        register_metric!(registry, relay_lookup_probes);

        let relay_table_capacity = IntGauge::new(
            "idr_target_relay_table_capacity",
            "Relay connection table slot capacity",
        )
        .expect("create idr_target_relay_table_capacity");
        register_metric!(registry, relay_table_capacity);

        let relay_table_tombstones = IntGauge::new(
            "idr_target_relay_table_tombstones",
            "Tombstone slots in relay connection table",
        )
        .expect("create idr_target_relay_table_tombstones");
        register_metric!(registry, relay_table_tombstones);

        let idle_connections_closed_total = IntCounter::new(
            "idr_target_idle_connections_closed_total",
            "Relay connections closed due to idle timeout",
        )
        .expect("create idr_target_idle_connections_closed_total");
        register_metric!(registry, idle_connections_closed_total);

        let sqlite_batch_size = Gauge::new(
            "idr_target_sqlite_batch_size",
            "Last SQLite writer batch size",
        )
        .expect("create idr_target_sqlite_batch_size");
        register_metric!(registry, sqlite_batch_size);

        let webrtc_sessions_active =
            IntGauge::new("idr_webrtc_sessions_active", "Active WebRTC sessions")
                .expect("create idr_webrtc_sessions_active");
        register_metric!(registry, webrtc_sessions_active);

        let webrtc_turn_probe_duration_seconds = Histogram::with_opts(HistogramOpts::new(
            "idr_webrtc_turn_probe_duration_seconds",
            "TURN probe round-trip duration",
        ))
        .expect("create idr_webrtc_turn_probe_duration_seconds");
        register_metric!(registry, webrtc_turn_probe_duration_seconds);

        let webrtc_turn_probe_unreachable_total = IntCounter::new(
            "idr_webrtc_turn_probe_unreachable_total",
            "TURN probe unreachable results",
        )
        .expect("create idr_webrtc_turn_probe_unreachable_total");
        register_metric!(registry, webrtc_turn_probe_unreachable_total);

        let webrtc_ice_path_total = IntCounterVec::new(
            opts!("idr_webrtc_ice_path_total", "ICE path types observed"),
            &["path"],
        )
        .expect("create idr_webrtc_ice_path_total");
        register_metric!(registry, webrtc_ice_path_total);

        let webrtc_byor_registration = IntCounterVec::new(
            opts!(
                "idr_webrtc_byor_registration",
                "Target registrations with BYOR relay mode"
            ),
            &["relay_mode"],
        )
        .expect("create idr_webrtc_byor_registration");
        register_metric!(registry, webrtc_byor_registration);

        Self {
            registry,
            presence_connected,
            signaling_commands_total,
            signaling_duplicates_total,
            relay_connections,
            relay_connection_attempts_total,
            relay_lookup_probes,
            relay_table_capacity,
            relay_table_tombstones,
            idle_connections_closed_total,
            sqlite_batch_size,
            webrtc_sessions_active,
            webrtc_turn_probe_duration_seconds,
            webrtc_turn_probe_unreachable_total,
            webrtc_ice_path_total,
            webrtc_byor_registration,
        }
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn set_relay_state_count(&self, state: &str, count: i64) {
        self.relay_connections
            .with_label_values(&[state])
            .set(count);
    }

    pub fn inc_signaling_result(&self, result: &str) {
        self.signaling_commands_total
            .with_label_values(&[result])
            .inc();
    }

    pub fn inc_connection_attempt(&self, result: &str, family: &str) {
        self.relay_connection_attempts_total
            .with_label_values(&[result, family])
            .inc();
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
