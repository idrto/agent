//! Writes a realistic idr.log/1 sample to `<dir>/sample-agent/` for CI schema validation:
//! `cargo run -p idr-telemetry --features subscriber --example sample -- <dir>`
//! then `idr_diag validate <dir>`.

use idr_telemetry::{init, new_id, Config, StdoutFormat};

fn main() {
    let dir = std::env::args().nth(1).expect("usage: sample <log root>");
    let mut cfg = Config::new("sample-agent", env!("CARGO_PKG_VERSION"));
    cfg.log_root = Some(dir.into());
    cfg.stdout = StdoutFormat::Off;
    cfg.recorder_prefixes = vec!["sample".into()];
    let guard = init(cfg).expect("init");
    let session = new_id();
    {
        let root = tracing::info_span!("source.connect", session_id = %session, persist_start = true, target.fqhn = "gpu--acme.idr.to");
        let _r = root.enter();
        let attempt = tracing::info_span!(
            "source.connect.attempt",
            retry.attempt = 1u64,
            persist_start = true
        );
        let _a = attempt.enter();
        tracing::debug!(event = "webrtc.ice.candidate_gathered", candidate.type = "host", candidate.protocol = "udp");
        tracing::warn!(event = "connection.attempt.failed", error.type = "ice_failed", phase = "ice", elapsed_ms = 30012u64, "ICE failed via 203.0.113.7");
        tracing::info!(
            event = "connection.established",
            transport.selected = "turn",
            setup_ms = 812u64
        );
        tracing::error!(event = "transfer.failed", error.type = "storage_full", bytes.done = 1024u64, transfer_id = %new_id());
    }
    drop(guard);
}
