//! Telemetry for the in-process engine (docs/observability/01 §3): the Dart host calls
//! `idr_telemetry_init` once with its `app_session_id`, so the engine writes the
//! `rust.jsonl` producer of the same run into the host's log directory.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::sync::Mutex;
use std::time::Duration;

use idr_telemetry::{Config, StdoutFormat, TelemetryGuard};

static GUARD: Mutex<Option<TelemetryGuard>> = Mutex::new(None);

/// `config_json`: `{"service", "log_root", "app_session_id", "filter"}`.
/// Returns 0, `-1` for invalid JSON, `-2` when already initialized or init fails.
#[no_mangle]
pub unsafe extern "C" fn idr_telemetry_init(config_json: *const c_char) -> c_int {
    caught!("idr_telemetry_init", -1, {
        if config_json.is_null() {
            return -1;
        }
        let Ok(text) = CStr::from_ptr(config_json).to_str() else { return -1 };
        let Ok(j) = serde_json::from_str::<serde_json::Value>(text) else { return -1 };
        let field = |k: &str| j.get(k).and_then(|v| v.as_str()).map(String::from);
        // service: the host's directory (shared by both producers); app_session_id: the host's id.
        let (Some(service), Some(app_session_id)) = (field("service"), field("app_session_id")) else {
            return -1;
        };
        let mut cfg = Config::new("idr-c-api", env!("CARGO_PKG_VERSION"));
        cfg.service_dir = Some(service);
        cfg.log_root = field("log_root").map(Into::into);
        cfg.app_session_id = Some(app_session_id);
        cfg.filter = field("filter").unwrap_or_else(|| "info".into());
        cfg.stdout = StdoutFormat::Off;
        let mut guard = GUARD.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_some() {
            return -2;
        }
        match idr_telemetry::init(cfg) {
            Ok(g) => {
                *guard = Some(g);
                0
            }
            Err(_) => -2,
        }
    })
}

/// Drains the flight recorder and syncs to disk (before a diagnostic bundle). 0 or -1.
#[no_mangle]
pub extern "C" fn idr_telemetry_flush() -> c_int {
    caught!("idr_telemetry_flush", -1, {
        if idr_telemetry::flush_and_wait(Duration::from_secs(5)) {
            0
        } else {
            -1
        }
    })
}

/// Writes remaining records and `app.stopping`; call from the host's shutdown.
#[no_mangle]
pub extern "C" fn idr_telemetry_shutdown() -> c_int {
    caught!("idr_telemetry_shutdown", -1, {
        drop(GUARD.lock().unwrap_or_else(|e| e.into_inner()).take());
        0
    })
}
