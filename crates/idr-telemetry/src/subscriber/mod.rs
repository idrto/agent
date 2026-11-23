//! Composition-point API: [`init`], [`init_from_env`], [`TelemetryGuard`], crash capture,
//! [`ffi_guard`], current context. Libraries must not call [`init`].

mod files;
mod layer;
mod pipeline;
mod record;

pub use files::{
    cleanup, free_bytes, recover, run_state, CleanupReport, Exit, FileSink, Recovered, RunKey,
    RunState,
};
pub use layer::Directives;
pub use pipeline::{Limits, Pipeline, Route, StdoutFormat, Writer};
pub use record::{
    format_ts, ErrorInfo, Kind, Level, Record, Value, MAX_CRASH_BYTES, MAX_RECORD_BYTES,
};

use crate::ids::{hex, TraceContext};
use crate::LocalContext;
use chrono::Utc;
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;

/// Default flight-recorder capture: our own crates only (third-party DEBUG is unbounded).
pub const DEFAULT_RECORDER_PREFIXES: &[&str] = &[
    "idr",
    "target_agent",
    "source_agent",
    "mock_presence",
    "presence",
    "relay",
    "diag_ingest",
];

pub struct Config {
    /// Process kind: `target-agent`, `presence`, `idr-c-api`, … (03 §1.3 `service`).
    pub service: String,
    pub service_version: String,
    /// Log root (`IDR_LOG_DIR`); files go to `<root>/<service>/`, crashes to `<root>/crash/`.
    /// `None` = no files (servers: stdout only).
    pub log_root: Option<PathBuf>,
    pub stdout: StdoutFormat,
    /// `IDR_LOG` directives, default `info`.
    pub filter: String,
    /// `Some` = embedded in a host process: adopt its id and write the `rust.jsonl` producer.
    pub app_session_id: Option<String>,
    pub parent_app_session_id: Option<String>,
    pub recorder_bytes: usize,
    pub queue_bytes: usize,
    pub recorder_prefixes: Vec<String>,
    pub install_panic_hook: bool,
    /// Directory under the log root; default `service`. The in-process engine uses its
    /// host's directory so both producers of one process sit together (01 §3).
    pub service_dir: Option<String>,
}

impl Config {
    pub fn new(service: impl Into<String>, service_version: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            service_version: service_version.into(),
            log_root: None,
            stdout: StdoutFormat::Json,
            filter: "info".into(),
            app_session_id: None,
            parent_app_session_id: None,
            recorder_bytes: 3 * 1024 * 1024,
            queue_bytes: 1024 * 1024,
            recorder_prefixes: DEFAULT_RECORDER_PREFIXES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            install_panic_hook: true,
            service_dir: None,
        }
    }

    /// Reads `IDR_LOG` (or deprecated `RUST_LOG`), `IDR_LOG_FORMAT`, `IDR_LOG_DIR`,
    /// `IDR_PARENT_APP_SESSION_ID` (01 §3). Stdout defaults to `json` for servers; a caller
    /// that is a CLI on a TTY sets `pretty`.
    pub fn from_env(
        service: impl Into<String>,
        service_version: impl Into<String>,
    ) -> (Self, Vec<&'static str>) {
        let mut c = Self::new(service, service_version);
        let mut deprecated = Vec::new();
        match (std::env::var("IDR_LOG"), std::env::var("RUST_LOG")) {
            (Ok(v), _) if !v.trim().is_empty() => c.filter = v,
            (_, Ok(v)) if !v.trim().is_empty() => {
                c.filter = v;
                deprecated.push("RUST_LOG");
            }
            _ => {}
        }
        c.stdout = match std::env::var("IDR_LOG_FORMAT").as_deref() {
            Ok("pretty") => StdoutFormat::Pretty,
            Ok("off") => StdoutFormat::Off,
            _ => StdoutFormat::Json,
        };
        c.log_root = std::env::var_os("IDR_LOG_DIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from);
        c.parent_app_session_id = std::env::var("IDR_PARENT_APP_SESSION_ID")
            .ok()
            .filter(|v| crate::is_uuid(v));
        (c, deprecated)
    }
}

/// Per-OS default log root (04 §1.1): Windows `%LOCALAPPDATA%\IDR\logs`, macOS
/// `~/Library/Logs/IDR`, Linux `$XDG_STATE_HOME/idr/logs` (or `~/.local/state/idr/logs`).
pub fn default_log_root() -> Option<PathBuf> {
    let env = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    if cfg!(windows) {
        env("LOCALAPPDATA").map(|p| p.join("IDR").join("logs"))
    } else if cfg!(target_os = "macos") {
        env("HOME").map(|h| h.join("Library").join("Logs").join("IDR"))
    } else {
        env("XDG_STATE_HOME")
            .or_else(|| env("HOME").map(|h| h.join(".local").join("state")))
            .map(|p| p.join("idr").join("logs"))
    }
}

/// How a binary wants telemetry when the environment does not say (01 §3).
pub struct BinaryDefaults<'a> {
    /// Filter when neither `IDR_LOG` nor `RUST_LOG` is set (e.g. the config file's level).
    pub filter: &'a str,
    /// Stdout as JSON when `IDR_LOG_FORMAT` is unset and stdout is not a terminal.
    pub json_stdout: bool,
    /// Write files under [`default_log_root`] when `IDR_LOG_DIR` is unset (agents: yes;
    /// servers: no, they log to stdout only).
    pub files: bool,
}

/// [`init_from_env`] with per-binary defaults: `IDR_LOG` > `RUST_LOG` (deprecated) >
/// `defaults.filter`; `IDR_LOG_FORMAT` > pretty on a terminal > JSON (`json_stdout`) or off
/// when files are written; `IDR_LOG_DIR` > [`default_log_root`] (if `files`).
pub fn init_binary(
    service: &str,
    version: &str,
    defaults: BinaryDefaults<'_>,
) -> Result<TelemetryGuard, InitError> {
    use std::io::IsTerminal;
    let (mut cfg, deprecated) = Config::from_env(service, version);
    let has = |k: &str| std::env::var(k).is_ok_and(|v| !v.trim().is_empty());
    if !has("IDR_LOG") && !has("RUST_LOG") {
        cfg.filter = defaults.filter.to_string();
    }
    if cfg.log_root.is_none() && defaults.files {
        cfg.log_root = default_log_root();
    }
    if !has("IDR_LOG_FORMAT") {
        cfg.stdout = if std::io::stdout().is_terminal() {
            StdoutFormat::Pretty
        } else if defaults.json_stdout || cfg.log_root.is_none() {
            StdoutFormat::Json
        } else {
            StdoutFormat::Off
        };
    }
    init_with_deprecations(cfg, &deprecated)
}

/// Ends the process like `std::process::exit`, after writing remaining records and
/// `app.stopping`. A bare `exit` skips destructors, so the run would look unclean (04 §3.3).
pub fn exit(code: i32) -> ! {
    if let Some(s) = SHARED.get() {
        let r = s
            .record(Kind::Log, Level::Info, "app.stopping")
            .attr("reason", Value::Str("exit".into()))
            .attr("exit_code", Value::I64(code.into()));
        s.pipeline.shutdown(r, Duration::from_secs(5));
    }
    std::process::exit(code)
}

/// `TRACEPARENT` handed to a spawned agent for its start-up span (02 §4.4).
pub fn startup_parent() -> Option<TraceContext> {
    std::env::var("TRACEPARENT")
        .ok()
        .and_then(|v| TraceContext::parse(&v))
}

#[derive(Debug)]
pub enum InitError {
    AlreadyInitialized,
    Io(io::Error),
}

impl std::fmt::Display for InitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InitError::AlreadyInitialized => f.write_str("telemetry already initialized"),
            InitError::Io(e) => write!(f, "telemetry init: {e}"),
        }
    }
}

impl std::error::Error for InitError {}

struct OpenSpan {
    name: &'static str,
    trace_id: String,
    span_id: String,
}

/// Process identity and handles shared by the layer, the guard and the panic hook.
pub(crate) struct Shared {
    pub service: String,
    pub service_version: String,
    pub app_session_id: String,
    pipeline: Arc<Pipeline>,
    crash_dir: Option<PathBuf>,
    open_spans: Mutex<HashMap<u64, OpenSpan>>,
}

impl Shared {
    pub(crate) fn span_opened(&self, id: u64, name: &'static str, d: &layer::SpanData) {
        if let Ok(mut m) = self.open_spans.lock() {
            m.insert(
                id,
                OpenSpan {
                    name,
                    trace_id: hex(&d.trace_id),
                    span_id: hex(&d.span_id),
                },
            );
        }
    }
    pub(crate) fn span_closed(&self, id: u64) {
        if let Ok(mut m) = self.open_spans.lock() {
            m.remove(&id);
        }
    }

    fn record(&self, kind: Kind, level: Level, event: &str) -> Record {
        let mut r = Record::new(kind, level, event);
        r.ts = format_ts(Utc::now());
        r.service.clone_from(&self.service);
        r.service_version.clone_from(&self.service_version);
        r.app_session_id.clone_from(&self.app_session_id);
        r.component = "idr_telemetry".into();
        r
    }

    fn emit(&self, r: Record) {
        self.pipeline.submit(
            r,
            Route {
                to_ring: true,
                to_file: true,
                to_stdout: true,
            },
        );
    }
}

static SHARED: OnceLock<Arc<Shared>> = OnceLock::new();
static FALLBACK_ID: OnceLock<String> = OnceLock::new();

/// This process's `app_session_id` (minted lazily if telemetry is not initialized).
pub fn app_session_id() -> String {
    match SHARED.get() {
        Some(s) => s.app_session_id.clone(),
        None => FALLBACK_ID.get_or_init(crate::new_id).clone(),
    }
}

/// Flushes the guard on drop: writes remaining records and `app.stopping` last.
pub struct TelemetryGuard {
    shared: Arc<Shared>,
    writer: Option<std::thread::JoinHandle<()>>,
    reason: &'static str,
}

impl TelemetryGuard {
    /// Reason recorded in `app.stopping` (`user`, `signal`, `update`, `error`; default `exit`).
    pub fn set_stop_reason(&mut self, reason: &'static str) {
        self.reason = reason;
    }

    pub fn pipeline(&self) -> &Arc<Pipeline> {
        &self.shared.pipeline
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        let r = self
            .shared
            .record(Kind::Log, Level::Info, "app.stopping")
            .attr("reason", Value::Str(self.reason.into()));
        self.shared.pipeline.shutdown(r, Duration::from_secs(5));
        if let Some(w) = self.writer.take() {
            let _ = w.join();
        }
    }
}

/// Installs the global subscriber. Call once, at the composition point.
pub fn init(cfg: Config) -> Result<TelemetryGuard, InitError> {
    init_with_deprecations(cfg, &[])
}

/// [`Config::from_env`] + [`init`], emitting deprecation events for old env vars.
pub fn init_from_env(service: &str, service_version: &str) -> Result<TelemetryGuard, InitError> {
    let (cfg, deprecated) = Config::from_env(service, service_version);
    init_with_deprecations(cfg, &deprecated)
}

fn init_with_deprecations(
    cfg: Config,
    deprecated: &[&'static str],
) -> Result<TelemetryGuard, InitError> {
    if SHARED.get().is_some() {
        return Err(InitError::AlreadyInitialized);
    }
    let (guard, subscriber) = build(cfg, deprecated)?;
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|_| InitError::AlreadyInitialized)?;
    let _ = SHARED.set(guard.shared.clone());
    Ok(guard)
}

/// Builds the pipeline, writer thread and subscriber without installing them globally
/// (tests use `tracing::subscriber::with_default`).
pub fn build(
    cfg: Config,
    deprecated: &[&'static str],
) -> Result<
    (
        TelemetryGuard,
        impl tracing::Subscriber + Send + Sync + for<'a> LookupSpan<'a>,
    ),
    InitError,
> {
    let directives = Directives::parse(&cfg.filter);
    let embedded = cfg.app_session_id.is_some();
    let app_session_id = cfg
        .app_session_id
        .clone()
        .filter(|v| crate::is_uuid(v))
        .unwrap_or_else(crate::new_id);
    let producer = if embedded { "rust.jsonl" } else { "jsonl" };
    let limits = Limits {
        queue_bytes: cfg.queue_bytes,
        ring_bytes: cfg.recorder_bytes,
        ..Limits::default()
    };
    let pipeline = Pipeline::new(limits, cfg.stdout);
    let shared = Arc::new(Shared {
        service: cfg.service.clone(),
        service_version: cfg.service_version.clone(),
        app_session_id: app_session_id.clone(),
        pipeline: pipeline.clone(),
        crash_dir: cfg.log_root.as_ref().map(|r| r.join("crash")),
        open_spans: Mutex::new(HashMap::new()),
    });

    // Files: recovery before cleanup (04 §1.3), disk guard.
    let mut startup: Vec<Record> = Vec::new();
    let mut file = None;
    if let Some(root) = &cfg.log_root {
        let dir = root.join(cfg.service_dir.as_deref().unwrap_or(&cfg.service));
        let crash_dir = root.join("crash");
        let free = std::fs::create_dir_all(&dir)
            .ok()
            .and_then(|_| free_bytes(&dir));
        if free.is_some_and(|b| b < files::MIN_FREE_BYTES) {
            startup.push(
                shared
                    .record(Kind::Log, Level::Warn, "diag.sink.unavailable")
                    .attr("reason", Value::Str("low_disk".into())),
            );
        } else {
            let start = Utc::now().format("%Y-%m-%dT%H-%M-%SZ").to_string();
            match FileSink::open(&dir, &start, &app_session_id, producer) {
                Ok(sink) => {
                    for rec in recover(&dir, &crash_dir, producer, Some(sink.key())) {
                        if !embedded {
                            startup.push(
                                shared
                                    .record(Kind::Log, Level::Warn, "app.previous_exit_unclean")
                                    .attr("previous_app_session_id", Value::Str(rec.app_session_id))
                                    .attr("crash_record", Value::Bool(rec.exit == Exit::Crash))
                                    .attr("open_operations", Value::StrList(rec.open_operations)),
                            );
                        }
                    }
                    let report = sink.cleanup();
                    for k in report.unknown_runs {
                        startup.push(
                            shared
                                .record(Kind::Log, Level::Warn, "diag.sink.degraded")
                                .attr("reason", Value::Str("ownership_unknown".into()))
                                .attr(
                                    "run",
                                    Value::Str(format!(
                                        "{}_{}.{}",
                                        k.start, k.app_session_id, k.producer
                                    )),
                                ),
                        );
                    }
                    file = Some(sink);
                }
                Err(e) => {
                    startup.push(
                        shared
                            .record(Kind::Log, Level::Warn, "diag.sink.unavailable")
                            .attr("reason", Value::Str(format!("open_failed: {e}"))),
                    );
                }
            }
        }
    }
    for s in &mut startup {
        if s.error.is_none() && s.level >= Level::Warn {
            s.error = Some(ErrorInfo {
                kind: s.event.rsplit('.').next().unwrap_or("diag").into(),
                ..Default::default()
            });
        }
    }

    let writer = {
        let sh = shared.clone();
        let make = Box::new(move |level: Level, event: &str| {
            let mut r = sh.record(Kind::Log, level, event);
            if level >= Level::Warn {
                r.error = Some(ErrorInfo {
                    kind: event.rsplit('.').next().unwrap_or("diag").into(),
                    ..Default::default()
                });
            }
            r
        });
        let w = Writer::new(pipeline.clone(), file, Box::new(io::stdout()), make);
        std::thread::Builder::new()
            .name("idr-telemetry-writer".into())
            .spawn(move || w.run())
            .map_err(InitError::Io)?
    };

    // app.started first, then recovery/cleanup findings, then deprecations.
    let mut started = shared
        .record(Kind::Log, Level::Info, "app.started")
        .attr("os.type", Value::Str(std::env::consts::OS.into()))
        // ponytail: OS version needs per-OS APIs; Dart side reports it. Add when an investigation needs it.
        .attr("os.version", Value::Str("unknown".into()))
        .attr("host.arch", Value::Str(std::env::consts::ARCH.into()))
        .attr("process.pid", Value::U64(std::process::id() as u64))
        .attr("telemetry.schema_version", Value::Str(crate::SCHEMA.into()));
    if let Some(p) = &cfg.parent_app_session_id {
        started = started.attr("parent_app_session_id", Value::Str(p.clone()));
    }
    shared.emit(started);
    for r in startup {
        shared.emit(r);
    }
    for key in deprecated {
        let mut r = shared
            .record(Kind::Log, Level::Warn, "telemetry.config.deprecated")
            .attr("key", Value::Str((*key).into()));
        r.error = Some(ErrorInfo {
            kind: "deprecated_config".into(),
            ..Default::default()
        });
        shared.emit(r);
    }

    if cfg.install_panic_hook {
        install_panic_hook(shared.clone());
    }
    let prefixes = cfg.recorder_prefixes.clone();
    let layer = layer::IdrLayer::new(
        shared.clone(),
        pipeline,
        directives,
        cfg.recorder_bytes > 0,
        prefixes,
    );
    let subscriber = tracing_subscriber::registry().with(layer);
    Ok((
        TelemetryGuard {
            shared,
            writer: Some(writer),
            reason: "exit",
        },
        subscriber,
    ))
}

// ---------------------------------------------------------------- current context

fn with_current_span<R>(f: impl FnOnce(&layer::SpanData) -> R) -> Option<R> {
    tracing::Span::current()
        .with_subscriber(|(id, dispatch)| {
            let reg = dispatch.downcast_ref::<tracing_subscriber::Registry>()?;
            let span = reg.span(id)?;
            let ext = span.extensions();
            ext.get::<layer::SpanData>().map(f)
        })
        .flatten()
}

/// The current span's W3C context, for propagation (HTTP header, env).
pub fn current() -> Option<TraceContext> {
    with_current_span(|d| d.context())
}

/// The full local context (`ctx_json`) for FFI, isolates and IPC.
pub fn current_ctx() -> LocalContext {
    with_current_span(|d| LocalContext {
        trace: Some(d.context()),
        session_id: d.session_id().map(String::from),
        operation_id: d.operation_id().map(String::from),
        transfer_id: d.transfer_id().map(String::from),
    })
    .unwrap_or_default()
}

/// Drains the flight recorder and waits until it is on disk (bundle builds).
pub fn flush_and_wait(timeout: Duration) -> bool {
    SHARED
        .get()
        .is_some_and(|s| s.pipeline.flush_and_wait(timeout))
}

// ---------------------------------------------------------------- crashes and FFI

thread_local! {
    static FFI_FN: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

fn install_panic_hook(shared: Arc<Shared>) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        write_crash(&shared, info);
        previous(info);
    }));
}

fn write_crash(shared: &Shared, info: &std::panic::PanicHookInfo<'_>) {
    let message = info
        .payload()
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| info.payload().downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "panic".into());
    let location = info
        .location()
        .map(|l| format!("{}:{}", l.file(), l.line()))
        .unwrap_or_default();
    let thread = std::thread::current()
        .name()
        .unwrap_or("unnamed")
        .to_string();
    let ffi_fn = FFI_FN.with(|f| f.get());
    let open: Vec<String> = shared
        .open_spans
        .try_lock()
        .map(|m| {
            m.values()
                .map(|s| format!("{} {} {}", s.name, s.trace_id, s.span_id))
                .collect()
        })
        .unwrap_or_default();
    let event = if ffi_fn.is_some() {
        "ffi.panic"
    } else {
        "app.crashed"
    };
    let mut r = shared.record(Kind::Crash, Level::Fatal, event);
    r.error = Some(ErrorInfo {
        kind: "panic".into(),
        message: Some(message.clone()),
        stack: Some(std::backtrace::Backtrace::force_capture().to_string()),
        ..Default::default()
    });
    r.attrs.push(("panic.message".into(), Value::Str(message)));
    r.attrs
        .push(("panic.location".into(), Value::Str(location)));
    r.attrs.push(("thread".into(), Value::Str(thread)));
    if let Some(f) = ffi_fn {
        r.attrs.push(("ffi.fn".into(), Value::Str(f.into())));
    }
    r.attrs
        .push(("open_operations".into(), Value::StrList(open)));
    r.attrs.push((
        "ring".into(),
        Value::StrList(shared.pipeline.ring_tail(200)),
    ));
    r.redact_in_place();
    // Crash record: synchronous write, own file, bigger cap.
    if let Some(dir) = &shared.crash_dir {
        let _ = std::fs::create_dir_all(dir);
        let name = format!(
            "{}_{}.crash.json",
            shared.app_session_id,
            Utc::now().format("%Y-%m-%dT%H-%M-%S%.6fZ")
        );
        let line = r.to_capped_line(MAX_CRASH_BYTES);
        let _ = std::fs::write(dir.join(name), line);
    }
    // FATAL in the log too (best effort, bounded wait).
    let mut log = r.clone();
    log.kind = Kind::Log;
    log.attrs.retain(|(k, _)| k != "ring");
    shared.emit(log);
    shared.pipeline.sync(Duration::from_millis(500));
}

/// True once any FFI export has panicked; the engine then fails fast (04 §3.1).
pub fn is_poisoned() -> bool {
    POISONED.load(Ordering::Acquire)
}

/// Wraps every `extern "C"` export: no panic crosses the ABI. A panic writes a crash
/// record (via the hook), poisons the engine and returns `on_panic`; later calls return
/// `on_panic` immediately.
pub fn ffi_guard<R>(ffi_fn: &'static str, on_panic: R, f: impl FnOnce() -> R) -> R {
    if POISONED.load(Ordering::Acquire) {
        if let Some(s) = SHARED
            .get()
            .filter(|_| !POISON_REPORTED.swap(true, Ordering::AcqRel))
        {
            let mut r = s
                .record(Kind::Log, Level::Warn, "ffi.engine_poisoned")
                .attr("ffi.fn", Value::Str(ffi_fn.into()));
            r.error = Some(ErrorInfo {
                kind: "engine_poisoned".into(),
                ..Default::default()
            });
            s.emit(r);
        }
        return on_panic;
    }
    ffi_catch(ffi_fn, on_panic, f)
}

/// [`ffi_guard`] without the fail-fast check, for exports that must keep working after a
/// panic so the host can find out what happened (`idr_last_error_*`, ABI version, frees).
pub fn ffi_catch<R>(ffi_fn: &'static str, on_panic: R, f: impl FnOnce() -> R) -> R {
    let prev = FFI_FN.with(|c| c.replace(Some(ffi_fn)));
    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    FFI_FN.with(|c| c.set(prev));
    match out {
        Ok(v) => v,
        Err(_) => {
            POISONED.store(true, Ordering::Release);
            on_panic
        }
    }
}

static POISONED: AtomicBool = AtomicBool::new(false);
static POISON_REPORTED: AtomicBool = AtomicBool::new(false);
