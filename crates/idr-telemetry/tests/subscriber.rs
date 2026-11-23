//! Subscriber tests: golden records, layer semantics, storage ownership and recovery,
//! recorder drain (review findings R2-3a/b/c), memory caps. docs/observability/07 §2.
#![cfg(feature = "subscriber")]

use idr_telemetry::*;
use serde_json::Value as J;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

fn vectors(name: &str) -> J {
    let path = format!(
        "{}/../../spec/telemetry/vectors/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap()
}

fn lines(dir: &Path) -> Vec<J> {
    let mut files: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .collect();
    files.sort();
    files
        .iter()
        .flat_map(|p| {
            fs::read_to_string(p)
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect::<Vec<J>>()
        })
        .collect()
}

fn events<'a>(all: &'a [J], name: &str) -> Vec<&'a J> {
    all.iter().filter(|r| r["event"] == name).collect()
}

// ------------------------------------------------------------------ golden records

#[test]
fn golden_record_vectors() {
    for c in vectors("records.json")["cases"].as_array().unwrap() {
        let r = &c["record"];
        let kind = match r["kind"].as_str().unwrap() {
            "span" => Kind::Span,
            "crash" => Kind::Crash,
            _ => Kind::Log,
        };
        let mut rec = Record::new(
            kind,
            Level::parse(r["level"].as_str().unwrap()).unwrap(),
            r["event"].as_str().unwrap(),
        );
        let s = |k: &str| r[k].as_str().map(String::from);
        rec.ts = s("ts").unwrap();
        rec.seq = r["seq"].as_u64().unwrap();
        rec.msg = s("msg");
        rec.service = s("service").unwrap();
        rec.service_version = s("service_version").unwrap();
        rec.component = s("component").unwrap();
        rec.app_session_id = s("app_session_id").unwrap();
        rec.trace_id = s("trace_id");
        rec.span_id = s("span_id");
        rec.parent_span_id = s("parent_span_id");
        rec.start_ts = s("start_ts");
        rec.duration_ms = r["duration_ms"].as_f64();
        rec.status = r["status"]
            .as_str()
            .map(|v| if v == "ok" { "ok" } else { "error" });
        rec.session_id = s("session_id");
        rec.connection_id = s("connection_id");
        fn err(e: &J) -> ErrorInfo {
            ErrorInfo {
                kind: e["type"].as_str().unwrap().into(),
                message: e["message"].as_str().map(String::from),
                code: e["code"].as_i64(),
                stack: e["stack"].as_str().map(String::from),
                cause: e.get("cause").map(|c| Box::new(err(c))),
            }
        }
        rec.error = r.get("error").map(err);
        for a in r["attrs"].as_array().unwrap() {
            let v = match &a[1] {
                J::String(x) => Value::Str(x.clone()),
                J::Bool(b) => Value::Bool(*b),
                J::Array(l) => {
                    Value::StrList(l.iter().map(|x| x.as_str().unwrap().to_string()).collect())
                }
                n => Value::I64(n.as_i64().unwrap()),
            };
            rec.attrs.push((a[0].as_str().unwrap().into(), v));
        }
        rec.redact_in_place();
        let line = with_flushed(&rec.to_line(), r["flushed"].as_bool().unwrap_or(false));
        assert_eq!(line, c["line"].as_str().unwrap(), "case {}", c["name"]);
    }
}

fn with_flushed(line: &str, flushed: bool) -> String {
    if flushed {
        format!("{},\"flushed\":true}}", &line[..line.len() - 1])
    } else {
        line.to_string()
    }
}

#[test]
fn oversized_records_are_trimmed_then_replaced() {
    let mut r = Record::new(Kind::Log, Level::Warn, "agent.process.exited");
    r.ts = "2026-11-21T10:41:03.000001Z".into();
    r.service = "s".into();
    r.service_version = "1".into();
    r.component = "c".into();
    r.app_session_id = new_id();
    r.error = Some(ErrorInfo {
        kind: "signal".into(),
        stack: Some("frame\n".repeat(500)),
        ..Default::default()
    });
    r.attrs.push((
        "stderr_tail".into(),
        Value::StrList(vec!["x".repeat(3000); 5]),
    ));
    let line = r.to_capped_line(MAX_RECORD_BYTES);
    assert!(line.len() <= MAX_RECORD_BYTES, "{}", line.len());
    assert!(
        line.contains("agent.process.exited"),
        "trimmed, not replaced"
    );

    let mut big = Record::new(Kind::Log, Level::Info, "x.y");
    big.app_session_id = new_id();
    big.attrs = (0..400).map(|i| (format!("k{i}"), Value::I64(i))).collect();
    let line = big.to_capped_line(1024);
    assert!(
        line.contains("diag.record.oversized") && line.len() <= 1024,
        "{line}"
    );
}

// ------------------------------------------------------------------ layer

fn test_cfg(root: &Path) -> Config {
    let mut c = Config::new("idrs", "1.0.0");
    c.log_root = Some(root.into());
    c.stdout = StdoutFormat::Off;
    c.install_panic_hook = false;
    c.recorder_prefixes = vec!["subscriber".into(), "idr".into()];
    c
}

#[test]
fn spans_events_and_correlation_inheritance() {
    let tmp = tempfile::tempdir().unwrap();
    let (guard, sub) = build(test_cfg(tmp.path()), &[]).unwrap();
    let session = new_id();
    let remote =
        TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").unwrap();
    let mut ctx_seen = LocalContext::default();
    tracing::subscriber::with_default(sub, || {
        let root = tracing::info_span!("source.connect", traceparent = %remote.to_traceparent(), session_id = %session, persist_start = true, target.fqhn = "gpu--acme.idr.to");
        let _g = root.enter();
        let attempt = tracing::info_span!("source.connect.attempt", retry.attempt = 1u64);
        let _a = attempt.enter();
        tracing::warn!(event = "connection.attempt.failed", error.type = "ice_failed", phase = "ice", elapsed_ms = 30012u64, "ICE failed for bob@example.com");
        ctx_seen = current_ctx();
    });
    drop(guard);
    let all = lines(&tmp.path().join("idrs"));
    for r in &all {
        assert_eq!(r["schema"], "idr.log/1");
    }
    let failed = events(&all, "connection.attempt.failed")[0];
    assert_eq!(
        failed["trace_id"],
        remote.trace_id_hex(),
        "remote parent adopted and inherited"
    );
    assert_eq!(
        failed["session_id"],
        session.as_str(),
        "correlation inherited from root span"
    );
    assert_eq!(failed["error"]["type"], "ice_failed");
    assert_eq!(failed["msg"], "ICE failed for [REDACTED EMAIL]");
    let attempt = events(&all, "source.connect.attempt")[0];
    let root = events(&all, "source.connect")[0];
    assert_eq!(attempt["kind"], "span");
    assert_eq!(attempt["parent_span_id"], root["span_id"]);
    assert_eq!(root["parent_span_id"], remote.span_id_hex());
    assert_eq!(failed["span_id"], attempt["span_id"]);
    assert_eq!(root["attrs"]["target.fqhn"], "gpu--acme.idr.to");
    let started = events(&all, "source.connect.started");
    assert_eq!(started.len(), 1, "persist_start writes a start record");
    assert_eq!(started[0]["span_id"], root["span_id"]);
    assert_eq!(ctx_seen.session_id.as_deref(), Some(session.as_str()));
    assert_eq!(ctx_seen.trace.unwrap().trace_id, remote.trace_id);
    assert_eq!(
        all.last().unwrap()["event"],
        "app.stopping",
        "app.stopping is the final record"
    );
    assert_eq!(all[0]["event"], "app.started");
}

#[test]
fn concurrent_operations_do_not_mix_ids() {
    let tmp = tempfile::tempdir().unwrap();
    let (guard, sub) = build(test_cfg(tmp.path()), &[]).unwrap();
    let dispatch = tracing::Dispatch::new(sub);
    let handles: Vec<_> = (0..16)
        .map(|_| {
            let d = dispatch.clone();
            std::thread::spawn(move || {
                let session = new_id();
                tracing::dispatcher::with_default(&d, || {
                    let s = tracing::info_span!("source.connect", session_id = %session);
                    let _e = s.enter();
                    for i in 0..50u64 {
                        tracing::info!(
                            event = "stream.opened",
                            stream.id = i,
                            service.name = "ollama"
                        );
                    }
                });
                session
            })
        })
        .collect();
    let sessions: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    drop(guard);
    let all = lines(&tmp.path().join("idrs"));
    let opened = events(&all, "stream.opened");
    assert_eq!(opened.len(), 16 * 50);
    let spans = events(&all, "source.connect");
    for s in &sessions {
        let span = spans
            .iter()
            .find(|r| r["session_id"] == s.as_str())
            .unwrap();
        let mine: Vec<_> = opened
            .iter()
            .filter(|r| r["session_id"] == s.as_str())
            .collect();
        assert_eq!(mine.len(), 50);
        assert!(mine
            .iter()
            .all(|r| r["trace_id"] == span["trace_id"] && r["span_id"] == span["span_id"]));
    }
}

// ------------------------------------------------------------------ storage

fn touch(dir: &Path, name: &str, body: &str, age: Duration) {
    let p = dir.join(name);
    fs::write(&p, body).unwrap();
    let f = fs::File::options().write(true).open(&p).unwrap();
    f.set_modified(SystemTime::now() - age).unwrap();
}

const START: &str = "2026-11-01T10-00-00Z";

#[test]
fn retention_never_deletes_an_active_runs_open_segment_even_when_idle() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let id = new_id();
    let owner = FileSink::open(dir, START, &id, "jsonl").unwrap(); // a live (idle) process
    let old = Duration::from_secs(30 * 24 * 3600);
    touch(dir, &format!("{START}_{id}_000.jsonl"), "{}\n", old);
    touch(dir, &format!("{START}_{id}_001.jsonl"), "{}\n", old);
    touch(dir, &format!("{START}_{id}_002.jsonl"), "{}\n", old); // highest = open
    let report = cleanup(
        dir,
        "jsonl",
        None,
        0,
        Duration::from_secs(1),
        SystemTime::now(),
    );
    assert_eq!(report.deleted.len(), 2, "{:?}", report.deleted);
    assert!(
        dir.join(format!("{START}_{id}_002.jsonl")).exists(),
        "open segment of an idle owner survives"
    );
    assert_eq!(run_state(dir, owner.key()), RunState::Active);
}

#[test]
fn unknown_ownership_deletes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let id = new_id();
    let old = Duration::from_secs(30 * 24 * 3600);
    touch(dir, &format!("{START}_{id}_000.jsonl"), "{}\n", old); // no lock file at all
    let report = cleanup(
        dir,
        "jsonl",
        None,
        0,
        Duration::from_secs(1),
        SystemTime::now(),
    );
    assert!(report.deleted.is_empty());
    assert_eq!(report.unknown_runs.len(), 1);
}

#[test]
fn other_producers_runs_are_never_touched() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let id = new_id();
    let old = Duration::from_secs(30 * 24 * 3600);
    fs::write(dir.join(format!("{START}_{id}.jsonl.lock")), "").unwrap(); // a Dart run
    fs::write(dir.join(format!("{START}_{id}.jsonl.ended")), "{}").unwrap();
    touch(dir, &format!("{START}_{id}_000.jsonl"), "{}\n", old);
    let report = cleanup(
        dir,
        "rust.jsonl",
        None,
        0,
        Duration::from_secs(1),
        SystemTime::now(),
    );
    assert!(report.deleted.is_empty() && report.unknown_runs.is_empty());
}

#[test]
fn recovery_is_per_run_claimed_once_and_never_reports_live_or_clean_runs() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("idrs");
    let crash = tmp.path().join("crash");
    fs::create_dir_all(&dir).unwrap();
    let rec = |event: &str| {
        format!("{{\"kind\":\"log\",\"event\":\"{event}\",\"span_id\":\"a1b2c3d4e5f60718\"}}\n")
    };

    // Live process with rotated segments (none contains app.stopping): not reported.
    let live = new_id();
    let _owner = FileSink::open(&dir, START, &live, "jsonl").unwrap();
    for n in 1..=5 {
        touch(
            &dir,
            &format!("{START}_{live}_{n:03}.jsonl"),
            &rec("stream.opened"),
            Duration::ZERO,
        );
    }
    // Killed process: lock released, last segment without app.stopping, an open operation.
    let killed = new_id();
    drop(FileSink::open(&dir, START, &killed, "jsonl").unwrap());
    touch(
        &dir,
        &format!("{START}_{killed}_000.jsonl"),
        &rec("transfer.send.started"),
        Duration::ZERO,
    );
    // Clean process.
    let clean = new_id();
    drop(FileSink::open(&dir, START, &clean, "jsonl").unwrap());
    touch(
        &dir,
        &format!("{START}_{clean}_000.jsonl"),
        &rec("app.stopping"),
        Duration::ZERO,
    );
    // Crashed process (crash record present even though app.stopping was written).
    let crashed = new_id();
    drop(FileSink::open(&dir, START, &crashed, "jsonl").unwrap());
    touch(
        &dir,
        &format!("{START}_{crashed}_000.jsonl"),
        &rec("app.stopping"),
        Duration::ZERO,
    );
    fs::create_dir_all(&crash).unwrap();
    fs::write(
        crash.join(format!("{crashed}_2026-11-01T10-01-00.000000Z.crash.json")),
        "{}",
    )
    .unwrap();

    // Two processes starting together: exactly one claims each run.
    let (a, b) = std::thread::scope(|s| {
        let a = s.spawn(|| recover(&dir, &crash, "jsonl", None));
        let b = s.spawn(|| recover(&dir, &crash, "jsonl", None));
        (a.join().unwrap(), b.join().unwrap())
    });
    let all: Vec<_> = a.iter().chain(b.iter()).collect();
    assert_eq!(all.len(), 2, "{all:?}");
    let k = all.iter().find(|r| r.app_session_id == killed).unwrap();
    assert_eq!(k.exit, Exit::Unclean);
    assert_eq!(k.open_operations, vec!["transfer.send".to_string()]);
    assert_eq!(
        all.iter()
            .find(|r| r.app_session_id == crashed)
            .unwrap()
            .exit,
        Exit::Crash
    );
    assert!(all
        .iter()
        .all(|r| r.app_session_id != live && r.app_session_id != clean));
    assert!(
        recover(&dir, &crash, "jsonl", None).is_empty(),
        "claimed once"
    );
    assert!(dir.join(format!("{START}_{clean}.jsonl.ended")).exists());
}

// ------------------------------------------------------------------ recorder drain

struct Harness {
    pipeline: Arc<Pipeline>,
    dir: tempfile::TempDir,
    id: String,
}

impl Harness {
    fn new(queue_bytes: usize) -> Self {
        let limits = Limits {
            queue_bytes,
            drain_pacing: Duration::ZERO,
            ..Limits::default()
        };
        Self {
            pipeline: Pipeline::new(limits, StdoutFormat::Off),
            dir: tempfile::tempdir().unwrap(),
            id: new_id(),
        }
    }

    fn rec(&self, level: Level, event: &str, trace: &str) -> Record {
        let mut r = Record::new(Kind::Log, level, event);
        r.ts = format_ts(chrono::Utc::now());
        r.service = "t".into();
        r.service_version = "1".into();
        r.component = "c".into();
        r.app_session_id = self.id.clone();
        r.trace_id = Some(trace.into());
        if level >= Level::Warn {
            r.error = Some(ErrorInfo {
                kind: "x".into(),
                ..Default::default()
            });
        }
        r
    }

    fn submit(&self, level: Level, event: &str, trace: &str) {
        let out = level >= Level::Info;
        self.pipeline.submit(
            self.rec(level, event, trace),
            Route {
                to_ring: true,
                to_file: out,
                to_stdout: false,
            },
        );
    }

    /// Starts the writer only now, so everything submitted so far is queued (or dropped).
    fn start(&self) -> std::thread::JoinHandle<()> {
        let sink = FileSink::open(self.dir.path(), START, &self.id, "jsonl").unwrap();
        let w = Writer::new(
            self.pipeline.clone(),
            Some(sink),
            Box::new(std::io::sink()),
            Box::new(|l, e| Record::new(Kind::Log, l, e)),
        );
        std::thread::spawn(move || w.run())
    }

    fn stop(&self, h: std::thread::JoinHandle<()>) -> Vec<J> {
        let mut stop = self.rec(Level::Info, "app.stopping", "t0");
        stop.trace_id = None;
        assert!(self.pipeline.shutdown(stop, Duration::from_secs(5)));
        h.join().unwrap();
        lines(self.dir.path())
    }
}

const T1: &str = "11111111111111111111111111111111";
const T2: &str = "22222222222222222222222222222222";

fn count(all: &[J], event: &str) -> usize {
    events(all, event).len()
}

#[test]
fn triggering_error_survives_a_full_queue_and_info_is_not_duplicated() {
    let h = Harness::new(1500); // ~3 records: the rest, and the ERROR, are dropped
    h.submit(Level::Debug, "webrtc.ice.candidate_gathered", T1);
    for _ in 0..8 {
        h.submit(Level::Info, "stream.opened", T1); // fills the queue; later ones dropped
    }
    h.submit(Level::Error, "connection.attempt.failed", T1); // dropped by the queue
    let w = h.start();
    let all = h.stop(w);
    let err = events(&all, "connection.attempt.failed");
    assert_eq!(err.len(), 1, "trigger written exactly once");
    assert_eq!(
        err[0]["flushed"], true,
        "recovered by the drain, not the queue"
    );
    assert_eq!(count(&all, "webrtc.ice.candidate_gathered"), 1);
    assert_eq!(
        count(&all, "stream.opened"),
        8,
        "each INFO exactly once (queued ones normal, dropped ones flushed)"
    );
    let infos = events(&all, "stream.opened");
    assert!(
        infos.iter().any(|r| r["flushed"] == true) && infos.iter().any(|r| r["flushed"].is_null()),
        "both paths exercised"
    );
    let mut seqs: Vec<u64> = all.iter().map(|r| r["seq"].as_u64().unwrap()).collect();
    seqs.sort();
    seqs.dedup();
    assert_eq!(seqs.len(), all.len(), "no record written twice");
}

#[test]
fn records_after_the_watermark_stay_for_a_later_drain() {
    // Trigger A at watermark w; records w+1.. arrive before the split; trigger B recovers them.
    let h = Harness::new(1024 * 1024);
    h.submit(Level::Debug, "before.a", T1);
    h.submit(Level::Error, "trigger.a", T1);
    for _ in 0..3 {
        h.submit(Level::Debug, "after.a", T2); // seq > watermark(A), before the split
    }
    let w = h.start();
    assert!(h.pipeline.sync(Duration::from_secs(5)));
    h.submit(Level::Error, "trigger.b", T2);
    assert!(h.pipeline.flush_and_wait(Duration::from_secs(5)));
    let all = h.stop(w);
    assert_eq!(count(&all, "before.a"), 1);
    assert_eq!(
        count(&all, "after.a"),
        3,
        "not lost when A's snapshot was freed"
    );
    assert!(events(&all, "after.a").iter().all(|r| r["flushed"] == true));
}

#[test]
fn many_triggers_merge_into_one_drain_and_bundles_wait_for_it() {
    let h = Harness::new(1024 * 1024);
    for i in 0..5 {
        h.submit(Level::Debug, "detail", T1);
        h.submit(
            Level::Error,
            &format!("failure.n{i}"),
            &format!("{:032x}", i + 1),
        );
    }
    let w = h.start();
    assert!(
        h.pipeline.flush_and_wait(Duration::from_secs(5)),
        "bundle request completes after its drain"
    );
    let all = h.stop(w);
    assert_eq!(
        count(&all, "detail"),
        5,
        "each DEBUG once: merged triggers, no duplicate drains"
    );
}

#[test]
fn memory_stays_within_byte_caps() {
    let limits = Limits {
        queue_bytes: 64 * 1024,
        ring_bytes: 128 * 1024,
        ..Limits::default()
    };
    let p = Pipeline::new(limits, StdoutFormat::Off);
    for i in 0..2000 {
        let mut r = Record::new(Kind::Log, Level::Info, "stream.opened");
        r.app_session_id = new_id();
        r.attrs
            .push(("blob".into(), Value::Str(format!("{i}").repeat(3000))));
        p.submit(
            r,
            Route {
                to_ring: true,
                to_file: true,
                to_stdout: false,
            },
        );
        let (q, ring) = p.byte_usage();
        assert!(q <= 64 * 1024 && ring <= 128 * 1024, "q={q} ring={ring}");
    }
}
