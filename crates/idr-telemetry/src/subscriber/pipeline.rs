//! Producer → writer pipeline: byte-capped queue (drop incoming), byte-capped flight
//! recorder ring (evict oldest), and the writer-controlled drain (04 §2.1, §6).
//!
//! One `State` mutex orders `seq` assignment, ring pushes and queue pushes, so the ring and
//! the queue are both sorted by `seq` and a drain can reason with a watermark.

use super::files::FileSink;
use super::record::{format_ts, with_tail, Kind, Level, Record, Value, MAX_RECORD_BYTES};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StdoutFormat {
    Json,
    Pretty,
    Off,
}

/// A finished record, shared by the ring and the queue. `persisted` is set only by the
/// writer after the bytes went to the file — never inferred from severity.
pub struct Entry {
    pub seq: u64,
    pub level: Level,
    pub trace_id: Option<String>,
    pub session_id: Option<String>,
    pub at: Instant,
    pub line: String,
    pub pretty: Option<String>,
    pub to_file: bool,
    pub to_stdout: bool,
    pub persisted: AtomicBool,
}

impl Entry {
    fn bytes(&self) -> usize {
        self.line.len() + 64
    }
}

#[derive(Default)]
struct FlushReq {
    watermark: u64,
    traces: HashSet<String>,
    sessions: HashSet<String>,
    triggers: Vec<Arc<Entry>>,
    done: Vec<mpsc::Sender<()>>,
}

enum Msg {
    Record(Arc<Entry>, u64),
    FlushToken,
    Sync(mpsc::Sender<()>),
    Shutdown(Box<Record>, mpsc::Sender<()>),
}

#[derive(Default)]
struct State {
    seq: u64,
    ring: VecDeque<Arc<Entry>>,
    ring_bytes: usize,
    queue: VecDeque<Msg>,
    queue_bytes: usize,
    dropped: u64,
    dropped_bytes: u64,
    ring_evicted_unflushed: u64,
    pending: Option<FlushReq>,
    last_trigger: HashMap<String, Instant>,
    closed: bool,
}

pub struct Limits {
    pub queue_bytes: usize,
    pub ring_bytes: usize,
    pub drain_pacing: Duration,
    pub trigger_debounce: Duration,
    pub drain_window: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            queue_bytes: 1024 * 1024,
            ring_bytes: 3 * 1024 * 1024,
            drain_pacing: Duration::from_secs(1),
            trigger_debounce: Duration::from_secs(30),
            drain_window: Duration::from_secs(60),
        }
    }
}

pub struct Pipeline {
    state: Mutex<State>,
    cv: Condvar,
    pub limits: Limits,
    pub stdout: StdoutFormat,
}

/// Decision about one record, made by the caller (the layer).
pub struct Route {
    pub to_ring: bool,
    pub to_file: bool,
    pub to_stdout: bool,
}

impl Pipeline {
    pub fn new(limits: Limits, stdout: StdoutFormat) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::default()),
            cv: Condvar::new(),
            limits,
            stdout,
        })
    }

    /// Redacts, caps, sequences and routes a record. Never blocks on I/O.
    pub fn submit(&self, mut rec: Record, route: Route) {
        if !(route.to_ring || route.to_file || route.to_stdout) {
            return;
        }
        rec.redact_in_place();
        let pretty_wanted = route.to_stdout && self.stdout == StdoutFormat::Pretty;
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.closed {
            return;
        }
        rec.seq = st.seq;
        st.seq += 1;
        let line = rec.to_capped_line(MAX_RECORD_BYTES);
        let entry = Arc::new(Entry {
            seq: rec.seq,
            level: rec.level,
            trace_id: rec.trace_id.clone(),
            session_id: rec.session_id.clone(),
            at: Instant::now(),
            pretty: pretty_wanted.then(|| pretty(&rec)),
            line,
            to_file: route.to_file,
            to_stdout: route.to_stdout,
            persisted: AtomicBool::new(false),
        });
        if route.to_ring && entry.level >= Level::Debug && self.limits.ring_bytes > 0 {
            st.ring_bytes += entry.bytes();
            st.ring.push_back(entry.clone());
            while st.ring_bytes > self.limits.ring_bytes {
                let Some(old) = st.ring.pop_front() else {
                    break;
                };
                st.ring_bytes -= old.bytes();
                let pending_wm = st.pending.as_ref().map(|p| p.watermark);
                if pending_wm.is_some_and(|w| old.seq <= w)
                    && !old.persisted.load(Ordering::Acquire)
                {
                    st.ring_evicted_unflushed += 1;
                }
            }
        }
        if route.to_file || route.to_stdout {
            if st.queue_bytes + entry.bytes() <= self.limits.queue_bytes {
                st.queue_bytes += entry.bytes();
                st.queue.push_back(Msg::Record(entry.clone(), 0));
            } else {
                st.dropped += 1; // drop incoming (04 §6); stays persisted=false for a drain
                st.dropped_bytes += entry.bytes() as u64;
            }
        }
        let trigger = rec.level >= Level::Error
            || rec.event.ends_with(".stalled")
            || rec.event.ends_with(".timed_out");
        if trigger && rec.kind == Kind::Log {
            self.trigger_locked(&mut st, Some(entry), None);
        }
        drop(st);
        self.cv.notify_one();
    }

    /// Requests a drain (bundle builds pass `done`). Debounced per trace for errors.
    fn trigger_locked(
        &self,
        st: &mut State,
        trigger: Option<Arc<Entry>>,
        done: Option<mpsc::Sender<()>>,
    ) {
        if let (Some(t), None) = (&trigger, &done) {
            if let Some(tr) = &t.trace_id {
                let now = Instant::now();
                if st
                    .last_trigger
                    .get(tr)
                    .is_some_and(|at| now.duration_since(*at) < self.limits.trigger_debounce)
                {
                    return;
                }
                st.last_trigger.insert(tr.clone(), now);
            }
        }
        let watermark = st.seq.saturating_sub(1);
        let new = st.pending.is_none();
        let req = st.pending.get_or_insert_with(FlushReq::default);
        req.watermark = req.watermark.max(watermark);
        if let Some(t) = trigger {
            req.traces.extend(t.trace_id.clone());
            req.sessions.extend(t.session_id.clone());
            req.triggers.push(t);
        }
        req.done.extend(done);
        if new {
            st.queue.push_back(Msg::FlushToken); // control: exempt from the byte cap
        }
    }

    /// Drain now (e.g. before collecting a bundle). Returns when written and synced.
    pub fn flush_and_wait(&self, timeout: Duration) -> bool {
        let (tx, rx) = mpsc::channel();
        {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if st.closed {
                return false;
            }
            self.trigger_locked(&mut st, None, Some(tx));
        }
        self.cv.notify_one();
        rx.recv_timeout(timeout).is_ok()
    }

    /// Waits until every record submitted so far has been handled by the writer.
    pub fn sync(&self, timeout: Duration) -> bool {
        let (tx, rx) = mpsc::channel();
        {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if st.closed {
                return false;
            }
            st.queue.push_back(Msg::Sync(tx));
        }
        self.cv.notify_one();
        rx.recv_timeout(timeout).is_ok()
    }

    /// Writes remaining records, then `stopping` synchronously as the final record.
    pub fn shutdown(&self, mut stopping: Record, timeout: Duration) -> bool {
        let (tx, rx) = mpsc::channel();
        {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if st.closed {
                return false;
            }
            stopping.seq = st.seq;
            st.seq += 1;
            st.closed = true;
            st.queue.push_back(Msg::Shutdown(Box::new(stopping), tx));
        }
        self.cv.notify_one();
        rx.recv_timeout(timeout).is_ok()
    }

    /// Last `n` ring lines (crash records). Non-blocking: skipped if the lock is busy.
    pub fn ring_tail(&self, n: usize) -> Vec<String> {
        match self.state.try_lock() {
            Ok(st) => st
                .ring
                .iter()
                .rev()
                .take(n)
                .rev()
                .map(|e| e.line.clone())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn byte_usage(&self) -> (usize, usize) {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        (st.queue_bytes, st.ring_bytes)
    }
}

/// Builds a writer-originated record (e.g. `diag.records.dropped`).
pub type MakeRecord = Box<dyn Fn(Level, &str) -> Record + Send>;

/// Writer side. Owns the sinks; runs on its own thread.
pub struct Writer {
    pub pipeline: Arc<Pipeline>,
    pub file: Option<FileSink>,
    pub stdout: Box<dyn Write + Send>,
    /// Builds a `diag.records.dropped` record (the writer cannot sequence on its own).
    pub make_record: MakeRecord,
    last_drain_end: Option<Instant>,
    /// A token arrived inside the pacing window; the request stays pending until due.
    deferred: bool,
    last_cleanup: Instant,
    last_dropped_report: Option<Instant>,
}

impl Writer {
    pub fn new(
        pipeline: Arc<Pipeline>,
        file: Option<FileSink>,
        stdout: Box<dyn Write + Send>,
        make_record: MakeRecord,
    ) -> Self {
        Self {
            pipeline,
            file,
            stdout,
            make_record,
            last_drain_end: None,
            deferred: false,
            last_cleanup: Instant::now(),
            last_dropped_report: None,
        }
    }

    fn pacing_left(&self) -> Duration {
        self.last_drain_end.map_or(Duration::ZERO, |t| {
            self.pipeline
                .limits
                .drain_pacing
                .saturating_sub(t.elapsed())
        })
    }

    pub fn run(mut self) {
        loop {
            if self.deferred && self.pacing_left().is_zero() {
                self.deferred = false;
                self.drain();
            }
            let mut batch = Vec::new();
            {
                let p = self.pipeline.clone();
                let mut st = p.state.lock().unwrap_or_else(|e| e.into_inner());
                while st.queue.is_empty() {
                    let wait = if self.deferred {
                        self.pacing_left().max(Duration::from_millis(1))
                    } else {
                        Duration::from_millis(500)
                    };
                    let (g, _) =
                        p.cv.wait_timeout(st, wait)
                            .unwrap_or_else(|e| e.into_inner());
                    st = g;
                    if st.queue.is_empty() {
                        drop(st);
                        if self.deferred && self.pacing_left().is_zero() {
                            self.deferred = false;
                            self.drain();
                        }
                        self.housekeeping();
                        st = p.state.lock().unwrap_or_else(|e| e.into_inner());
                    }
                }
                while let Some(m) = st.queue.pop_front() {
                    let m = match m {
                        Msg::Record(e, _) => {
                            st.queue_bytes -= e.bytes();
                            let d = std::mem::take(&mut st.dropped);
                            Msg::Record(e, d)
                        }
                        other => other,
                    };
                    let stop = matches!(m, Msg::FlushToken | Msg::Shutdown(..));
                    batch.push(m);
                    if stop || batch.len() >= 256 {
                        break;
                    }
                }
            }
            for m in batch {
                match m {
                    Msg::Record(e, dropped) => {
                        if dropped > 0 {
                            self.report_dropped(dropped);
                        }
                        self.write_entry(&e, dropped, false);
                    }
                    Msg::FlushToken => self.drain(),
                    Msg::Sync(tx) => {
                        self.sync_sinks();
                        let _ = tx.send(());
                    }
                    Msg::Shutdown(stopping, tx) => {
                        self.finish(*stopping);
                        let _ = tx.send(());
                        return;
                    }
                }
            }
            if let Some(f) = &mut self.file {
                let _ = f.flush();
            }
            let _ = self.stdout.flush();
        }
    }

    fn housekeeping(&mut self) {
        if self.last_cleanup.elapsed() >= Duration::from_secs(3600) {
            self.last_cleanup = Instant::now();
            if let Some(f) = &self.file {
                let _ = f.cleanup();
            }
        }
    }

    fn report_dropped(&mut self, count: u64) {
        let due = self
            .last_dropped_report
            .is_none_or(|t| t.elapsed() >= Duration::from_secs(10));
        if !due {
            return;
        }
        self.last_dropped_report = Some(Instant::now());
        let bytes = {
            let mut st = self
                .pipeline
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut st.dropped_bytes)
        };
        let rec = (self.make_record)(Level::Warn, "diag.records.dropped")
            .attr("count", Value::U64(count))
            .attr("bytes", Value::U64(bytes))
            .attr("reason", Value::Str("queue_full".into()));
        self.write_direct(rec);
    }

    /// Writes a writer-originated record straight to the sinks (sequenced via the state).
    fn write_direct(&mut self, mut rec: Record) {
        {
            let mut st = self
                .pipeline
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            rec.seq = st.seq;
            st.seq += 1;
        }
        if rec.ts.is_empty() {
            rec.ts = format_ts(chrono::Utc::now());
        }
        rec.redact_in_place();
        let line = rec.to_capped_line(MAX_RECORD_BYTES);
        if let Some(f) = &mut self.file {
            if matches!(f.write_line(&line), Ok(true)) {
                let _ = f.cleanup();
            }
        }
        if self.pipeline.stdout != StdoutFormat::Off {
            let text = if self.pipeline.stdout == StdoutFormat::Pretty {
                pretty(&rec)
            } else {
                line
            };
            let _ = writeln!(self.stdout, "{text}");
        }
    }

    fn write_entry(&mut self, e: &Entry, dropped: u64, flushed: bool) {
        if e.to_file || flushed {
            if let Some(f) = &mut self.file {
                let line = with_tail(&e.line, dropped, flushed);
                // On a disk error the entry stays unpersisted.
                if let Ok(rotated) = f.write_line(&line) {
                    e.persisted.store(true, Ordering::Release);
                    if rotated {
                        let _ = f.cleanup();
                    }
                }
            }
        }
        if e.to_stdout && !flushed && self.pipeline.stdout != StdoutFormat::Off {
            let text = match &e.pretty {
                Some(p) => p.clone(),
                None => with_tail(&e.line, dropped, false),
            };
            let _ = writeln!(self.stdout, "{text}");
        }
    }

    /// The drain (04 §2.1): take the pending request, write queued records up to the
    /// watermark, split the ring at the watermark, write unpersisted records, free.
    fn drain(&mut self) {
        let p = self.pipeline.clone();
        let (req, pre, snapshot) = {
            let mut st = p.state.lock().unwrap_or_else(|e| e.into_inner());
            if !self.pacing_left().is_zero() {
                self.deferred = true; // the request stays pending; later triggers merge into it
                return;
            }
            let Some(req) = st.pending.take() else { return };
            // Everything enqueued up to the watermark is handled first on the normal path,
            // including interleaved Sync messages, so nothing <= watermark is still queued.
            let mut pre = Vec::new();
            loop {
                match st.queue.front() {
                    Some(Msg::Record(e, _)) if e.seq <= req.watermark => {}
                    Some(Msg::Sync(_)) => {}
                    _ => break,
                }
                match st.queue.pop_front() {
                    Some(Msg::Record(e, _)) => {
                        st.queue_bytes -= e.bytes();
                        let d = std::mem::take(&mut st.dropped);
                        pre.push(Msg::Record(e, d));
                    }
                    Some(other) => pre.push(other),
                    None => break,
                }
            }
            // Split: detach only seq <= watermark; later records stay in the live ring.
            let cut = st.ring.partition_point(|e| e.seq <= req.watermark);
            let tail = st.ring.split_off(cut);
            let snapshot = std::mem::replace(&mut st.ring, tail);
            st.ring_bytes = st.ring.iter().map(|e| e.bytes()).sum();
            let evicted = std::mem::take(&mut st.ring_evicted_unflushed);
            drop(st);
            if evicted > 0 {
                let rec = (self.make_record)(Level::Warn, "diag.records.dropped")
                    .attr("count", Value::U64(evicted))
                    .attr("bytes", Value::U64(0))
                    .attr("reason", Value::Str("ring_evicted_unflushed".into()));
                self.write_direct(rec);
            }
            (req, pre, snapshot)
        };
        for m in pre {
            match m {
                Msg::Record(e, d) => self.write_entry(&e, d, false),
                Msg::Sync(tx) => {
                    self.sync_sinks();
                    let _ = tx.send(());
                }
                Msg::FlushToken | Msg::Shutdown(..) => {}
            }
        }
        // Select unpersisted records; scope first, then the recent window; triggers always.
        let window_start = Instant::now().checked_sub(p.limits.drain_window);
        let in_scope = |e: &Entry| {
            e.trace_id.as_ref().is_some_and(|t| req.traces.contains(t))
                || e.session_id
                    .as_ref()
                    .is_some_and(|s| req.sessions.contains(s))
        };
        let unpersisted = |e: &Arc<Entry>| !e.persisted.load(Ordering::Acquire);
        let mut chosen: Vec<Arc<Entry>> = snapshot
            .iter()
            .filter(|e| unpersisted(e) && in_scope(e))
            .cloned()
            .collect();
        for t in &req.triggers {
            if unpersisted(t) && !chosen.iter().any(|c| Arc::ptr_eq(c, t)) {
                chosen.push(t.clone());
            }
        }
        chosen.sort_by_key(|e| e.seq);
        let rest: Vec<Arc<Entry>> = snapshot
            .iter()
            .filter(|e| unpersisted(e) && !in_scope(e) && window_start.is_none_or(|w| e.at >= w))
            .filter(|e| !chosen.iter().any(|c| Arc::ptr_eq(c, e)))
            .cloned()
            .collect();
        for e in chosen.iter().chain(rest.iter()) {
            self.write_entry(e, 0, true);
        }
        drop(snapshot);
        self.sync_sinks();
        self.last_drain_end = Some(Instant::now());
        for d in req.done {
            let _ = d.send(());
        }
    }

    fn sync_sinks(&mut self) {
        if let Some(f) = &mut self.file {
            let _ = f.sync();
        }
        let _ = self.stdout.flush();
    }

    fn finish(&mut self, stopping: Record) {
        // Everything still queued, then app.stopping as the very last record.
        let rest: Vec<Msg> = {
            let mut st = self
                .pipeline
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            st.queue.drain(..).collect()
        };
        for m in rest {
            match m {
                Msg::Record(e, d) => self.write_entry(&e, d, false),
                Msg::Sync(tx) => {
                    let _ = tx.send(());
                }
                Msg::FlushToken | Msg::Shutdown(..) => {}
            }
        }
        let mut stopping = stopping;
        stopping.redact_in_place();
        let line = stopping.to_capped_line(MAX_RECORD_BYTES);
        if let Some(f) = &mut self.file {
            let _ = f.write_line(&line);
        }
        if self.pipeline.stdout != StdoutFormat::Off {
            let text = if self.pipeline.stdout == StdoutFormat::Pretty {
                pretty(&stopping)
            } else {
                line
            };
            let _ = writeln!(self.stdout, "{text}");
        }
        self.sync_sinks();
    }
}

/// Human-readable single line for TTY stdout.
pub fn pretty(r: &Record) -> String {
    use std::fmt::Write as _;
    let mut s = format!(
        "{} {:5} {}",
        r.ts.get(11..23).unwrap_or(&r.ts),
        r.level.as_str(),
        r.event
    );
    if let Some(m) = &r.msg {
        let _ = write!(s, " — {m}");
    }
    if let Some(e) = &r.error {
        let _ = write!(s, " error.type={}", e.kind);
        if let Some(m) = &e.message {
            let _ = write!(s, " error={m:?}");
        }
    }
    for (k, v) in &r.attrs {
        let _ = match v {
            Value::Str(x) => write!(s, " {k}={x:?}"),
            Value::I64(x) => write!(s, " {k}={x}"),
            Value::U64(x) => write!(s, " {k}={x}"),
            Value::F64(x) => write!(s, " {k}={x}"),
            Value::Bool(x) => write!(s, " {k}={x}"),
            Value::StrList(x) => write!(s, " {k}={x:?}"),
        };
    }
    s
}
