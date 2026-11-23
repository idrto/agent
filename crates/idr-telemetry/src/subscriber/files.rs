//! Local files: runs, lifetime locks, rotation, ownership-safe retention, per-run exit
//! recovery and the disk guard (docs/observability/04 §1.3, §3.3).
//!
//! Names (in `<root>/<service>/`):
//!   `<start>_<app_session_id>_<NNN>.<producer>`   segment
//!   `<start>_<app_session_id>.<producer>.lock`     held by the owner for its lifetime
//!   `<start>_<app_session_id>.<producer>.ended`    written once by recovery
//! where `<producer>` is `jsonl` (primary) or `rust.jsonl` (in-process engine).

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub const SEGMENT_BYTES: u64 = 10 * 1024 * 1024;
pub const DEFAULT_CAP_BYTES: u64 = 100 * 1024 * 1024;
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600);
pub const MIN_FREE_BYTES: u64 = 500 * 1024 * 1024;
const START_LEN: usize = 20; // 2026-11-21T10-00-00Z

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RunKey {
    pub start: String,
    pub app_session_id: String,
    pub producer: String,
}

impl RunKey {
    fn base(&self) -> String {
        format!("{}_{}", self.start, self.app_session_id)
    }
    fn lock_name(&self) -> String {
        format!("{}.{}.lock", self.base(), self.producer)
    }
    fn ended_name(&self) -> String {
        format!("{}.{}.ended", self.base(), self.producer)
    }
    fn segment_name(&self, n: u32) -> String {
        format!("{}_{n:03}.{}", self.base(), self.producer)
    }
}

enum Entry {
    Segment(RunKey, u32),
    Lock(RunKey),
    Ended(RunKey),
}

fn parse_name(name: &str) -> Option<Entry> {
    if name.len() < START_LEN + 1 + 36 + 2 || name.as_bytes()[START_LEN] != b'_' {
        return None;
    }
    let start = &name[..START_LEN];
    let id = &name[START_LEN + 1..START_LEN + 37];
    if !crate::is_uuid(id) {
        return None;
    }
    let rest = &name[START_LEN + 37..];
    let key = |producer: &str| RunKey {
        start: start.into(),
        app_session_id: id.into(),
        producer: producer.into(),
    };
    if let Some(r) = rest.strip_prefix('.') {
        if let Some(p) = r.strip_suffix(".lock") {
            return Some(Entry::Lock(key(p)));
        }
        if let Some(p) = r.strip_suffix(".ended") {
            return Some(Entry::Ended(key(p)));
        }
        return None;
    }
    let r = rest.strip_prefix('_')?;
    let (num, producer) = r.split_once('.')?;
    Some(Entry::Segment(key(producer), num.parse().ok()?))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunState {
    Active,
    Ended,
    Unknown,
}

/// Ownership by lock test (04 §1.3). Never inferred from modification time.
pub fn run_state(dir: &Path, key: &RunKey) -> RunState {
    let Ok(f) = OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.join(key.lock_name()))
    else {
        return RunState::Unknown; // missing lock file or open error
    };
    match f.try_lock() {
        Ok(()) => RunState::Ended, // released when `f` drops
        Err(TryLockError::WouldBlock) => RunState::Active,
        Err(TryLockError::Error(_)) => RunState::Unknown,
    }
}

#[derive(Default)]
struct RunFiles {
    segments: BTreeMap<u32, (PathBuf, u64, SystemTime)>,
    has_lock: bool,
    has_ended: bool,
}

fn scan(dir: &Path) -> HashMap<RunKey, RunFiles> {
    let mut runs: HashMap<RunKey, RunFiles> = HashMap::new();
    let Ok(rd) = fs::read_dir(dir) else {
        return runs;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        match parse_name(&name) {
            Some(Entry::Segment(k, n)) => {
                let md = e.metadata().ok();
                let size = md.as_ref().map_or(0, |m| m.len());
                let mtime = md
                    .and_then(|m| m.modified().ok())
                    .unwrap_or(SystemTime::UNIX_EPOCH);
                runs.entry(k)
                    .or_default()
                    .segments
                    .insert(n, (e.path(), size, mtime));
            }
            Some(Entry::Lock(k)) => runs.entry(k).or_default().has_lock = true,
            Some(Entry::Ended(k)) => runs.entry(k).or_default().has_ended = true,
            None => {}
        }
    }
    runs
}

/// The active writer of one run. Holds the run lock for its whole lifetime.
pub struct FileSink {
    dir: PathBuf,
    key: RunKey,
    seg: u32,
    out: BufWriter<File>,
    size: u64,
    _lock: File,
    pub cap_bytes: u64,
    pub max_age: Duration,
}

impl FileSink {
    pub fn open(dir: &Path, start: &str, app_session_id: &str, producer: &str) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let key = RunKey {
            start: start.into(),
            app_session_id: app_session_id.into(),
            producer: producer.into(),
        };
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join(key.lock_name()))?;
        lock.try_lock().map_err(|e| match e {
            TryLockError::WouldBlock => {
                io::Error::new(io::ErrorKind::AlreadyExists, "run already owned")
            }
            TryLockError::Error(e) => e,
        })?;
        let out = BufWriter::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join(key.segment_name(0)))?,
        );
        Ok(Self {
            dir: dir.into(),
            key,
            seg: 0,
            out,
            size: 0,
            _lock: lock,
            cap_bytes: DEFAULT_CAP_BYTES,
            max_age: DEFAULT_MAX_AGE,
        })
    }

    pub fn key(&self) -> &RunKey {
        &self.key
    }

    /// Writes one line; rotates first when the segment would exceed 10 MiB.
    /// Returns true when a rotation happened (caller runs retention).
    pub fn write_line(&mut self, line: &str) -> io::Result<bool> {
        let n = line.len() as u64 + 1;
        let rotated = self.size > 0 && self.size + n > SEGMENT_BYTES;
        if rotated {
            self.out.flush()?;
            self.seg += 1;
            self.out = BufWriter::new(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(self.dir.join(self.key.segment_name(self.seg)))?,
            );
            self.size = 0;
        }
        self.out.write_all(line.as_bytes())?;
        self.out.write_all(b"\n")?;
        self.size += n;
        Ok(rotated)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }

    pub fn sync(&mut self) -> io::Result<()> {
        self.out.flush()?;
        self.out.get_ref().sync_data()
    }

    pub fn cleanup(&self) -> CleanupReport {
        cleanup(
            &self.dir,
            &self.key.producer,
            Some(&self.key),
            self.cap_bytes,
            self.max_age,
            SystemTime::now(),
        )
    }
}

#[derive(Debug, Default)]
pub struct CleanupReport {
    pub deleted: Vec<PathBuf>,
    pub unknown_runs: Vec<RunKey>,
}

/// Retention over provably-closed segments of `producer` runs only (04 §1.3). Runs of other
/// producers are never judged: lock primitives differ between languages on POSIX
/// (`flock` here, `fcntl` in Dart), so only the implementation that takes a lock tests it.
pub fn cleanup(
    dir: &Path,
    producer: &str,
    own: Option<&RunKey>,
    cap_bytes: u64,
    max_age: Duration,
    now: SystemTime,
) -> CleanupReport {
    let mut report = CleanupReport::default();
    let runs = scan(dir);
    let mut deletable: Vec<(SystemTime, PathBuf, u64)> = Vec::new();
    let mut ended_runs = Vec::new();
    for (key, files) in &runs {
        if key.producer != producer || files.segments.is_empty() {
            continue;
        }
        let state = if Some(key) == own {
            RunState::Active
        } else {
            run_state(dir, key)
        };
        let highest = *files.segments.keys().next_back().unwrap();
        match state {
            RunState::Unknown => report.unknown_runs.push(key.clone()),
            RunState::Ended if !files.has_ended => {} // recovery has not classified it yet
            RunState::Ended => {
                ended_runs.push(key.clone());
                deletable.extend(files.segments.values().map(|(p, s, m)| (*m, p.clone(), *s)));
            }
            RunState::Active => deletable.extend(
                files
                    .segments
                    .iter()
                    .filter(|(n, _)| **n != highest)
                    .map(|(_, (p, s, m))| (*m, p.clone(), *s)),
            ),
        }
    }
    deletable.sort();
    let mut total: u64 = deletable.iter().map(|d| d.2).sum();
    for (mtime, path, size) in deletable {
        let too_old = now.duration_since(mtime).unwrap_or_default() > max_age;
        if (too_old || total > cap_bytes) && fs::remove_file(&path).is_ok() {
            total -= size;
            report.deleted.push(path);
        }
    }
    // Ended runs with no segments left lose their lock and sidecar too.
    let remaining = scan(dir);
    for key in ended_runs {
        if remaining.get(&key).is_none_or(|f| f.segments.is_empty()) {
            let _ = fs::remove_file(dir.join(key.lock_name()));
            let _ = fs::remove_file(dir.join(key.ended_name()));
        }
    }
    report
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    Clean,
    Unclean,
    Crash,
}

impl Exit {
    fn as_str(self) -> &'static str {
        match self {
            Exit::Clean => "clean",
            Exit::Unclean => "unclean",
            Exit::Crash => "crash",
        }
    }
}

#[derive(Debug)]
pub struct Recovered {
    pub app_session_id: String,
    pub exit: Exit,
    pub open_operations: Vec<String>,
}

/// Per-run exit recovery for runs of `producer` (04 §3.3). Each ended, unclaimed run is
/// classified and claimed exactly once via exclusive create of its `.ended` sidecar.
/// Returns only crash/unclean runs claimed by this call.
pub fn recover(
    dir: &Path,
    crash_dir: &Path,
    producer: &str,
    own: Option<&RunKey>,
) -> Vec<Recovered> {
    let mut out = Vec::new();
    for (key, files) in scan(dir) {
        if key.producer != producer
            || files.has_ended
            || files.segments.is_empty()
            || Some(&key) == own
        {
            continue;
        }
        if run_state(dir, &key) != RunState::Ended {
            continue; // active, or unknown: nothing is claimed
        }
        let (last_path, _, _) = files.segments.values().next_back().unwrap();
        let crash = has_crash_record(crash_dir, &key.app_session_id);
        let exit = if crash {
            Exit::Crash
        } else if last_event(last_path).as_deref() == Some("app.stopping") {
            Exit::Clean
        } else {
            Exit::Unclean
        };
        let claim = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(key.ended_name()));
        let Ok(mut f) = claim else { continue }; // another process claimed it
        let _ = writeln!(f, "{{\"exit\":\"{}\"}}", exit.as_str());
        if exit != Exit::Clean {
            out.push(Recovered {
                app_session_id: key.app_session_id.clone(),
                exit,
                open_operations: open_operations(last_path),
            });
        }
    }
    out
}

fn has_crash_record(crash_dir: &Path, app_session_id: &str) -> bool {
    fs::read_dir(crash_dir).is_ok_and(|rd| {
        rd.flatten().any(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.starts_with(app_session_id) && n.ends_with(".crash.json")
        })
    })
}

/// Event of the last complete, parseable line in the last 64 KiB.
fn last_event(path: &Path) -> Option<String> {
    let mut f = File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    f.seek(SeekFrom::Start(len.saturating_sub(64 * 1024)))
        .ok()?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).ok()?;
    String::from_utf8_lossy(&buf)
        .lines()
        .rev()
        .find_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .and_then(|v| v["event"].as_str().map(String::from))
}

/// `*.started` records without a matching span end, within the last segment (best effort).
fn open_operations(path: &Path) -> Vec<String> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut open: Vec<(String, String)> = Vec::new();
    for v in text
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
    {
        let span = v["span_id"].as_str().unwrap_or_default().to_string();
        match (v["kind"].as_str(), v["event"].as_str()) {
            (Some("log"), Some(e)) if e.ends_with(".started") => {
                open.push((span, e.trim_end_matches(".started").into()))
            }
            (Some("span"), _) => open.retain(|(s, _)| *s != span),
            _ => {}
        }
    }
    open.into_iter().map(|(_, name)| name).collect()
}

/// Free bytes on the volume holding `dir`; `None` when unknown.
pub fn free_bytes(dir: &Path) -> Option<u64> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut free = 0u64;
        // SAFETY: valid NUL-terminated path; out-pointers are valid for the call.
        let ok = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &mut free,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        (ok != 0).then_some(free)
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
        // SAFETY: valid C string; statvfs writes into `s`.
        let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
        (unsafe { libc::statvfs(c.as_ptr(), &mut s) } == 0)
            .then(|| s.f_bavail as u64 * s.f_frsize as u64)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = dir;
        None
    }
}
