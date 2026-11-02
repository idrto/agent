//! File transfer behind the engine handle (ABI v3).
//!
//! The engine embeds the same agent `Daemon` as `source-agent`: per Target a
//! supervisor keeps a bound session (reconnect, re-authorization at lease end),
//! and transfers belong to its outbox, so they resume after reconnects and after
//! the app restarts with the same `data_dir`. Transfers are named by 16-byte ids
//! (values, not pointers): a call on an unknown or finished id returns an error,
//! never touches freed memory. Events are drained in batches with progress
//! coalesced per transfer; nothing calls back into the host.

use std::collections::VecDeque;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use idr_core::error::{IdrError, IdrErrorKind, Result};
use idr_protocol::transfer::{TransferErrorKind, TransferId};
use idr_source::agent::{Daemon, DaemonConfig, RuntimeFactory};
use idr_transfer::bind::{entity_roots, LocalIdentity};
use idr_transfer::native::manager::{info_json, Manager};
use idr_transfer::policy::{lease_from_minutes, ReceivePolicy};
use idr_transfer::storage::Approval;
use idr_transfer::{Outcome, TransferEvent};
use parking_lot::Mutex;

use crate::engine::{cstr, Engine};
use crate::error::{clear_last_error, set_last_error, set_last_error_kind};

/// `-(IDR_TRANSFER_ERROR_BASE + idr_transfer_error_kind)` is returned when the
/// transfer layer refuses a call; the stable name is in `idr_last_error_message`.
pub const IDR_TRANSFER_ERROR_BASE: c_int = 100;

pub const IDR_TEV_OFFERED: u32 = 1;
pub const IDR_TEV_AWAITING_DECISION: u32 = 2;
pub const IDR_TEV_ACCEPTED: u32 = 3;
pub const IDR_TEV_PROGRESS: u32 = 4;
pub const IDR_TEV_ENTRY_FAILED: u32 = 5;
pub const IDR_TEV_RENAMED: u32 = 6;
pub const IDR_TEV_LEASE_EXPIRING: u32 = 7;
pub const IDR_TEV_PAUSED: u32 = 8;
pub const IDR_TEV_RESUMED: u32 = 9;
pub const IDR_TEV_FINISHED: u32 = 10;
pub const IDR_TEV_INTERRUPTED: u32 = 11;
pub const IDR_TEV_RESYNC: u32 = 12;

pub const IDR_OUTCOME_COMPLETED: u32 = 0;
pub const IDR_OUTCOME_COMPLETED_WITH_ERRORS: u32 = 1;
pub const IDR_OUTCOME_FAILED: u32 = 2;
pub const IDR_OUTCOME_CANCELLED: u32 = 3;
pub const IDR_OUTCOME_REJECTED: u32 = 4;

/// Queued events kept per engine; progress is coalesced first, then RESYNC.
const EVENT_QUEUE_CAP: usize = 1024;

#[repr(C)]
pub struct IdrTransferConfig {
    pub abi_version: u32,
    pub struct_size: u32,
    /// Outbox and IPC-free state of agent-owned transfers (required).
    pub data_dir: *const c_char,
    /// Default destination for incoming transfers (required).
    pub receive_dir: *const c_char,
    /// Entity root PEM; NULL = the root at the end of this device's chain.
    pub entity_root_pem: *const c_char,
    /// 1: incoming offers no rule auto-accepts wait for accept/reject (GUI).
    pub interactive: u32,
    /// 1: accept may name any directory (the user chose it in a native picker).
    pub any_destination: u32,
    /// 0 = 15; values below 5 are raised to 5.
    pub lease_minutes: u32,
    /// 0 = 300.
    pub offer_expiry_seconds: u32,
}

/// 64 bytes, no padding.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IdrTransferEvent {
    pub kind: u32,
    /// FINISHED: IDR_OUTCOME_*; INTERRUPTED / ENTRY_FAILED: error kind;
    /// ACCEPTED: 1 user, 2 auto; PAUSED/RESUMED: 1 by peer; LEASE_EXPIRING: seconds left.
    pub code: u32,
    pub transfer_id: [u8; 16],
    /// ENTRY_FAILED / RENAMED: entry id. FINISHED: error kind (0 = none).
    pub entry: u32,
    pub files_done: u32,
    pub files_total: u32,
    pub files_failed: u32,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub bytes_per_sec: u64,
}

const _: () = assert!(std::mem::size_of::<IdrTransferEvent>() == 64);

#[derive(Default)]
struct Queue {
    events: VecDeque<IdrTransferEvent>,
    resync: bool,
}

impl Queue {
    fn push(&mut self, ev: IdrTransferEvent) {
        if ev.kind == IDR_TEV_PROGRESS {
            // Replace this transfer's newest event if it is also progress.
            if let Some(last) = self.events.iter_mut().rev().find(|e| e.transfer_id == ev.transfer_id) {
                if last.kind == IDR_TEV_PROGRESS {
                    *last = ev;
                    return;
                }
            }
        }
        if self.events.len() >= EVENT_QUEUE_CAP {
            match self.events.iter().position(|e| e.kind == IDR_TEV_PROGRESS) {
                Some(i) => {
                    self.events.remove(i);
                }
                None => {
                    self.resync = true;
                    return;
                }
            }
        }
        self.events.push_back(ev);
    }

    fn pop(&mut self) -> Option<IdrTransferEvent> {
        if std::mem::take(&mut self.resync) {
            return Some(IdrTransferEvent { kind: IDR_TEV_RESYNC, ..Default::default() });
        }
        self.events.pop_front()
    }
}

fn to_c(id: TransferId, ev: &TransferEvent) -> Option<IdrTransferEvent> {
    let base = IdrTransferEvent { transfer_id: id, ..Default::default() };
    Some(match ev {
        TransferEvent::Offered(s) => IdrTransferEvent {
            kind: IDR_TEV_OFFERED,
            files_total: s.files,
            bytes_total: s.total_bytes,
            ..base
        },
        TransferEvent::AwaitingDecision => IdrTransferEvent { kind: IDR_TEV_AWAITING_DECISION, ..base },
        TransferEvent::Accepted { approval } => IdrTransferEvent {
            kind: IDR_TEV_ACCEPTED,
            code: match approval {
                Some(Approval::User) => 1,
                Some(Approval::Auto) => 2,
                None => 0,
            },
            ..base
        },
        TransferEvent::Progress(p) => IdrTransferEvent {
            kind: IDR_TEV_PROGRESS,
            files_done: p.files_done,
            files_total: p.files_total,
            files_failed: p.files_failed,
            bytes_done: p.bytes_done,
            bytes_total: p.bytes_total,
            bytes_per_sec: p.bytes_per_sec,
            ..base
        },
        TransferEvent::EntryFailed { entry, code } => IdrTransferEvent {
            kind: IDR_TEV_ENTRY_FAILED,
            entry: *entry,
            code: *code as u32,
            ..base
        },
        TransferEvent::Renamed { entry, .. } => IdrTransferEvent { kind: IDR_TEV_RENAMED, entry: *entry, ..base },
        TransferEvent::LeaseExpiring { secs_left } => IdrTransferEvent {
            kind: IDR_TEV_LEASE_EXPIRING,
            code: (*secs_left).min(u32::MAX as u64) as u32,
            ..base
        },
        TransferEvent::Paused { by_peer } => IdrTransferEvent { kind: IDR_TEV_PAUSED, code: *by_peer as u32, ..base },
        TransferEvent::Resumed { by_peer } => IdrTransferEvent { kind: IDR_TEV_RESUMED, code: *by_peer as u32, ..base },
        TransferEvent::Finished(o) => {
            let err = o.code().map_or(0, |k| k as u32);
            let (kind, code) = match o {
                Outcome::Completed => (IDR_TEV_FINISHED, IDR_OUTCOME_COMPLETED),
                Outcome::CompletedWithErrors { .. } => (IDR_TEV_FINISHED, IDR_OUTCOME_COMPLETED_WITH_ERRORS),
                Outcome::Failed(_) => (IDR_TEV_FINISHED, IDR_OUTCOME_FAILED),
                Outcome::Cancelled => (IDR_TEV_FINISHED, IDR_OUTCOME_CANCELLED),
                Outcome::Rejected(_) => (IDR_TEV_FINISHED, IDR_OUTCOME_REJECTED),
                // Not final: the agent resumes it on the next session.
                Outcome::Interrupted(k) => (IDR_TEV_INTERRUPTED, *k as u32),
            };
            let files_failed = match o {
                Outcome::CompletedWithErrors { failed } => *failed,
                _ => 0,
            };
            IdrTransferEvent { kind, code, entry: err, files_failed, ..base }
        }
    })
}

pub(crate) struct Transfers {
    daemon: Daemon,
    queue: Arc<Mutex<Queue>>,
    any_destination: bool,
    receive_dir: PathBuf,
}

/// Rust-side configuration (the C struct, parsed).
pub struct TransferSettings {
    pub data_dir: PathBuf,
    pub receive_dir: PathBuf,
    pub entity_root_pem: Option<String>,
    pub interactive: bool,
    pub any_destination: bool,
    pub lease: Duration,
    pub offer_expiry: Duration,
}

fn err(kind: IdrErrorKind, msg: impl Into<String>) -> IdrError {
    IdrError::new(kind, msg)
}

impl Engine {
    /// Enable file transfer with the engine's own runtimes (mock or native).
    pub fn enable_transfers(&self, s: TransferSettings) -> Result<()> {
        let factory = self.runtime_factory();
        self.enable_transfers_with(s, factory)
    }

    /// Enable file transfer with `runtimes`, proving the engine's DP identity.
    pub fn enable_transfers_with(&self, s: TransferSettings, runtimes: RuntimeFactory) -> Result<()> {
        let id = self
            .identity
            .lock()
            .clone()
            .ok_or_else(|| err(IdrErrorKind::NotInitialized, "set the DP identity first"))?;
        let d = id
            .private_jwk
            .get("d")
            .and_then(|v| v.as_str())
            .ok_or_else(|| err(IdrErrorKind::InvalidArgument, "identity has no private key"))?;
        let chain = id
            .chain_pem
            .as_deref()
            .or(id.cert_pem.as_deref())
            .ok_or_else(|| err(IdrErrorKind::NotInitialized, "identity has no issued certificate (enroll first)"))?;
        let me = LocalIdentity::from_jwk(d, &id.ski, chain)
            .ok_or_else(|| err(IdrErrorKind::InvalidArgument, "identity key is not Ed25519"))?;
        self.start_transfers(s, me, runtimes)
    }

    /// Enable file transfer as `me` (embedders holding the binding identity directly, tests).
    pub fn start_transfers(&self, s: TransferSettings, me: LocalIdentity, runtimes: RuntimeFactory) -> Result<()> {
        let mut slot = self.transfers.lock();
        if slot.is_some() {
            return Err(err(IdrErrorKind::InvalidArgument, "transfers already enabled"));
        }
        let roots = entity_roots(s.entity_root_pem.as_deref(), &me.chain_pem)
            .ok_or_else(|| err(IdrErrorKind::InvalidArgument, "no entity root: pass entity_root_pem"))?;
        let mut policy = if s.interactive { ReceivePolicy::interactive() } else { ReceivePolicy::headless() };
        policy.lease = s.lease;
        std::fs::create_dir_all(&s.receive_dir)
            .map_err(|e| err(IdrErrorKind::InvalidArgument, format!("receive_dir: {e}")))?;
        let _rt = self.rt.enter();
        let daemon = Daemon::start(
            DaemonConfig {
                data_dir: s.data_dir,
                targets: Vec::new(),
                identity: Arc::new(me),
                roots,
                receive_dir: s.receive_dir.clone(),
                receive_policy: policy,
                send_policy: Default::default(),
                limits: Default::default(),
                reconnect_min: Duration::from_secs(1),
                reconnect_max: Duration::from_secs(60),
                ipc: None,
                permitted_dirs: Vec::new(),
                offer_expiry: s.offer_expiry,
            },
            runtimes,
        )
        .map_err(|e| err(IdrErrorKind::InternalError, format!("{e:#}")))?;
        let queue = Arc::new(Mutex::new(Queue::default()));
        let mut rx = daemon.manager().subscribe();
        let q = queue.clone();
        self.rt.spawn(async move {
            use tokio::sync::broadcast::error::RecvError;
            loop {
                match rx.recv().await {
                    Ok((id, ev)) => {
                        if let Some(c) = to_c(id, &ev) {
                            q.lock().push(c);
                        }
                    }
                    Err(RecvError::Lagged(_)) => q.lock().resync = true,
                    Err(RecvError::Closed) => break,
                }
            }
        });
        *slot = Some(Transfers {
            daemon,
            queue,
            any_destination: s.any_destination,
            receive_dir: s.receive_dir,
        });
        Ok(())
    }

    fn with_transfers<T>(&self, f: impl FnOnce(&Transfers) -> Result<T>) -> Result<T> {
        let slot = self.transfers.lock();
        let t = slot
            .as_ref()
            .ok_or_else(|| err(IdrErrorKind::NotInitialized, "transfers not enabled"))?;
        f(t)
    }

    pub fn transfer_send(&self, target: &str, paths: &[PathBuf]) -> Result<TransferId> {
        let _rt = self.rt.enter();
        self.with_transfers(|t| {
            t.daemon
                .send_paths(target, paths)
                .map_err(|e| err(IdrErrorKind::InvalidArgument, e.to_string()))
        })
    }

    pub fn transfer_send_selection(&self, target: &str, folder: &std::path::Path, selected: &[String]) -> Result<TransferId> {
        let _rt = self.rt.enter();
        self.with_transfers(|t| {
            t.daemon
                .send_selection(target, folder, selected)
                .map_err(|e| err(IdrErrorKind::InvalidArgument, e.to_string()))
        })
    }

    /// Run a manager command on a known transfer. Ok(Err(kind)): the transfer layer refused.
    pub fn transfer_command(&self, id: &TransferId, cmd: TransferCommand) -> Result<std::result::Result<(), TransferErrorKind>> {
        let manager: Arc<Manager> = self.with_transfers(|t| Ok(t.daemon.manager().clone()))?;
        if manager.status(id).is_none() {
            return Err(err(IdrErrorKind::InvalidArgument, "unknown transfer"));
        }
        let _rt = self.rt.enter();
        Ok(match cmd {
            TransferCommand::Pause => self.rt.block_on(manager.pause(id)),
            TransferCommand::Resume => self.rt.block_on(manager.resume(id)),
            TransferCommand::Cancel => self.rt.block_on(manager.cancel(id)),
            TransferCommand::Retry => manager.retry(id),
            TransferCommand::Reject => manager.reject(id),
            TransferCommand::Accept(out) => {
                let permitted = self.with_transfers(|t| {
                    Ok(match (&out, t.any_destination) {
                        (Some(dir), true) => vec![dir.clone()],
                        _ => vec![t.receive_dir.clone()],
                    })
                })?;
                manager.accept(id, out, &permitted)
            }
        })
    }

    pub fn transfer_list_json(&self) -> Result<String> {
        self.with_transfers(|t| {
            let v: Vec<_> = t.daemon.manager().list().iter().map(info_json).collect();
            Ok(serde_json::Value::Array(v).to_string())
        })
    }

    pub fn transfer_status_json(&self, id: &TransferId) -> Result<String> {
        self.with_transfers(|t| {
            t.daemon
                .manager()
                .status(id)
                .map(|i| info_json(&i).to_string())
                .ok_or_else(|| err(IdrErrorKind::InvalidArgument, "unknown transfer"))
        })
    }

    pub fn transfer_entries_json(&self, id: &TransferId, first: u32, max: u32) -> Result<String> {
        self.with_transfers(|t| {
            t.daemon
                .manager()
                .entries_json(id, first, max)
                .map(|v| v.to_string())
                .ok_or_else(|| err(IdrErrorKind::InvalidArgument, "unknown transfer"))
        })
    }

    pub fn transfer_poll(&self) -> Option<IdrTransferEvent> {
        let q = self.transfers.lock().as_ref().map(|t| t.queue.clone())?;
        let ev = q.lock().pop();
        ev
    }

    /// Stop supervisors; running transfers stop resumably (outbox + journal).
    pub(crate) fn shutdown_transfers(&self) {
        if let Some(t) = self.transfers.lock().take() {
            self.rt.block_on(t.daemon.shutdown());
        }
    }
}

pub enum TransferCommand {
    Pause,
    Resume,
    Cancel,
    Retry,
    Reject,
    Accept(Option<PathBuf>),
}

// ---- C exports --------------------------------------------------------------

unsafe fn engine<'a>(e: *mut crate::ffi::IdrEngine) -> Option<&'a Engine> {
    (!e.is_null()).then(|| &*(e as *mut Engine))
}

fn invalid(msg: &str) -> c_int {
    set_last_error_kind(IdrErrorKind::InvalidArgument, msg);
    -(IdrErrorKind::InvalidArgument as c_int)
}

fn fail(e: IdrError) -> c_int {
    set_last_error(&e);
    -(e.kind as c_int)
}

unsafe fn read_id(id: *const u8) -> Option<TransferId> {
    (!id.is_null()).then(|| {
        let mut out = [0u8; 16];
        std::ptr::copy_nonoverlapping(id, out.as_mut_ptr(), 16);
        out
    })
}

unsafe fn str_arg<'a>(p: *const c_char) -> Option<&'a str> {
    (!p.is_null()).then(|| CStr::from_ptr(p).to_str().ok()).flatten()
}

unsafe fn str_list(items: *const *const c_char, n: usize) -> Option<Vec<String>> {
    if items.is_null() || n == 0 {
        return None;
    }
    std::slice::from_raw_parts(items, n)
        .iter()
        .map(|&p| str_arg(p).map(str::to_string))
        .collect()
}

#[no_mangle]
pub unsafe extern "C" fn idr_transfer_enable(e: *mut crate::ffi::IdrEngine, cfg: *const IdrTransferConfig) -> c_int {
    clear_last_error();
    let (Some(eng), false) = (engine(e), cfg.is_null()) else { return invalid("null argument") };
    let c = &*cfg;
    if c.abi_version != crate::ABI_VERSION {
        set_last_error_kind(IdrErrorKind::IncompatibleVersion, "abi_version mismatch");
        return -(IdrErrorKind::IncompatibleVersion as c_int);
    }
    if (c.struct_size as usize) < std::mem::size_of::<IdrTransferConfig>() {
        return invalid("struct_size too small");
    }
    let (Some(data_dir), Some(receive_dir)) = (cstr(c.data_dir), cstr(c.receive_dir)) else {
        return invalid("data_dir and receive_dir are required");
    };
    let settings = TransferSettings {
        data_dir: data_dir.into(),
        receive_dir: receive_dir.into(),
        entity_root_pem: cstr(c.entity_root_pem),
        interactive: c.interactive != 0,
        any_destination: c.any_destination != 0,
        lease: lease_from_minutes((c.lease_minutes != 0).then_some(c.lease_minutes as u64)),
        offer_expiry: Duration::from_secs(if c.offer_expiry_seconds == 0 { 300 } else { c.offer_expiry_seconds as u64 }),
    };
    match eng.enable_transfers(settings) {
        Ok(()) => 0,
        Err(e) => fail(e),
    }
}

/// Send files (one or more) or one folder: `paths` are absolute local paths.
#[no_mangle]
pub unsafe extern "C" fn idr_transfer_send(
    e: *mut crate::ffi::IdrEngine,
    target_fqhn: *const c_char,
    paths: *const *const c_char,
    n_paths: usize,
    out_id: *mut u8,
) -> c_int {
    clear_last_error();
    let (Some(eng), Some(target), Some(paths), false) = (engine(e), str_arg(target_fqhn), str_list(paths, n_paths), out_id.is_null()) else {
        return invalid("null or invalid argument");
    };
    let paths: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).collect();
    match eng.transfer_send(target, &paths) {
        Ok(id) => {
            std::ptr::copy_nonoverlapping(id.as_ptr(), out_id, 16);
            0
        }
        Err(e) => fail(e),
    }
}

/// Send a selection inside `folder`: `selected` are `/`-separated paths relative to it.
#[no_mangle]
pub unsafe extern "C" fn idr_transfer_send_selection(
    e: *mut crate::ffi::IdrEngine,
    target_fqhn: *const c_char,
    folder: *const c_char,
    selected: *const *const c_char,
    n_selected: usize,
    out_id: *mut u8,
) -> c_int {
    clear_last_error();
    let (Some(eng), Some(target), Some(folder), Some(sel), false) =
        (engine(e), str_arg(target_fqhn), str_arg(folder), str_list(selected, n_selected), out_id.is_null())
    else {
        return invalid("null or invalid argument");
    };
    match eng.transfer_send_selection(target, std::path::Path::new(folder), &sel) {
        Ok(id) => {
            std::ptr::copy_nonoverlapping(id.as_ptr(), out_id, 16);
            0
        }
        Err(e) => fail(e),
    }
}

unsafe fn command(e: *mut crate::ffi::IdrEngine, id: *const u8, cmd: TransferCommand) -> c_int {
    clear_last_error();
    let (Some(eng), Some(id)) = (engine(e), read_id(id)) else { return invalid("null argument") };
    match eng.transfer_command(&id, cmd) {
        Ok(Ok(())) => 0,
        Ok(Err(k)) => {
            set_last_error_kind(IdrErrorKind::AuthorizationDenied, k.as_str());
            -(IDR_TRANSFER_ERROR_BASE + k as c_int)
        }
        Err(e) => fail(e),
    }
}

/// Accept a pending incoming offer; `out_dir` NULL = the configured receive_dir.
#[no_mangle]
pub unsafe extern "C" fn idr_transfer_accept(e: *mut crate::ffi::IdrEngine, id: *const u8, out_dir: *const c_char) -> c_int {
    if !out_dir.is_null() && str_arg(out_dir).is_none() {
        return invalid("invalid utf8 out_dir");
    }
    command(e, id, TransferCommand::Accept(str_arg(out_dir).map(PathBuf::from)))
}

#[no_mangle]
pub unsafe extern "C" fn idr_transfer_reject(e: *mut crate::ffi::IdrEngine, id: *const u8) -> c_int {
    command(e, id, TransferCommand::Reject)
}

#[no_mangle]
pub unsafe extern "C" fn idr_transfer_pause(e: *mut crate::ffi::IdrEngine, id: *const u8) -> c_int {
    command(e, id, TransferCommand::Pause)
}

#[no_mangle]
pub unsafe extern "C" fn idr_transfer_resume(e: *mut crate::ffi::IdrEngine, id: *const u8) -> c_int {
    command(e, id, TransferCommand::Resume)
}

#[no_mangle]
pub unsafe extern "C" fn idr_transfer_cancel(e: *mut crate::ffi::IdrEngine, id: *const u8) -> c_int {
    command(e, id, TransferCommand::Cancel)
}

#[no_mangle]
pub unsafe extern "C" fn idr_transfer_retry_failed(e: *mut crate::ffi::IdrEngine, id: *const u8) -> c_int {
    command(e, id, TransferCommand::Retry)
}

/// JSON array of transfers (same shape as `source-agent transfer list --json`).
#[no_mangle]
pub unsafe extern "C" fn idr_transfer_list(e: *mut crate::ffi::IdrEngine, buf: *mut c_char, capacity: usize) -> c_int {
    clear_last_error();
    let (Some(eng), false) = (engine(e), buf.is_null() || capacity == 0) else { return invalid("null argument") };
    match eng.transfer_list_json() {
        Ok(json) => crate::ffi::copy_json_to_buf(json, buf, capacity),
        Err(e) => fail(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn idr_transfer_status(e: *mut crate::ffi::IdrEngine, id: *const u8, buf: *mut c_char, capacity: usize) -> c_int {
    clear_last_error();
    let (Some(eng), Some(id), false) = (engine(e), read_id(id), buf.is_null() || capacity == 0) else {
        return invalid("null argument");
    };
    match eng.transfer_status_json(&id) {
        Ok(json) => crate::ffi::copy_json_to_buf(json, buf, capacity),
        Err(e) => fail(e),
    }
}

/// `{"total","first","entries":[{entry,path,kind,size,failed,stored_as}]}`, at most 256 entries.
#[no_mangle]
pub unsafe extern "C" fn idr_transfer_entries(
    e: *mut crate::ffi::IdrEngine,
    id: *const u8,
    first: u32,
    max: u32,
    buf: *mut c_char,
    capacity: usize,
) -> c_int {
    clear_last_error();
    let (Some(eng), Some(id), false) = (engine(e), read_id(id), buf.is_null() || capacity == 0) else {
        return invalid("null argument");
    };
    match eng.transfer_entries_json(&id, first, max) {
        Ok(json) => crate::ffi::copy_json_to_buf(json, buf, capacity),
        Err(e) => fail(e),
    }
}

/// Drain up to `max_events`. Safe to call from any one thread at a time, while
/// other threads issue commands.
#[no_mangle]
pub unsafe extern "C" fn idr_transfer_poll_events(
    e: *mut crate::ffi::IdrEngine,
    out: *mut IdrTransferEvent,
    max_events: usize,
    out_count: *mut usize,
) -> c_int {
    clear_last_error();
    let (Some(eng), false) = (engine(e), out.is_null() || out_count.is_null()) else { return invalid("null argument") };
    let dest = std::slice::from_raw_parts_mut(out, max_events);
    let mut n = 0;
    while n < max_events {
        let Some(ev) = eng.transfer_poll() else { break };
        dest[n] = ev;
        n += 1;
    }
    *out_count = n;
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: u32, id: u8, bytes: u64) -> IdrTransferEvent {
        IdrTransferEvent { kind, transfer_id: [id; 16], bytes_done: bytes, ..Default::default() }
    }

    #[test]
    fn progress_is_coalesced_per_transfer_and_order_kept() {
        let mut q = Queue::default();
        q.push(ev(IDR_TEV_PROGRESS, 1, 10));
        q.push(ev(IDR_TEV_PROGRESS, 2, 5));
        q.push(ev(IDR_TEV_PROGRESS, 1, 20));
        q.push(ev(IDR_TEV_FINISHED, 1, 0));
        q.push(ev(IDR_TEV_PROGRESS, 1, 30));
        let got: Vec<_> = std::iter::from_fn(|| q.pop()).map(|e| (e.kind, e.transfer_id[0], e.bytes_done)).collect();
        assert_eq!(
            got,
            [(IDR_TEV_PROGRESS, 1, 20), (IDR_TEV_PROGRESS, 2, 5), (IDR_TEV_FINISHED, 1, 0), (IDR_TEV_PROGRESS, 1, 30)]
        );
    }

    #[test]
    fn overflow_drops_progress_first_then_signals_resync() {
        let mut q = Queue::default();
        q.push(ev(IDR_TEV_PROGRESS, 0, 1));
        for i in 0..EVENT_QUEUE_CAP - 1 {
            q.push(ev(IDR_TEV_ENTRY_FAILED, 1, i as u64));
        }
        q.push(ev(IDR_TEV_FINISHED, 2, 0)); // evicts the one progress event
        assert_eq!(q.events.len(), EVENT_QUEUE_CAP);
        assert!(!q.resync);
        q.push(ev(IDR_TEV_FINISHED, 3, 0)); // nothing left to evict
        assert_eq!(q.pop().unwrap().kind, IDR_TEV_RESYNC);
        assert_eq!(q.pop().unwrap().kind, IDR_TEV_ENTRY_FAILED);
        assert!(q.events.iter().all(|e| e.transfer_id != [3; 16]));
    }
}
