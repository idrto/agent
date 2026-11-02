//! The `idr_transfer_*` C ABI end to end: an engine created through the C ABI
//! sends to and receives from an in-process Target over real WebRTC
//! (libdatachannel), with real storage on both sides. Everything after setup
//! goes through the exported C functions.

#[path = "../../idr-target/tests/common/mod.rs"]
mod common;

use std::ffi::CString;
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use ed25519_dalek::SigningKey;
use idr_c_api::*;
use idr_protocol::transfer::{new_transfer_id, ManifestKind};
use idr_protocol::webrtc_signaling::SourceAuthMode;
use idr_source::SourceRuntime;
use idr_target::webrtc::local::{TransferConfig, TransferEndpoint};
use idr_transfer::bind::LocalIdentity;
use idr_transfer::manifest::build;
use idr_transfer::native::NativeFiles;
use idr_transfer::policy::{PeerRule, PolicyEngine, ReceivePolicy};
use idr_transfer::{Limits, Outcome, Outgoing};
use idr_webrtc::native::NativePeerConfig;
use idr_webrtc::NativePeer;
use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, SanType};
use sha2::Digest;

// ---- PKI (as in the source-agent daemon tests) -------------------------------

fn keys(seed: u8) -> (SigningKey, KeyPair) {
    let mut der = vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    der.extend_from_slice(&[seed; 32]);
    (SigningKey::from_bytes(&[seed; 32]), KeyPair::try_from(der.as_slice()).unwrap())
}

fn params(cn: &str) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    p.distinguished_name = dn;
    p.not_before = rcgen::date_time_ymd(2020, 1, 1);
    p.not_after = rcgen::date_time_ymd(2099, 1, 1);
    p
}

struct Pki {
    root: rcgen::Certificate,
    root_key: KeyPair,
}

impl Pki {
    fn new() -> Self {
        let (_, root_key) = keys(1);
        let mut p = params("entity root");
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        Self { root: p.self_signed(&root_key).unwrap(), root_key }
    }

    fn device(&self, seed: u8, ski: &str, host: Option<&str>) -> LocalIdentity {
        let (sk, kp) = keys(seed);
        let mut p = params(ski);
        p.subject_alt_names = vec![SanType::URI(format!("urn:dp:ski:{ski}").try_into().unwrap())];
        if let Some(h) = host {
            p.subject_alt_names.push(SanType::DnsName(h.try_into().unwrap()));
        }
        let leaf = p.signed_by(&kp, &self.root, &self.root_key).unwrap();
        LocalIdentity { key: sk, ski: ski.into(), chain_pem: format!("{}{}", leaf.pem(), self.root.pem()) }
    }
}

// ---- World -------------------------------------------------------------------

const SRC: &str = "ffi-src-ski";
const TGT: &str = "ffi-tgt-ski";

struct World {
    /// Runs the Target's services; the engine has its own runtime.
    rt: tokio::runtime::Runtime,
    pki: Pki,
    endpoint: Arc<TransferEndpoint>,
    connectors: Arc<idr_core::ConnectorRegistry>,
    target_dir: tempfile::TempDir,
    data_dir: tempfile::TempDir,
    inbox: tempfile::TempDir,
}

fn world() -> World {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let pki = Pki::new();
    let target_dir = tempfile::tempdir().unwrap();
    let mut policy = ReceivePolicy::headless();
    policy.peers.insert(SRC.into(), PeerRule { auto_accept: true, ..PeerRule::default() });
    let (endpoint, connectors) = rt.block_on(async {
        let (ep, events) = TransferEndpoint::new(TransferConfig {
            identity: pki.device(4, TGT, Some(FQHN)),
            roots: vec![pki.root.der().to_vec()],
            policy: PolicyEngine::new(policy, None),
            receive_dir: target_dir.path().to_path_buf(),
            limits: Limits::default(),
            bind_timeout: Duration::from_secs(5),
            manager: None,
            offer_expiry: None,
        });
        std::mem::forget(events);
        (ep, services().await)
    });
    World {
        rt,
        pki,
        endpoint,
        connectors,
        target_dir,
        data_dir: tempfile::tempdir().unwrap(),
        inbox: tempfile::tempdir().unwrap(),
    }
}

struct Eng(*mut IdrEngine);

impl Eng {
    fn e(&self) -> *mut IdrEngine {
        self.0
    }
}

impl Drop for Eng {
    fn drop(&mut self) {
        unsafe { idr_engine_destroy(self.0) };
    }
}

/// An engine through the C ABI, with transfers on against the World's Target.
fn engine(w: &World, interactive: bool) -> Eng {
    let token = CString::new("t").unwrap();
    let (id, region) = (CString::new("ffi").unwrap(), CString::new("local").unwrap());
    let cfg = IdrEngineConfig {
        abi_version: ABI_VERSION,
        struct_size: std::mem::size_of::<IdrEngineConfig>() as u32,
        use_mock: 1,
        source_id: id.as_ptr(),
        source_region: region.as_ptr(),
        auth_token: token.as_ptr(),
        auth_mode: IDR_AUTH_BEARER,
        discovery_url: std::ptr::null(),
        discovery_key: std::ptr::null(),
        insecure_dev: 0,
    };
    let ptr = unsafe { idr_engine_create(&cfg) };
    assert!(!ptr.is_null());
    let (connectors, ep) = (w.connectors.clone(), w.endpoint.clone());
    let factory: idr_source::agent::RuntimeFactory = Arc::new(move || {
        SourceRuntime::with_auth(
            Box::new(LoopPresence { connectors: connectors.clone(), transfers: Some(ep.clone()), attested_ski: Some(SRC.into()), relay: None }),
            || Box::new(NativePeer::new(NativePeerConfig::default()).unwrap()),
            "ffi-src",
            "local",
            SourceAuthMode::Bearer,
            Some("t".into()),
        )
    });
    let eng = unsafe { &*(ptr as *const Engine) };
    eng.start_transfers(
        TransferSettings {
            data_dir: w.data_dir.path().into(),
            receive_dir: w.inbox.path().into(),
            entity_root_pem: Some(w.pki.root.pem()),
            interactive,
            any_destination: true,
            lease: Duration::from_secs(15 * 60),
            offer_expiry: Duration::from_secs(30),
        },
        w.pki.device(3, SRC, None),
        factory,
    )
    .unwrap();
    Eng(ptr)
}

fn send(e: &Eng, paths: &[&Path]) -> [u8; 16] {
    let target = CString::new(FQHN).unwrap();
    let owned: Vec<CString> = paths.iter().map(|p| CString::new(p.to_str().unwrap()).unwrap()).collect();
    let ptrs: Vec<*const c_char> = owned.iter().map(|c| c.as_ptr()).collect();
    let mut id = [0u8; 16];
    let rc = unsafe { idr_transfer_send(e.e(), target.as_ptr(), ptrs.as_ptr(), ptrs.len(), id.as_mut_ptr()) };
    assert_eq!(rc, 0, "send: {}", last_error_message());
    id
}

fn poll(e: &Eng, into: &mut Vec<IdrTransferEvent>) {
    let mut buf = [IdrTransferEvent::default(); 32];
    loop {
        let mut n = 0;
        assert_eq!(unsafe { idr_transfer_poll_events(e.e(), buf.as_mut_ptr(), buf.len(), &mut n) }, 0);
        into.extend_from_slice(&buf[..n]);
        if n < buf.len() {
            return;
        }
    }
}

/// Poll until an event for `id` matches; returns it. All events land in `seen`.
fn wait(e: &Eng, id: &[u8; 16], secs: u64, seen: &mut Vec<IdrTransferEvent>, want: impl Fn(&IdrTransferEvent) -> bool) -> IdrTransferEvent {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut from = seen.len();
    loop {
        poll(e, seen);
        if let Some(ev) = seen[from..].iter().find(|ev| ev.transfer_id == *id && want(ev)) {
            return *ev;
        }
        from = seen.len();
        assert!(Instant::now() < deadline, "no matching event; last: {:?}", seen.last());
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn finished(code: u32) -> impl Fn(&IdrTransferEvent) -> bool {
    move |e| e.kind == IDR_TEV_FINISHED && e.code == code
}

fn json(f: impl Fn(*mut c_char, usize) -> i32) -> serde_json::Value {
    let mut buf = vec![0u8; 256 * 1024];
    let n = f(buf.as_mut_ptr() as *mut c_char, buf.len());
    assert!(n >= 0, "json call failed: {n} {}", last_error_message());
    serde_json::from_slice(&buf[..n as usize]).unwrap()
}

fn bytes(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| ((i as u32).wrapping_mul(2_654_435_761) >> 24) as u8 ^ seed).collect()
}

fn file(dir: &Path, name: &str, n: usize) -> PathBuf {
    let p = dir.join(name);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, bytes(n, 7)).unwrap();
    p
}

fn sha(p: &Path) -> Vec<u8> {
    sha2::Sha256::digest(std::fs::read(p).unwrap()).to_vec()
}

fn hex(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

// ---- Tests -------------------------------------------------------------------

/// `idr.h` and the Rust exports agree on every transfer constant and the ABI version.
#[test]
fn header_matches_rust() {
    let h = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/include/idr.h")).unwrap();
    let val = |name: &str| -> u32 {
        let line = h.lines().find(|l| l.split_whitespace().any(|w| w.trim_end_matches(',') == name))
            .unwrap_or_else(|| panic!("{name} missing from idr.h"));
        let code = line.split("/*").next().unwrap();
        code.split(['=', ' ', ',']).filter_map(|t| t.trim().parse().ok()).next_back().unwrap()
    };
    assert_eq!(val("IDR_ABI_VERSION"), ABI_VERSION);
    assert_eq!(val("IDR_TRANSFER_ERROR_BASE"), IDR_TRANSFER_ERROR_BASE as u32);
    for (n, v) in [
        ("IDR_TEV_OFFERED", IDR_TEV_OFFERED), ("IDR_TEV_AWAITING_DECISION", IDR_TEV_AWAITING_DECISION),
        ("IDR_TEV_ACCEPTED", IDR_TEV_ACCEPTED), ("IDR_TEV_PROGRESS", IDR_TEV_PROGRESS),
        ("IDR_TEV_ENTRY_FAILED", IDR_TEV_ENTRY_FAILED), ("IDR_TEV_RENAMED", IDR_TEV_RENAMED),
        ("IDR_TEV_LEASE_EXPIRING", IDR_TEV_LEASE_EXPIRING), ("IDR_TEV_PAUSED", IDR_TEV_PAUSED),
        ("IDR_TEV_RESUMED", IDR_TEV_RESUMED), ("IDR_TEV_FINISHED", IDR_TEV_FINISHED),
        ("IDR_TEV_INTERRUPTED", IDR_TEV_INTERRUPTED), ("IDR_TEV_RESYNC", IDR_TEV_RESYNC),
        ("IDR_OUTCOME_COMPLETED", IDR_OUTCOME_COMPLETED), ("IDR_OUTCOME_COMPLETED_WITH_ERRORS", IDR_OUTCOME_COMPLETED_WITH_ERRORS),
        ("IDR_OUTCOME_FAILED", IDR_OUTCOME_FAILED), ("IDR_OUTCOME_CANCELLED", IDR_OUTCOME_CANCELLED),
        ("IDR_OUTCOME_REJECTED", IDR_OUTCOME_REJECTED),
    ] {
        assert_eq!(val(n), v, "{n}");
    }
    for k in 1..=19 {
        let kind = idr_protocol::transfer::TransferErrorKind::from_u32(k).unwrap();
        assert_eq!(val(&format!("IDR_TERR_{}", kind.as_str().to_uppercase())), k, "{}", kind.as_str());
    }
    assert!(idr_protocol::transfer::TransferErrorKind::from_u32(20).is_none(), "new kind: add it to idr.h");
}

/// Files, a folder and a selection through `idr_transfer_send*`; list, status
/// and bounded entry batches; argument errors never crash.
#[test]
fn send_files_folder_and_selection() {
    let w = world();
    let e = engine(&w, false);
    let src = tempfile::tempdir().unwrap();
    let mut seen = Vec::new();

    let a = file(src.path(), "a.bin", 3 << 20);
    let b = file(src.path(), "b.txt", 1000);
    let id = send(&e, &[&a, &b]);
    let done = wait(&e, &id, 60, &mut seen, finished(IDR_OUTCOME_COMPLETED));
    assert_eq!(done.entry, 0);
    assert_eq!(sha(&a), sha(&w.target_dir.path().join("a.bin")));
    assert!(seen.iter().any(|ev| ev.transfer_id == id && ev.kind == IDR_TEV_PROGRESS && ev.bytes_total == (3 << 20) + 1000));

    let list = json(|b, n| unsafe { idr_transfer_list(e.e(), b, n) });
    assert!(list.as_array().unwrap().iter().any(|t| t["id"] == hex(&id) && t["state"] == "completed"));
    let st = json(|b, n| unsafe { idr_transfer_status(e.e(), id.as_ptr(), b, n) });
    assert_eq!(st["summary"]["files"], 2);
    assert_eq!(st["path"], "host", "loopback runs host↔host (direct)");

    // Folder with 300 entries: entries come back in bounded batches.
    let folder = src.path().join("Project");
    for i in 0..300 {
        file(&folder, &format!("f{i:03}.txt"), 10);
    }
    let fid = send(&e, &[&folder]);
    wait(&e, &fid, 60, &mut seen, finished(IDR_OUTCOME_COMPLETED));
    assert!(w.target_dir.path().join("Project/f299.txt").is_file());
    let batch = json(|b, n| unsafe { idr_transfer_entries(e.e(), fid.as_ptr(), 0, 10_000, b, n) });
    assert_eq!(batch["total"], 301, "folder + 300 files");
    assert_eq!(batch["entries"].as_array().unwrap().len(), 256, "capped at 256 per call");
    let tail = json(|b, n| unsafe { idr_transfer_entries(e.e(), fid.as_ptr(), 256, 256, b, n) });
    assert_eq!(tail["entries"].as_array().unwrap().len(), 45);
    let mut small = [0 as c_char; 8];
    assert_eq!(
        unsafe { idr_transfer_list(e.e(), small.as_mut_ptr(), small.len()) },
        -(idr_core::IdrErrorKind::ResourceExhausted as i32),
        "too-small buffer is reported, not overrun"
    );

    // Selection: only the chosen paths, under the folder's name.
    let docs = src.path().join("Docs");
    file(&docs, "keep/one.txt", 50);
    file(&docs, "keep/two.txt", 50);
    file(&docs, "skip/three.txt", 50);
    file(&docs, "top.txt", 50);
    let (target, folder_c) = (CString::new(FQHN).unwrap(), CString::new(docs.to_str().unwrap()).unwrap());
    let sel: Vec<CString> = ["keep", "top.txt"].iter().map(|s| CString::new(*s).unwrap()).collect();
    let sel_ptrs: Vec<*const c_char> = sel.iter().map(|c| c.as_ptr()).collect();
    let mut sid = [0u8; 16];
    assert_eq!(
        unsafe { idr_transfer_send_selection(e.e(), target.as_ptr(), folder_c.as_ptr(), sel_ptrs.as_ptr(), 2, sid.as_mut_ptr()) },
        0
    );
    wait(&e, &sid, 60, &mut seen, finished(IDR_OUTCOME_COMPLETED));
    let t = w.target_dir.path().join("Docs");
    assert!(t.join("keep/one.txt").is_file() && t.join("keep/two.txt").is_file() && t.join("top.txt").is_file());
    assert!(!t.join("skip").exists(), "unselected entry was sent");
    let escape = [CString::new("../a.bin").unwrap()];
    let esc_ptrs: Vec<*const c_char> = escape.iter().map(|c| c.as_ptr()).collect();
    assert_eq!(
        unsafe { idr_transfer_send_selection(e.e(), target.as_ptr(), folder_c.as_ptr(), esc_ptrs.as_ptr(), 1, sid.as_mut_ptr()) },
        -(idr_core::IdrErrorKind::InvalidArgument as i32)
    );

    // Unknown ids, nulls and missing paths are errors, not crashes.
    let unknown = [9u8; 16];
    assert_eq!(unsafe { idr_transfer_pause(e.e(), unknown.as_ptr()) }, -(idr_core::IdrErrorKind::InvalidArgument as i32));
    assert_eq!(unsafe { idr_transfer_cancel(e.e(), std::ptr::null()) }, -(idr_core::IdrErrorKind::InvalidArgument as i32));
    assert_eq!(unsafe { idr_transfer_cancel(std::ptr::null_mut(), id.as_ptr()) }, -(idr_core::IdrErrorKind::InvalidArgument as i32));
    let missing = CString::new(src.path().join("nope.bin").to_str().unwrap()).unwrap();
    let mut out = [0u8; 16];
    assert_eq!(
        unsafe { idr_transfer_send(e.e(), target.as_ptr(), [missing.as_ptr()].as_ptr(), 1, out.as_mut_ptr()) },
        -(idr_core::IdrErrorKind::InvalidArgument as i32)
    );
    // A command on a finished transfer is a no-op, never a use-after-free.
    assert_eq!(unsafe { idr_transfer_cancel(e.e(), id.as_ptr()) }, 0);
}

/// Pause, resume and cancel from another thread while one thread keeps polling.
#[test]
fn pause_resume_cancel_while_polling() {
    let w = world();
    let e = engine(&w, false);
    let src = tempfile::tempdir().unwrap();
    let f = file(src.path(), "p.bin", 40 << 20);
    let id = send(&e, &[&f]);
    let mut seen = Vec::new();
    wait(&e, &id, 60, &mut seen, |ev| ev.kind == IDR_TEV_PROGRESS && ev.bytes_done >= 2 << 20);

    let ptr = e.e() as usize;
    let cmds = std::thread::spawn(move || {
        let e = ptr as *mut IdrEngine;
        assert_eq!(unsafe { idr_transfer_pause(e, id.as_ptr()) }, 0);
        std::thread::sleep(Duration::from_millis(600));
        assert_eq!(unsafe { idr_transfer_resume(e, id.as_ptr()) }, 0);
    });
    let until = Instant::now() + Duration::from_millis(400);
    while Instant::now() < until {
        poll(&e, &mut seen);
        std::thread::sleep(Duration::from_millis(5));
    }
    let st = json(|b, n| unsafe { idr_transfer_status(e.e(), id.as_ptr(), b, n) });
    assert_eq!(st["state"], "paused");
    cmds.join().unwrap();
    wait(&e, &id, 120, &mut seen, finished(IDR_OUTCOME_COMPLETED));
    assert_eq!(sha(&f), sha(&w.target_dir.path().join("p.bin")));

    let g = file(src.path(), "c.bin", 40 << 20);
    let id = send(&e, &[&g]);
    wait(&e, &id, 60, &mut seen, |ev| ev.kind == IDR_TEV_PROGRESS && ev.bytes_done >= 2 << 20);
    assert_eq!(unsafe { idr_transfer_cancel(e.e(), id.as_ptr()) }, 0);
    let done = wait(&e, &id, 30, &mut seen, |ev| ev.kind == IDR_TEV_FINISHED);
    assert_eq!(done.code, IDR_OUTCOME_CANCELLED);
    assert!(!w.target_dir.path().join("c.bin").exists());
}

/// Destroying the engine mid-transfer stops it resumably; a new engine on the
/// same data_dir finishes it from where it was, not from zero.
#[test]
fn destroy_mid_transfer_then_resume() {
    let w = world();
    let src = tempfile::tempdir().unwrap();
    let f = file(src.path(), "restart.bin", 40 << 20);
    let mut seen = Vec::new();
    let id = {
        let e = engine(&w, false);
        let id = send(&e, &[&f]);
        wait(&e, &id, 60, &mut seen, |ev| ev.kind == IDR_TEV_PROGRESS && ev.bytes_done >= 4 << 20);
        id
    }; // idr_engine_destroy here, transfer still running
    let e = engine(&w, false);
    let mut after = Vec::new();
    wait(&e, &id, 120, &mut after, finished(IDR_OUTCOME_COMPLETED));
    let first = after.iter().find(|ev| ev.transfer_id == id && ev.kind == IDR_TEV_PROGRESS).expect("no progress after restart");
    assert!(first.bytes_done > 0, "restart resent from zero");
    assert_eq!(sha(&f), sha(&w.target_dir.path().join("restart.bin")));
}

/// Target → engine: an interactive offer surfaces as AWAITING_DECISION;
/// accept stores it in the directory the user picked; reject refuses the sender.
#[test]
fn incoming_offer_accept_and_reject() {
    let w = world();
    let e = engine(&w, true);
    // Sending once brings up the bound session the Target sends back on.
    let src = tempfile::tempdir().unwrap();
    let warm = file(src.path(), "warm.txt", 10);
    let wid = send(&e, &[&warm]);
    let mut seen = Vec::new();
    wait(&e, &wid, 60, &mut seen, finished(IDR_OUTCOME_COMPLETED));
    let session = *w.endpoint.bound_sessions().first().expect("no bound session");

    let offer = |name: &str| {
        let f = file(src.path(), name, 200_000);
        let (files, sel) = NativeFiles::loose(&[f]).unwrap();
        let m = build(ManifestKind::Files, sel, &Limits::default()).unwrap();
        let ep = w.endpoint.clone();
        w.rt.spawn(async move {
            let (_tx, rx) = tokio::sync::mpsc::channel(1);
            ep.send(session, Outgoing { transfer_id: new_transfer_id(), manifest: m, files, resume: false }, rx).await
        })
    };

    let awaiting = |seen: &mut Vec<IdrTransferEvent>| {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let from = seen.len();
            poll(&e, seen);
            if let Some(ev) = seen[from..].iter().find(|ev| ev.kind == IDR_TEV_AWAITING_DECISION) {
                return ev.transfer_id;
            }
            assert!(Instant::now() < deadline, "offer never awaited a decision");
            std::thread::sleep(Duration::from_millis(20));
        }
    };

    let first = offer("incoming.bin");
    let pid = awaiting(&mut seen);
    let st = json(|b, n| unsafe { idr_transfer_status(e.e(), pid.as_ptr(), b, n) });
    assert_eq!((st["state"].as_str(), st["direction"].as_str(), st["summary"]["files"].as_u64()), (Some("pending"), Some("incoming"), Some(1)));
    let picked = tempfile::tempdir().unwrap();
    let out = CString::new(picked.path().to_str().unwrap()).unwrap();
    assert_eq!(unsafe { idr_transfer_accept(e.e(), pid.as_ptr(), out.as_ptr()) }, 0, "{}", last_error_message());
    assert_eq!(w.rt.block_on(first).unwrap(), Outcome::Completed);
    assert!(picked.path().join("incoming.bin").is_file(), "not stored where the user picked");
    wait(&e, &pid, 30, &mut seen, finished(IDR_OUTCOME_COMPLETED));
    let ent = json(|b, n| unsafe { idr_transfer_entries(e.e(), pid.as_ptr(), 0, 10, b, n) });
    assert_eq!(ent["entries"][0]["path"], "incoming.bin", "incoming manifest available for detail");

    let second = offer("unwanted.bin");
    let pid = awaiting(&mut seen);
    assert_eq!(unsafe { idr_transfer_reject(e.e(), pid.as_ptr()) }, 0);
    assert_eq!(w.rt.block_on(second).unwrap(), Outcome::Rejected(idr_protocol::transfer::TransferErrorKind::Rejected));
    assert!(!w.inbox.path().join("unwanted.bin").exists());
    // Deciding twice: the transfer layer refuses with a stable code.
    let rc = unsafe { idr_transfer_reject(e.e(), pid.as_ptr()) };
    assert_eq!(rc, -(IDR_TRANSFER_ERROR_BASE + 5), "second reject → rejected");
    assert_eq!(last_error_message(), "rejected");
}
