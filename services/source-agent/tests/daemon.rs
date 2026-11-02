//! The Source daemon over real WebRTC (libdatachannel) against an in-process
//! Target: agent-owned transfers, reconnects, restarts and incoming transfers.

#[path = "../../../crates/idr-target/tests/common/mod.rs"]
mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use common::*;
use ed25519_dalek::SigningKey;
use idr_protocol::transfer::{new_transfer_id, ManifestKind, TransferErrorKind as K, TransferId};
use idr_protocol::webrtc_signaling::SourceAuthMode;
use idr_source::SourceRuntime;
use idr_target::webrtc::local::{TransferConfig, TransferEndpoint};
use idr_transfer::bind::LocalIdentity;
use idr_transfer::manifest::build;
use idr_transfer::native::manager::{Direction, State};
use idr_transfer::native::NativeFiles;
use idr_transfer::policy::{PeerRule, PolicyEngine, ReceivePolicy};
use idr_transfer::{Limits, Outcome, Outgoing};
use idr_webrtc::native::NativePeerConfig;
use idr_webrtc::{NativePeer, PeerConnectRequest, PeerEvent, PeerTransport};
use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, SanType};
use sha2::Digest;
use idr_transfer::native::ipc::{call, CallError, IpcAddr, Request};
use source_agent::daemon::{Daemon, DaemonConfig, RuntimeFactory};
use tokio::sync::{mpsc, watch};

// ---- PKI -------------------------------------------------------------------

fn keys(seed: u8) -> (SigningKey, KeyPair) {
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ];
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

// ---- A peer the test can kill ----------------------------------------------

/// Native peer that reports `Closed` once the kill counter passes its birth value.
struct KillablePeer {
    inner: NativePeer,
    born: u64,
    kill: watch::Receiver<u64>,
}

#[async_trait]
impl PeerTransport for KillablePeer {
    async fn start(&mut self, r: PeerConnectRequest) -> idr_core::Result<()> {
        self.inner.start(r).await
    }
    async fn set_remote_description(&mut self, t: &str, sdp: &str) -> idr_core::Result<()> {
        self.inner.set_remote_description(t, sdp).await
    }
    async fn create_local_description(&mut self) -> idr_core::Result<()> {
        self.inner.create_local_description().await
    }
    fn add_remote_candidate(&mut self, c: &str, m: &str) -> idr_core::Result<()> {
        self.inner.add_remote_candidate(c, m)
    }
    fn send_binary(&mut self, b: &[u8]) -> idr_core::Result<()> {
        self.inner.send_binary(b)
    }
    async fn next_event(&mut self) -> idr_core::Result<PeerEvent> {
        let born = self.born;
        tokio::select! {
            ev = self.inner.next_event() => ev,
            _ = self.kill.wait_for(|k| *k > born) => Ok(PeerEvent::Closed),
        }
    }
    fn close(&mut self) {
        self.inner.close();
    }
    fn set_ice_servers_json(&mut self, json: &str) -> idr_core::Result<()> {
        self.inner.set_ice_servers_json(json)
    }
    fn buffered_amount(&self) -> usize {
        self.inner.buffered_amount()
    }
    fn selected_candidate_pair(&self) -> Option<(String, String)> {
        self.inner.selected_candidate_pair()
    }
}

// ---- World -----------------------------------------------------------------

const SRC: &str = "src-ski";
const TGT: &str = "tgt-ski";

struct World {
    pki: Pki,
    endpoint: Arc<TransferEndpoint>,
    target_dir: PathBuf,
    data_dir: PathBuf,
    source_inbox: PathBuf,
    runtimes: RuntimeFactory,
    kill: watch::Sender<u64>,
    ipc: Option<IpcAddr>,
    alt_inbox: PathBuf,
    /// The endpoint new sessions reach; swapped to simulate a target-agent restart.
    slot: Arc<std::sync::Mutex<Arc<TransferEndpoint>>>,
    _tmp: Vec<tempfile::TempDir>,
}

fn auto(ski: &str) -> ReceivePolicy {
    let mut p = ReceivePolicy::headless();
    p.peers.insert(ski.into(), PeerRule { auto_accept: true, ..PeerRule::default() });
    p
}

fn target_endpoint(pki: &Pki, dir: &Path, policy: ReceivePolicy) -> Arc<TransferEndpoint> {
    let (endpoint, events) = TransferEndpoint::new(TransferConfig {
        identity: pki.device(4, TGT, Some(FQHN)),
        roots: vec![pki.root.der().to_vec()],
        policy: PolicyEngine::new(policy, None),
        receive_dir: dir.to_path_buf(),
        limits: Limits::default(),
        bind_timeout: Duration::from_secs(5),
        manager: None,
        offer_expiry: None,
    });
    std::mem::forget(events);
    endpoint
}

async fn world() -> World {
    world_with(auto(SRC)).await
}

async fn world_with(target_policy: ReceivePolicy) -> World {
    world_at(target_policy, None).await
}

/// `dirs`: (Target receive dir, Source data dir) to reuse, e.g. after a crash.
async fn world_at(target_policy: ReceivePolicy, dirs: Option<(PathBuf, PathBuf)>) -> World {
    let pki = Pki::new();
    let mut tmp = Vec::new();
    let mut fresh = || {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().to_path_buf();
        tmp.push(t);
        p
    };
    let (target_dir, data_dir) = dirs.unwrap_or_else(|| (fresh(), fresh()));
    let (source_inbox, alt_inbox) = (fresh(), fresh());
    let endpoint = target_endpoint(&pki, &target_dir, target_policy);
    let slot = Arc::new(std::sync::Mutex::new(endpoint.clone()));
    let connectors = services().await;
    let (kill, kill_rx) = watch::channel(0u64);
    let ep = slot.clone();
    let runtimes: RuntimeFactory = Arc::new(move || {
        let presence = LoopPresence {
            connectors: connectors.clone(),
            transfers: Some(ep.lock().unwrap().clone()),
            attested_ski: Some(SRC.into()),
            relay: None,
        };
        let kill = kill_rx.clone();
        SourceRuntime::with_auth(
            Box::new(presence),
            move || {
                Box::new(KillablePeer {
                    inner: NativePeer::new(NativePeerConfig::default()).unwrap(),
                    born: *kill.borrow(),
                    kill: kill.clone(),
                })
            },
            "daemon-src",
            "local",
            SourceAuthMode::Bearer,
            Some("t".into()),
        )
    });
    World {
        pki,
        endpoint,
        target_dir,
        data_dir,
        source_inbox,
        runtimes,
        kill,
        ipc: None,
        alt_inbox,
        slot,
        _tmp: tmp,
    }
}

fn start(w: &World, receive_policy: ReceivePolicy) -> Daemon {
    Daemon::start(
        DaemonConfig {
            data_dir: w.data_dir.as_path().to_path_buf(),
            targets: vec![FQHN.into()],
            identity: Arc::new(w.pki.device(3, SRC, None)),
            roots: vec![w.pki.root.der().to_vec()],
            receive_dir: w.source_inbox.as_path().to_path_buf(),
            receive_policy,
            send_policy: Default::default(),
            limits: Limits::default(),
            reconnect_min: Duration::from_millis(100),
            reconnect_max: Duration::from_secs(1),
            ipc: w.ipc.clone(),
            permitted_dirs: vec![w.alt_inbox.as_path().to_path_buf()],
            offer_expiry: Duration::from_secs(30),
        },
        w.runtimes.clone(),
    )
    .unwrap()
}

async fn wait_state(d: &Daemon, id: &TransferId, secs: u64, want: impl Fn(&State) -> bool) -> State {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let s = d.manager().status(id).map(|i| i.state);
        if let Some(s) = &s {
            if want(s) {
                return s.clone();
            }
        }
        assert!(tokio::time::Instant::now() < deadline, "state stuck at {s:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_bytes(d: &Daemon, id: &TransferId, at_least: u64) {
    for _ in 0..400 {
        if d.manager().status(id).is_some_and(|i| i.progress.bytes_done >= at_least) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("transfer made no progress");
}

fn bytes(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| ((i as u32).wrapping_mul(2_654_435_761) >> 24) as u8 ^ seed).collect()
}

fn file(dir: &Path, name: &str, n: usize) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, bytes(n, 9)).unwrap();
    p
}

fn sha(p: &Path) -> Vec<u8> {
    sha2::Sha256::digest(std::fs::read(p).unwrap()).to_vec()
}

fn completed(s: &State) -> bool {
    *s == State::Done(Outcome::Completed)
}

// ---- Tests -----------------------------------------------------------------

/// CLI-001 / CLI-003 / CLI-012 / CLI-019: the daemon owns a queued transfer;
/// the caller only gets an id back.
#[tokio::test(flavor = "multi_thread")]
async fn queued_file_and_folder_complete() {
    let w = world().await;
    let d = start(&w, ReceivePolicy::headless());
    let src = tempfile::tempdir().unwrap();
    let f = file(src.path(), "report.pdf", 3 << 20);
    let id = d.send_paths(FQHN, std::slice::from_ref(&f)).unwrap();
    wait_state(&d, &id, 60, completed).await;
    assert_eq!(sha(&f), sha(&w.target_dir.as_path().join("report.pdf")));
    // In-process loopback: the selected ICE pair is host↔host, i.e. direct.
    let info = idr_transfer::native::manager::info_json(&d.manager().status(&id).unwrap());
    assert_eq!((info["path"].as_str(), info["relayed"].as_bool()), (Some("host"), Some(false)));
    assert_eq!(info["connection"], "direct");
    // The Target classifies the same pair from its side and agrees.
    let target_view = w.endpoint.peer(bound_session(&w).await).unwrap().path;
    assert_eq!(target_view, Some(idr_protocol::webrtc_ice::IcePath::Host));

    let folder = src.path().join("Project");
    std::fs::create_dir_all(folder.join("src")).unwrap();
    file(&folder, "README.md", 100);
    file(&folder.join("src"), "main.rs", 4000);
    let id = d.send_paths(FQHN, &[folder]).unwrap();
    wait_state(&d, &id, 60, completed).await;
    assert!(w.target_dir.as_path().join("Project/src/main.rs").is_file());
    d.shutdown().await;
}

/// REL-012 / REL-013 / RTC-007 / RTC-008: the session dies mid-transfer; the
/// supervisor reconnects and re-binds, and the manager resumes on its own.
#[tokio::test(flavor = "multi_thread")]
async fn survives_a_dropped_session() {
    let w = world().await;
    let d = start(&w, ReceivePolicy::headless());
    let src = tempfile::tempdir().unwrap();
    let f = file(src.path(), "big.bin", 40 << 20);
    let id = d.send_paths(FQHN, std::slice::from_ref(&f)).unwrap();
    wait_bytes(&d, &id, 4 << 20).await;
    w.kill.send_modify(|k| *k += 1);
    wait_state(&d, &id, 120, completed).await;
    assert_eq!(sha(&f), sha(&w.target_dir.as_path().join("big.bin")));
    d.shutdown().await;
}

/// CLI-013 / RTC-009 / REL-017 / REL-019: the daemon stops mid-transfer; a new
/// daemon on the same data directory finishes it from where it was.
#[tokio::test(flavor = "multi_thread")]
async fn resumes_after_daemon_restart() {
    let w = world().await;
    let src = tempfile::tempdir().unwrap();
    let f = file(src.path(), "restart.bin", 40 << 20);
    let d = start(&w, ReceivePolicy::headless());
    let id = d.send_paths(FQHN, std::slice::from_ref(&f)).unwrap();
    wait_bytes(&d, &id, 4 << 20).await;
    d.shutdown().await;

    let d = start(&w, ReceivePolicy::headless());
    // The restored transfer waits for the session, so this sees its first report.
    let mut events = d.manager().subscribe();
    let restored = d.manager().status(&id).expect("transfer forgotten across restart");
    assert_eq!(restored.direction, Direction::Outgoing);
    wait_state(&d, &id, 120, completed).await;
    let resumed_from = std::iter::from_fn(|| events.try_recv().ok()).find_map(|(t, e)| match e {
        idr_transfer::TransferEvent::Progress(p) if t == id => Some(p.bytes_done),
        _ => None,
    });
    assert!(resumed_from.unwrap_or(0) > 0, "restart resent from zero");
    assert_eq!(sha(&f), sha(&w.target_dir.as_path().join("restart.bin")));
    d.shutdown().await;
}

/// REL-008 / REL-009 / CLI-009 / CLI-010: pause and resume, and cancel, through
/// the daemon's manager.
#[tokio::test(flavor = "multi_thread")]
async fn pause_resume_and_cancel() {
    let w = world().await;
    let d = start(&w, ReceivePolicy::headless());
    let src = tempfile::tempdir().unwrap();
    let f = file(src.path(), "p.bin", 40 << 20);
    let id = d.send_paths(FQHN, std::slice::from_ref(&f)).unwrap();
    wait_bytes(&d, &id, 2 << 20).await;
    d.manager().pause(&id).await.unwrap();
    assert_eq!(d.manager().status(&id).unwrap().state, State::Paused);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let held = d.manager().status(&id).unwrap().progress.bytes_done;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let later = d.manager().status(&id).unwrap().progress.bytes_done;
    assert!(later <= held + (1 << 20), "kept sending while paused ({held} → {later})");
    d.manager().resume(&id).await.unwrap();
    wait_state(&d, &id, 120, completed).await;
    assert_eq!(sha(&f), sha(&w.target_dir.as_path().join("p.bin")));

    let g = file(src.path(), "c.bin", 40 << 20);
    let id = d.send_paths(FQHN, &[g]).unwrap();
    wait_bytes(&d, &id, 2 << 20).await;
    d.manager().cancel(&id).await.unwrap();
    wait_state(&d, &id, 30, |s| *s == State::Done(Outcome::Cancelled)).await;
    assert!(!w.target_dir.as_path().join("c.bin").exists());
    d.shutdown().await;
}

async fn bound_session(w: &World) -> uuid::Uuid {
    for _ in 0..200 {
        if let Some(s) = w.endpoint.bound_sessions().first() {
            return *s;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("daemon never bound to the Target");
}

/// RTC-002 / CLI-014 / CLI-015: Target → Source lands in the daemon's receive
/// directory when a peer rule allows it, and is refused without one.
#[tokio::test(flavor = "multi_thread")]
async fn incoming_follows_local_policy() {
    for (policy, allowed) in [(auto(TGT), true), (ReceivePolicy::headless(), false)] {
        let w = world().await;
        let d = start(&w, policy);
        let session = bound_session(&w).await;
        let src = tempfile::tempdir().unwrap();
        let f = file(src.path(), "from-target.bin", 1 << 20);
        let (files, sel) = NativeFiles::loose(std::slice::from_ref(&f)).unwrap();
        let m = build(ManifestKind::Files, sel, &Limits::default()).unwrap();
        let (_tx, rx) = mpsc::channel(1);
        let o = w
            .endpoint
            .send(session, Outgoing { transfer_id: new_transfer_id(), manifest: m, files, resume: false }, rx)
            .await;
        if allowed {
            assert_eq!(o, Outcome::Completed);
            assert_eq!(sha(&f), sha(&w.source_inbox.as_path().join("from-target.bin")));
            let incoming = d.manager().list().into_iter().find(|i| i.direction == Direction::Incoming).unwrap();
            assert_eq!(incoming.state, State::Done(Outcome::Completed));
        } else {
            assert_eq!(o, Outcome::Rejected(K::Unauthorized));
            assert!(std::fs::read_dir(w.source_inbox.as_path()).unwrap().next().is_none());
        }
        d.shutdown().await;
    }
}

async fn pending_id(d: &Daemon) -> String {
    for _ in 0..200 {
        if let Some(i) = d.manager().list().into_iter().find(|i| i.state == State::Pending) {
            return idr_transfer::native::manager::info_json(&i)["id"].as_str().unwrap().to_string();
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no pending offer");
}

async fn ipc(w: &World, req: Request) -> idr_transfer::native::ipc::Response {
    call(w.ipc.as_ref().unwrap(), &req).await.expect("agent IPC unavailable")
}

/// CLI-001 / CLI-005..011 / CLI-019 / CLI-020 / AUTH-011 / UX-002: the local
/// IPC the `transfer` CLI uses, end to end against the running daemon.
#[tokio::test(flavor = "multi_thread")]
async fn ipc_controls_the_daemon() {
    let mut w = world().await;
    let dir = w.data_dir.as_path().to_path_buf();
    w.ipc = Some(IpcAddr::for_agent(&format!("sa-test-{}", uuid::Uuid::new_v4().simple()), &dir).unwrap());
    let d = start(&w, ReceivePolicy::interactive());
    tokio::time::sleep(Duration::from_millis(150)).await;
    let src = tempfile::tempdir().unwrap();

    // send / status / list
    let f = file(src.path(), "via-ipc.bin", 2 << 20);
    let r = ipc(&w, Request::Send { target: FQHN.into(), paths: vec![f.clone()] }).await;
    assert!(r.ok, "{r:?}");
    let id = r.data["id"].as_str().unwrap().to_string();
    let tid = idr_transfer::native::manager::parse_id(&id).unwrap();
    wait_state(&d, &tid, 60, completed).await;
    let st = ipc(&w, Request::Status { id: id.clone() }).await;
    assert_eq!(st.data["state"], "completed");
    assert_eq!(st.data["summary"]["top_level"][0], "via-ipc.bin");
    let list = ipc(&w, Request::List).await;
    assert!(list.data.as_array().unwrap().iter().any(|t| t["id"] == id));
    assert_eq!(ipc(&w, Request::Status { id: "nope".into() }).await.error.as_deref(), Some("invalid_argument"));

    // pause / resume / cancel
    let big = file(src.path(), "big.bin", 40 << 20);
    let id2 = ipc(&w, Request::Send { target: FQHN.into(), paths: vec![big] }).await.data["id"].as_str().unwrap().to_string();
    let tid2 = idr_transfer::native::manager::parse_id(&id2).unwrap();
    wait_bytes(&d, &tid2, 1 << 20).await;
    assert!(ipc(&w, Request::Pause { id: id2.clone() }).await.ok);
    assert_eq!(ipc(&w, Request::Status { id: id2.clone() }).await.data["state"], "paused");
    assert!(ipc(&w, Request::Resume { id: id2.clone() }).await.ok);
    assert!(ipc(&w, Request::Cancel { id: id2.clone() }).await.ok);
    wait_state(&d, &tid2, 30, |s| *s == State::Done(Outcome::Cancelled)).await;

    // An incoming offer waits for a decision (interactive, no auto-accept rule).
    let session = bound_session(&w).await;

    // peers: the bound Target, with how the session reaches it.
    let peers = ipc(&w, Request::Peers).await;
    assert_eq!(peers.data, serde_json::json!([{ "peer": FQHN, "path": "host", "connection": "direct" }]));
    let offer = |name: &str| {
        let f = file(src.path(), name, 100_000);
        let (files, sel) = NativeFiles::loose(&[f]).unwrap();
        let m = build(ManifestKind::Files, sel, &Limits::default()).unwrap();
        let ep = w.endpoint.clone();
        tokio::spawn(async move {
            let (_tx, rx) = mpsc::channel(1);
            ep.send(session, Outgoing { transfer_id: new_transfer_id(), manifest: m, files, resume: false }, rx).await
        })
    };
    let first = offer("incoming.bin");
    let pid = pending_id(&d).await;
    let shown = ipc(&w, Request::Status { id: pid.clone() }).await;
    assert_eq!((shown.data["state"].as_str(), shown.data["summary"]["files"].as_u64()), (Some("pending"), Some(1)));
    let outside = tempfile::tempdir().unwrap();
    let refused = ipc(&w, Request::Accept { id: pid.clone(), out: Some(outside.path().to_path_buf()) }).await;
    assert_eq!(refused.error.as_deref(), Some("unauthorized"), "accept into a non-permitted dir");
    assert!(ipc(&w, Request::Accept { id: pid.clone(), out: Some(w.alt_inbox.as_path().to_path_buf()) }).await.ok);
    assert_eq!(first.await.unwrap(), Outcome::Completed);
    assert!(w.alt_inbox.as_path().join("incoming.bin").is_file(), "not stored where accepted");

    let second = offer("unwanted.bin");
    let pid = pending_id(&d).await;
    assert!(ipc(&w, Request::Reject { id: pid }).await.ok);
    assert_eq!(second.await.unwrap(), Outcome::Rejected(K::Rejected));
    assert!(!w.source_inbox.as_path().join("unwanted.bin").exists());

    d.shutdown().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(matches!(call(w.ipc.as_ref().unwrap(), &Request::List).await, Err(CallError::Unavailable)));
}

/// An interactive receiver asks once. A resume of the accepted transfer (same
/// peer, id and manifest) after the session drops continues without asking
/// again; a "resume" with a different manifest under that id still asks.
#[tokio::test(flavor = "multi_thread")]
async fn interactive_resume_needs_no_second_accept() {
    let w = world().await;
    let d = start(&w, ReceivePolicy::interactive());
    let src = tempfile::tempdir().unwrap();
    let f = file(src.path(), "resumed.bin", 40 << 20);
    let id = new_transfer_id();
    let attempt = |session, path: &Path, resume| {
        let (files, sel) = NativeFiles::loose(&[path.to_path_buf()]).unwrap();
        let m = build(ManifestKind::Files, sel, &Limits::default()).unwrap();
        let ep = w.endpoint.clone();
        tokio::spawn(async move {
            let (_tx, rx) = mpsc::channel(1);
            ep.send(session, Outgoing { transfer_id: id, manifest: m, files, resume }, rx).await
        })
    };

    let first = attempt(bound_session(&w).await, &f, false);
    let pid = pending_id(&d).await;
    assert!(d.manager().accept(&idr_transfer::native::manager::parse_id(&pid).unwrap(), None, &[]).is_ok());
    wait_bytes(&d, &id, 4 << 20).await;
    w.kill.send_modify(|k| *k += 1);
    assert!(matches!(first.await.unwrap(), Outcome::Interrupted(_)));

    // Retry on a live session, as the manager does after an interruption. Asking
    // again would park the offer until it expires and end it as Rejected.
    let mut session = bound_session(&w).await;
    let mut outcome = Outcome::Interrupted(K::TransportClosed);
    for _ in 0..40 {
        let resumed = attempt(session, &f, true);
        outcome = tokio::time::timeout(Duration::from_secs(60), resumed).await.expect("resume waited for consent").unwrap();
        if !matches!(outcome, Outcome::Interrupted(_)) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
        session = bound_session(&w).await;
    }
    assert_eq!(outcome, Outcome::Completed);
    assert_eq!(sha(&f), sha(&w.source_inbox.as_path().join("resumed.bin")));

    // Same id, other content, claiming to resume: parked for a decision.
    let other = file(src.path(), "other.bin", 1000);
    let forged = attempt(session, &other, true);
    assert_eq!(pending_id(&d).await, idr_transfer::native::manager::info_json(&d.manager().status(&id).unwrap())["id"]);
    d.manager().reject(&id).unwrap();
    assert_eq!(forged.await.unwrap(), Outcome::Rejected(K::Rejected));
    d.shutdown().await;
}

/// The sender restarts and resumes before the receiver noticed the old attempt
/// died: the old attempt still holds the files. The resume takes over (no new
/// consent, no sharing violation at finish) and the file is intact.
#[tokio::test(flavor = "multi_thread")]
async fn resume_takes_over_a_lingering_attempt() {
    let w = world().await;
    let d = start(&w, ReceivePolicy::interactive());
    let src = tempfile::tempdir().unwrap();
    let f = file(src.path(), "overlap.bin", 40 << 20);
    let id = new_transfer_id();
    let session = bound_session(&w).await;
    let attempt = |resume| {
        let (files, sel) = NativeFiles::loose(std::slice::from_ref(&f)).unwrap();
        let m = build(ManifestKind::Files, sel, &Limits::default()).unwrap();
        let ep = w.endpoint.clone();
        tokio::spawn(async move {
            let (_tx, rx) = mpsc::channel(1);
            ep.send(session, Outgoing { transfer_id: id, manifest: m, files, resume }, rx).await
        })
    };
    let first = attempt(false);
    let pid = pending_id(&d).await;
    assert!(d.manager().accept(&idr_transfer::native::manager::parse_id(&pid).unwrap(), None, &[]).is_ok());
    wait_bytes(&d, &id, 4 << 20).await;
    let second = attempt(true);
    let outcome = tokio::time::timeout(Duration::from_secs(60), second).await.expect("resume stuck").unwrap();
    assert_eq!(outcome, Outcome::Completed);
    assert!(matches!(first.await.unwrap(), Outcome::Interrupted(_)));
    assert_eq!(sha(&f), sha(&w.source_inbox.as_path().join("overlap.bin")));
    wait_state(&d, &id, 10, completed).await;
    d.shutdown().await;
}

fn short_lease(mut p: ReceivePolicy) -> ReceivePolicy {
    p.lease = Duration::from_secs(4);
    p
}

/// AUTH-023..AUTH-028: a transfer outlives several 4 s authorization leases.
/// At each lease end it stops resumably (AuthorizationExpired), the Source
/// re-authorizes through a fresh session with no user involvement, and the
/// transfer completes from where it was.
#[tokio::test(flavor = "multi_thread")]
async fn transfer_survives_lease_expiry() {
    let w = world_with(short_lease(auto(SRC))).await;
    let d = start(&w, short_lease(ReceivePolicy::headless()));
    let mut events = d.manager().subscribe();
    let t0 = std::time::Instant::now();
    let src = tempfile::tempdir().unwrap();
    let f = file(src.path(), "leased.bin", 60 << 20);
    let id = d.send_paths(FQHN, std::slice::from_ref(&f)).unwrap();
    wait_state(&d, &id, 240, completed).await;
    assert_eq!(sha(&f), sha(&w.target_dir.as_path().join("leased.bin")));
    let expired = std::iter::from_fn(|| events.try_recv().ok())
        .filter(|(t, e)| {
            *t == id && matches!(e, idr_transfer::TransferEvent::Finished(Outcome::Interrupted(K::AuthorizationExpired)))
        })
        .count();
    eprintln!("lease test: {expired} lease-boundary stops, {:?}", t0.elapsed());
    assert!(expired >= 1, "no attempt ended at a lease boundary");
    d.shutdown().await;
}

/// REL-017 (target-agent restart): the Target's endpoint is replaced by a fresh
/// one on the same receive directory and every session drops mid-transfer. The
/// Source reconnects, re-binds and resumes from the Target's journal, not zero.
#[tokio::test(flavor = "multi_thread")]
async fn resumes_after_target_agent_restart() {
    let w = world().await;
    let d = start(&w, ReceivePolicy::headless());
    let mut events = d.manager().subscribe();
    let src = tempfile::tempdir().unwrap();
    let f = file(src.path(), "t-restart.bin", 40 << 20);
    let id = d.send_paths(FQHN, std::slice::from_ref(&f)).unwrap();
    wait_bytes(&d, &id, 8 << 20).await;
    *w.slot.lock().unwrap() = target_endpoint(&w.pki, w.target_dir.as_path(), auto(SRC));
    w.kill.send_modify(|k| *k += 1);
    wait_state(&d, &id, 120, completed).await;
    assert_eq!(sha(&f), sha(&w.target_dir.as_path().join("t-restart.bin")));
    // After the drop, the first progress of a new attempt starts above zero.
    let mut after_drop = false;
    let mut resumed_from = None;
    for (t, e) in std::iter::from_fn(|| events.try_recv().ok()) {
        if t != id {
            continue;
        }
        match e {
            idr_transfer::TransferEvent::Finished(Outcome::Interrupted(_)) => after_drop = true,
            idr_transfer::TransferEvent::Progress(p) if after_drop && resumed_from.is_none() => {
                resumed_from = Some(p.bytes_done)
            }
            _ => {}
        }
    }
    assert!(resumed_from.unwrap_or(0) > 0, "restart resent from zero ({resumed_from:?})");
    d.shutdown().await;
}

/// A resume refused for the peer's offer rate (LimitExceeded) waits and retries
/// instead of ending the transfer. Before the fix it ended as Rejected.
#[tokio::test(flavor = "multi_thread")]
async fn rate_limited_resume_retries() {
    let mut policy = auto(SRC);
    policy.offers_per_minute = 1;
    let w = world_with(policy).await;
    let d = start(&w, ReceivePolicy::headless());
    let src = tempfile::tempdir().unwrap();
    let f = file(src.path(), "limited.bin", 40 << 20);
    let id = d.send_paths(FQHN, std::slice::from_ref(&f)).unwrap();
    wait_bytes(&d, &id, 4 << 20).await;
    w.kill.send_modify(|k| *k += 1);
    wait_state(&d, &id, 30, |s| *s == State::Waiting(K::LimitExceeded)).await;
    wait_state(&d, &id, 150, completed).await;
    assert_eq!(sha(&f), sha(&w.target_dir.as_path().join("limited.bin")));
    d.shutdown().await;
}

// ---- Hard crash of both agents (also what a JWT remint does to target-agent) ---

const CRASH_ENV: &str = "IDR_TEST_CRASH_CHILD";

/// Child half of `resumes_after_both_agents_crash`: runs the Source daemon and
/// the Target endpoint, starts the transfer, and waits to be killed. A no-op
/// unless the parent test launched this binary with `IDR_TEST_CRASH_CHILD`.
#[tokio::test(flavor = "multi_thread")]
async fn crash_child() {
    let Ok(spec) = std::env::var(CRASH_ENV) else { return };
    let [target, data, file]: [&str; 3] = spec.split('|').collect::<Vec<_>>().try_into().unwrap();
    let w = world_at(auto(SRC), Some((target.into(), data.into()))).await;
    let d = start(&w, ReceivePolicy::headless());
    d.send_paths(FQHN, &[PathBuf::from(file)]).unwrap();
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn staged_bytes(target: &Path) -> u64 {
    std::fs::read_dir(target)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(".idr-partial-"))
        .filter_map(|e| std::fs::metadata(e.path().join("p").join("0")).ok())
        .map(|m| m.len())
        .max()
        .unwrap_or(0)
}

/// REL-017 / REL-019 / CLI-013, hard crash: both agents run in a child process
/// that is killed (TerminateProcess on Windows: no shutdown code runs) mid-
/// transfer. On Windows the SDK's JWT-remint restart of target-agent is the
/// same abrupt kill (`Process.kill`). Restarted on the same directories, the
/// Source resumes from its outbox and the Target from its journal, at a
/// verified checkpoint boundary, not zero; the result is byte-identical with
/// no duplicate file, no numbered copy, no leftover staging.
#[test]
fn resumes_after_both_agents_crash() {
    let (target, data, src) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let f = file(src.path(), "crash.bin", 60 << 20);
    let spec = format!("{}|{}|{}", target.path().display(), data.path().display(), f.display());
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["crash_child", "--exact", "--nocapture", "--test-threads=1"])
        .env(CRASH_ENV, spec)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    while staged_bytes(target.path()) < 14 << 20 {
        assert!(std::time::Instant::now() < deadline, "child made no progress");
        std::thread::sleep(Duration::from_millis(20));
    }
    child.kill().unwrap();
    child.wait().unwrap();
    let at_kill = staged_bytes(target.path());
    eprintln!("killed with {at_kill} bytes staged");

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let w = world_at(auto(SRC), Some((target.path().into(), data.path().into()))).await;
        let d = start(&w, ReceivePolicy::headless());
        let mut events = d.manager().subscribe();
        let restored = d.manager().list();
        assert_eq!(restored.len(), 1, "outbox should hold exactly the one transfer");
        let id = restored[0].id;
        wait_state(&d, &id, 180, completed).await;
        let first = std::iter::from_fn(|| events.try_recv().ok()).find_map(|(t, e)| match e {
            idr_transfer::TransferEvent::Progress(p) if t == id => Some(p.bytes_done),
            _ => None,
        });
        let resumed_from = first.expect("no progress after restart");
        eprintln!("resumed from {resumed_from} bytes");
        assert!(resumed_from > 0, "restart resent from zero");
        // The last 4 MiB checkpoint at or below what was on disk; the unproven
        // tail past it was cut back, not trusted.
        assert_eq!(resumed_from, at_kill / (4 << 20) * (4 << 20), "did not resume at the last verified checkpoint");
        d.shutdown().await;
    });
    assert_eq!(sha(&f), sha(&target.path().join("crash.bin")), "corrupted after crash + resume");
    let left: Vec<_> = std::fs::read_dir(target.path()).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(left, ["crash.bin"], "duplicate, numbered copy or staging left behind");
}
