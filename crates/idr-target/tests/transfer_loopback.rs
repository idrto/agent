//! File transfer over real WebRTC (libdatachannel): Source ↔ Target in one
//! process, identities bound in-band, real storage on both sides.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use common::*;
use ed25519_dalek::SigningKey;
use idr_core::{LogicalStream, StreamPriority};
use idr_protocol::peer_bind::{BindRole, TrustPolicy, VerifiedPeer, BIND_SERVICE};
use idr_protocol::transfer::{new_transfer_id, ManifestKind, TransferErrorKind as K, TransferId, TRANSFER_SERVICE};
use idr_source::{SessionOpener, SourceSession};
use idr_target::webrtc::local::{TransferConfig, TransferEndpoint};
use idr_transfer::bind::{bind_peer, LocalIdentity};
use idr_transfer::io::Framed;
use idr_transfer::manifest::{build, Selected};
use idr_transfer::native::{enumerate, NativeFiles, NativeSink};
use idr_transfer::policy::{PeerRule, PolicyEngine, ReceivePolicy};
use idr_transfer::storage::StreamOpener;
use idr_transfer::{receive, send, Command, Limits, Outcome, Outgoing, Routed, Router, TransferEvent};
use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, SanType};
use sha2::Digest;
use tokio::sync::mpsc;
use tokio::time::timeout;
use uuid::Uuid;

// ---- Identities (root-issued DP-shaped devices) ---------------------------

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

    fn trust(&self, require_dns: Option<&str>) -> TrustPolicy {
        TrustPolicy {
            roots: vec![self.root.der().to_vec()],
            require_ski: None,
            require_dns: require_dns.map(String::from),
            now: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        }
    }
}

fn accepting(ski: &str) -> PolicyEngine {
    let mut p = ReceivePolicy::headless();
    p.peers.insert(ski.into(), PeerRule { auto_accept: true, ..PeerRule::default() });
    PolicyEngine::new(p, None)
}

// ---- A connected, bound pair ----------------------------------------------

struct World {
    pki: Pki,
    session: SourceSession,
    endpoint: Arc<TransferEndpoint>,
    target_events: mpsc::UnboundedReceiver<(TransferId, TransferEvent)>,
    target_dir: tempfile::TempDir,
    /// What the Source proved about the Target (None: binding failed).
    target_peer: Option<VerifiedPeer>,
}

struct Setup {
    /// Presence attests the Source's SKI.
    attest: bool,
    /// The identity the Source actually presents.
    source_ski: &'static str,
}

const SOURCE_SKI: &str = "src-ski";

async fn world(setup: Setup) -> World {
    world_via(setup, None).await
}

async fn world_via(setup: Setup, relay: Option<Vec<idr_protocol::webrtc_ice::IceServer>>) -> World {
    let pki = Pki::new();
    let target_dir = tempfile::tempdir().unwrap();
    let (endpoint, target_events) = TransferEndpoint::new(TransferConfig {
        identity: pki.device(4, "tgt-ski", Some(FQHN)),
        roots: vec![pki.root.der().to_vec()],
        policy: accepting(SOURCE_SKI),
        receive_dir: target_dir.path().to_path_buf(),
        limits: Limits::default(),
        bind_timeout: Duration::from_secs(5),
        manager: None,
        offer_expiry: None,
    });
    let session = connect_to(LoopPresence {
        connectors: services().await,
        transfers: Some(endpoint.clone()),
        attested_ski: setup.attest.then(|| SOURCE_SKI.to_string()),
        relay,
    })
    .await;
    let target_peer = bind(&session, &pki, setup.source_ski).await;
    World { pki, session, endpoint, target_events, target_dir, target_peer }
}

async fn bind(session: &SourceSession, pki: &Pki, ski: &str) -> Option<VerifiedPeer> {
    let me = pki.device(3, ski, None);
    let stream = session.opener().open(BIND_SERVICE, StreamPriority::Interactive).await.ok()?;
    let peer = bind_peer(
        &mut Framed::new(stream),
        BindRole::Offerer,
        session.bind_context(),
        &me,
        &pki.trust(Some(FQHN)),
        Duration::from_secs(5),
    )
    .await
    .ok()?;
    Some(peer)
}

fn session_uuid(s: &SourceSession) -> Uuid {
    Uuid::parse_str(&s.bind_context().session_id).unwrap()
}

/// Wait until the Target has the Source bound on this session.
async fn target_bound(w: &World) -> bool {
    for _ in 0..100 {
        if w.endpoint.peer(session_uuid(&w.session)).is_some() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

struct Opener(SessionOpener);

#[async_trait]
impl StreamOpener for Opener {
    async fn open(&mut self) -> idr_core::Result<Box<dyn LogicalStream>> {
        self.0.open(TRANSFER_SERVICE, StreamPriority::Bulk).await
    }
}

fn limits() -> Limits {
    Limits { step_timeout: Duration::from_secs(10), ..Limits::default() }
}

/// Source → Target. Returns (sender outcome, Target outcome, sender events).
async fn to_target(w: &mut World, m: idr_protocol::transfer::Manifest, files: NativeFiles, id: TransferId, resume: bool, cmds: mpsc::Receiver<Command>) -> (Outcome, Outcome, Vec<TransferEvent>) {
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
    let req = Outgoing { transfer_id: id, manifest: m, files, resume };
    // Generous: the 100k-entry test spends minutes on per-file fsync + rename.
    let sender = timeout(Duration::from_secs(1200), send(&mut Opener(w.session.opener()), req, &limits(), ev_tx, cmds))
        .await
        .expect("sender hung");
    let receiver = timeout(Duration::from_secs(30), async {
        loop {
            match w.target_events.recv().await {
                Some((tid, TransferEvent::Finished(o))) if tid == id => return o,
                Some(_) => {}
                None => return Outcome::Interrupted(K::TransportClosed),
            }
        }
    })
    .await
    .unwrap_or(Outcome::Interrupted(K::Timeout));
    let events = std::iter::from_fn(|| ev_rx.try_recv().ok()).collect();
    (sender, receiver, events)
}

fn no_cmds() -> mpsc::Receiver<Command> {
    let (tx, rx) = mpsc::channel(1);
    std::mem::forget(tx);
    rx
}

/// Accept Target → Source transfers into `dir`; outcomes arrive on the receiver.
async fn source_receives(w: &mut World, dir: &Path) -> mpsc::UnboundedReceiver<Outcome> {
    let mut incoming = w.session.accept_streams(&[TRANSFER_SERVICE]).await;
    let router = Router::default();
    let peer = w.target_peer.clone();
    let dir = dir.to_path_buf();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(inc) = incoming.recv().await {
            if let Routed::Control { header, stream } = router.route(inc.stream, Duration::from_secs(5)).await {
                let (router, peer, dir, tx) = (router.clone(), peer.clone(), dir.clone(), tx.clone());
                tokio::spawn(async move {
                    let mut sink = NativeSink::new(&dir).unwrap();
                    let mut consent = accepting("tgt-ski").consent(peer, None);
                    let (ev, _evs) = mpsc::unbounded_channel();
                    let o = receive(&router, header, stream, &mut sink, &mut consent, &limits(), ev, no_cmds()).await;
                    let _ = tx.send(o);
                });
            }
        }
    });
    rx
}

// ---- Files ------------------------------------------------------------------

fn bytes(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| ((i as u32).wrapping_mul(2_654_435_761) >> 24) as u8 ^ seed).collect()
}

fn write(root: &Path, rel: &str, data: &[u8]) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, data).unwrap();
}

fn sha_file(p: &Path) -> Vec<u8> {
    sha2::Sha256::digest(std::fs::read(p).unwrap()).to_vec()
}

fn project(root: &Path) {
    write(root, "Project/README.md", b"# readme");
    write(root, "Project/empty.txt", b"");
    write(root, "Project/src/main.dart", &bytes(5000, 1));
    write(root, "Project/src/network/client.dart", &bytes(900, 2));
    write(root, "Project/docs/guide.pdf", &bytes(300_000, 3));
    std::fs::create_dir_all(root.join("Project/empty-folder")).unwrap();
}

fn folder_manifest(root: &Path, sel: &[&str]) -> idr_protocol::transfer::Manifest {
    let dir = cap_std::fs::Dir::open_ambient_dir(root, cap_std::ambient_authority()).unwrap();
    let sels: Vec<Vec<String>> = sel.iter().map(|s| s.split('/').map(String::from).collect()).collect();
    build(ManifestKind::Folder, enumerate(&dir, &sels).unwrap().selected, &Limits::default()).unwrap()
}

fn same_tree(a: &Path, b: &Path, rels: &[&str]) {
    for r in rels {
        assert_eq!(sha_file(&a.join(r)), sha_file(&b.join(r)), "{r}");
    }
}

// ---- Tests ------------------------------------------------------------------

/// RTC-001 (scaled to 24 MB) / RTC-003 / AUTH-001 over real WebRTC: bound
/// identities, a large file and a nested folder, Source → Target.
#[tokio::test(flavor = "multi_thread")]
async fn source_sends_file_and_folder_to_target() {
    let mut w = world(Setup { attest: true, source_ski: SOURCE_SKI }).await;
    assert_eq!(w.target_peer.as_ref().map(|p| p.ski.as_str()), Some("tgt-ski"), "Source verified the Target");
    assert!(target_bound(&w).await, "Target verified the Source");

    let src = tempfile::tempdir().unwrap();
    write(src.path(), "big.bin", &bytes(24 << 20, 7));
    let (files, sel) = NativeFiles::loose(&[src.path().join("big.bin")]).unwrap();
    let m = build(ManifestKind::Files, sel, &Limits::default()).unwrap();
    let (s, r, _) = to_target(&mut w, m, files, new_transfer_id(), false, no_cmds()).await;
    assert_eq!((s, r), (Outcome::Completed, Outcome::Completed));
    assert_eq!(sha_file(&src.path().join("big.bin")), sha_file(&w.target_dir.path().join("big.bin")));

    project(src.path());
    let m = folder_manifest(src.path(), &["Project"]);
    let (s, r, _) = to_target(&mut w, m, NativeFiles::new(src.path()).unwrap(), new_transfer_id(), false, no_cmds()).await;
    assert_eq!((s, r), (Outcome::Completed, Outcome::Completed));
    same_tree(src.path(), w.target_dir.path(), &[
        "Project/README.md", "Project/empty.txt", "Project/src/main.dart",
        "Project/src/network/client.dart", "Project/docs/guide.pdf",
    ]);
    assert!(w.target_dir.path().join("Project/empty-folder").is_dir());
}

/// RTC-005: a selection arrives as exactly that selection.
#[tokio::test(flavor = "multi_thread")]
async fn selective_folder_over_webrtc() {
    let mut w = world(Setup { attest: true, source_ski: SOURCE_SKI }).await;
    assert!(target_bound(&w).await);
    let src = tempfile::tempdir().unwrap();
    project(src.path());
    let m = folder_manifest(src.path(), &["Project/src/network", "Project/docs/guide.pdf"]);
    let (s, r, _) = to_target(&mut w, m, NativeFiles::new(src.path()).unwrap(), new_transfer_id(), false, no_cmds()).await;
    assert_eq!((s, r), (Outcome::Completed, Outcome::Completed));
    let got = w.target_dir.path().join("Project");
    assert!(got.join("src/network/client.dart").is_file());
    assert!(got.join("docs/guide.pdf").is_file());
    assert!(!got.join("README.md").exists() && !got.join("src/main.dart").exists());
}

/// RTC-002 / RTC-004 / RTC-011: Target → Source (Source verified the Target
/// first), concurrently with Source → Target.
#[tokio::test(flavor = "multi_thread")]
async fn both_directions_at_once() {
    let mut w = world(Setup { attest: true, source_ski: SOURCE_SKI }).await;
    assert!(target_bound(&w).await);
    let source_dir = tempfile::tempdir().unwrap();
    let mut source_outcomes = source_receives(&mut w, source_dir.path()).await;

    let tsrc = tempfile::tempdir().unwrap();
    project(tsrc.path());
    let to_source = {
        let endpoint = w.endpoint.clone();
        let session = session_uuid(&w.session);
        let m = folder_manifest(tsrc.path(), &["Project"]);
        let files = NativeFiles::new(tsrc.path()).unwrap();
        tokio::spawn(async move {
            endpoint.send(session, Outgoing { transfer_id: new_transfer_id(), manifest: m, files, resume: false }, no_cmds()).await
        })
    };
    let ssrc = tempfile::tempdir().unwrap();
    write(ssrc.path(), "up.bin", &bytes(8 << 20, 5));
    let (files, sel) = NativeFiles::loose(&[ssrc.path().join("up.bin")]).unwrap();
    let m = build(ManifestKind::Files, sel, &Limits::default()).unwrap();
    let (s, r, _) = to_target(&mut w, m, files, new_transfer_id(), false, no_cmds()).await;
    assert_eq!((s, r), (Outcome::Completed, Outcome::Completed));

    assert_eq!(to_source.await.unwrap(), Outcome::Completed);
    let o = timeout(Duration::from_secs(10), source_outcomes.recv()).await.unwrap().unwrap();
    assert_eq!(o, Outcome::Completed);
    same_tree(tsrc.path(), source_dir.path(), &["Project/src/main.dart", "Project/docs/guide.pdf", "Project/empty.txt"]);
    assert_eq!(sha_file(&ssrc.path().join("up.bin")), sha_file(&w.target_dir.path().join("up.bin")));
}

/// RTC-006 / ST-001: ten thousand small files in one folder transfer.
#[tokio::test(flavor = "multi_thread")]
async fn ten_thousand_small_files() {
    let mut w = world(Setup { attest: true, source_ski: SOURCE_SKI }).await;
    assert!(target_bound(&w).await);
    let src = tempfile::tempdir().unwrap();
    for i in 0..10_000 {
        write(src.path(), &format!("Many/d{}/f{i:05}.txt", i % 50), &bytes(64, i as u8));
    }
    let m = folder_manifest(src.path(), &["Many"]);
    assert_eq!(m.entries.len(), 10_051);
    let started = std::time::Instant::now();
    let (s, r, events) = to_target(&mut w, m, NativeFiles::new(src.path()).unwrap(), new_transfer_id(), false, no_cmds()).await;
    assert_eq!((s, r), (Outcome::Completed, Outcome::Completed));
    eprintln!("10,000 files in {:?}, {} sender events", started.elapsed(), events.len());
    assert!(events.len() < 1000, "events grew with file count: {}", events.len());
    assert_eq!(sha_file(&src.path().join("Many/d7/f09957.txt")), sha_file(&w.target_dir.path().join("Many/d7/f09957.txt")));
}

/// RTC-016 / AUTH-002 / AUTH-003: an unverified Source (Presence attested
/// nothing) or an impostor (wrong device) can connect but can't transfer.
#[tokio::test(flavor = "multi_thread")]
async fn unverified_or_impostor_source_cannot_transfer() {
    for setup in [
        Setup { attest: false, source_ski: SOURCE_SKI },
        Setup { attest: true, source_ski: "someone-else" },
    ] {
        let mut w = world(setup).await;
        assert!(!target_bound(&w).await, "Target bound an unverified Source");
        let src = tempfile::tempdir().unwrap();
        write(src.path(), "x.bin", b"payload");
        let (files, sel) = NativeFiles::loose(&[src.path().join("x.bin")]).unwrap();
        let m = build(ManifestKind::Files, sel, &Limits::default()).unwrap();
        let (ev_tx, _ev) = mpsc::unbounded_channel();
        let req = Outgoing { transfer_id: new_transfer_id(), manifest: m, files, resume: false };
        let o = send(&mut Opener(w.session.opener()), req, &limits(), ev_tx, no_cmds()).await;
        assert!(!matches!(o, Outcome::Completed), "transfer completed: {o:?}");
        assert!(std::fs::read_dir(w.target_dir.path()).unwrap().next().is_none(), "something was stored");
    }
}

/// RTC-010 / REG-004: a tunnel-style stream stays responsive during a transfer.
#[tokio::test(flavor = "multi_thread")]
async fn tunnel_stays_responsive_during_transfer() {
    let mut w = world(Setup { attest: true, source_ski: SOURCE_SKI }).await;
    assert!(target_bound(&w).await);
    let mut tunnel = w.session.open_named_stream("echo").await.unwrap();
    let src = tempfile::tempdir().unwrap();
    write(src.path(), "bulk.bin", &bytes(32 << 20, 9));
    let (files, sel) = NativeFiles::loose(&[src.path().join("bulk.bin")]).unwrap();
    let m = build(ManifestKind::Files, sel, &Limits::default()).unwrap();
    let opener = w.session.opener();
    let transfer = tokio::spawn(async move {
        let (ev, _e) = mpsc::unbounded_channel();
        send(&mut Opener(opener), Outgoing { transfer_id: new_transfer_id(), manifest: m, files, resume: false }, &limits(), ev, no_cmds()).await
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut worst = Duration::ZERO;
    for i in 0..20 {
        let ping = format!("p{i:02}");
        let t = std::time::Instant::now();
        tunnel.write(ping.as_bytes()).await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 8];
        while got.len() < 3 {
            let n = timeout(Duration::from_secs(2), tunnel.read(&mut buf)).await.expect("tunnel starved").unwrap();
            got.extend_from_slice(&buf[..n]);
        }
        worst = worst.max(t.elapsed());
    }
    eprintln!("worst tunnel RTT during transfer: {worst:?}");
    assert!(worst < Duration::from_millis(250));
    assert_eq!(transfer.await.unwrap(), Outcome::Completed);
    let _ = &mut w;
}

/// RTC-007 / RTC-008 / REL-012 / REL-013: the session drops mid-transfer; a new
/// session re-binds and resumes from verified data.
#[tokio::test(flavor = "multi_thread")]
async fn disconnect_reconnect_rebind_resume() {
    let mut w = world(Setup { attest: true, source_ski: SOURCE_SKI }).await;
    assert!(target_bound(&w).await);
    let src = tempfile::tempdir().unwrap();
    write(src.path(), "resume.bin", &bytes(40 << 20, 3));
    let path = src.path().join("resume.bin");
    let (files, sel) = NativeFiles::loose(&[path.clone()]).unwrap();
    let m = build(ManifestKind::Files, sel, &Limits::default()).unwrap();
    let id = new_transfer_id();

    // Drop the whole WebRTC session part-way through.
    let opener = w.session.opener();
    let (m1, files1) = (m.clone(), files);
    let first = tokio::spawn(async move {
        let (ev, _e) = mpsc::unbounded_channel();
        send(&mut Opener(opener), Outgoing { transfer_id: id, manifest: m1, files: files1, resume: false }, &limits(), ev, no_cmds()).await
    });
    tokio::time::sleep(Duration::from_millis(800)).await;
    idr_core::PeerSession::close(&mut w.session).await.unwrap();
    assert!(matches!(first.await.unwrap(), Outcome::Interrupted(_)));
    // The Target's first attempt ends Interrupted too (and keeps its data).
    let first_target = timeout(Duration::from_secs(10), async {
        loop {
            if let Some((tid, TransferEvent::Finished(o))) = w.target_events.recv().await {
                if tid == id {
                    return o;
                }
            }
        }
    })
    .await
    .unwrap();
    assert!(matches!(first_target, Outcome::Interrupted(_)), "{first_target:?}");

    // New session through Presence, same identities, same transfer id.
    w.session = connect_to(LoopPresence {
        connectors: services().await,
        transfers: Some(w.endpoint.clone()),
        attested_ski: Some(SOURCE_SKI.into()),
        relay: None,
    })
    .await;
    w.target_peer = bind(&w.session, &w.pki, SOURCE_SKI).await;
    assert!(target_bound(&w).await);
    let (files, _) = NativeFiles::loose(&[path.clone()]).unwrap();
    let (s, r, events) = to_target(&mut w, m, files, id, true, no_cmds()).await;
    assert_eq!((s, r), (Outcome::Completed, Outcome::Completed));
    assert_eq!(sha_file(&path), sha_file(&w.target_dir.path().join("resume.bin")));
    let resumed_from = events.iter().find_map(|e| match e {
        TransferEvent::Progress(p) => Some(p.bytes_done),
        _ => None,
    });
    assert!(resumed_from.unwrap_or(0) > 0, "resume restarted from zero");
}

/// RTC-001 / RTC-002 at full size. Slow in debug builds: run with
/// `cargo test --release -p idr-target --features webrtc --test transfer_loopback -- --ignored`.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn one_gigabyte_each_way() {
    let mut w = world(Setup { attest: true, source_ski: SOURCE_SKI }).await;
    assert!(target_bound(&w).await);
    let src = tempfile::tempdir().unwrap();
    {
        use std::io::Write;
        let mut f = std::fs::File::create(src.path().join("gig.bin")).unwrap();
        let block = bytes(1 << 20, 11);
        for _ in 0..1024 {
            f.write_all(&block).unwrap();
        }
    }
    let t = std::time::Instant::now();
    let (files, sel) = NativeFiles::loose(&[src.path().join("gig.bin")]).unwrap();
    let m = build(ManifestKind::Files, sel, &Limits::default()).unwrap();
    let (s, r, _) = to_target(&mut w, m, files, new_transfer_id(), false, no_cmds()).await;
    assert_eq!((s, r), (Outcome::Completed, Outcome::Completed));
    eprintln!("1 GiB Source→Target in {:?}", t.elapsed());
    assert_eq!(sha_file(&src.path().join("gig.bin")), sha_file(&w.target_dir.path().join("gig.bin")));

    let back = tempfile::tempdir().unwrap();
    let mut outcomes = source_receives(&mut w, back.path()).await;
    let t = std::time::Instant::now();
    let (files, sel) = NativeFiles::loose(&[src.path().join("gig.bin")]).unwrap();
    let m = build(ManifestKind::Files, sel, &Limits::default()).unwrap();
    let o = w.endpoint.send(session_uuid(&w.session), Outgoing { transfer_id: new_transfer_id(), manifest: m, files, resume: false }, no_cmds()).await;
    assert_eq!(o, Outcome::Completed);
    assert_eq!(outcomes.recv().await, Some(Outcome::Completed));
    eprintln!("1 GiB Target→Source in {:?}", t.elapsed());
    assert_eq!(sha_file(&src.path().join("gig.bin")), sha_file(&back.path().join("gig.bin")));
}

/// (peak working set, peak commit) of this process so far, in MiB.
fn peak_mib() -> (u64, u64) {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        // SAFETY: plain out-struct of the size we pass.
        unsafe {
            let mut c: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
            c.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
            K32GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb);
            ((c.PeakWorkingSetSize >> 20) as u64, (c.PeakPagefileUsage >> 20) as u64)
        }
    }
    #[cfg(not(windows))]
    {
        (0, 0)
    }
}

/// PERF-001 / ST-002: a folder at exactly the entry limit (100,000 entries:
/// the root folder + 990 subfolders + 99,009 files). Prints per-stage timings
/// and this process's peak memory (both agents and the test together). Run in
/// release: `cargo test --release -p idr-target --features webrtc --test
/// transfer_loopback -- --ignored hundred_thousand --nocapture`.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn hundred_thousand_entries() {
    let mut w = world(Setup { attest: true, source_ski: SOURCE_SKI }).await;
    assert!(target_bound(&w).await);
    eprintln!("peak memory at start (working set, commit MiB): {:?}", peak_mib());
    let src = tempfile::tempdir().unwrap();
    let t = std::time::Instant::now();
    for d in 0..990 {
        let dir = src.path().join(format!("Big/d{d:03}"));
        std::fs::create_dir_all(&dir).unwrap();
        for i in 0..100 {
            std::fs::write(dir.join(format!("f{i:03}.txt")), [d as u8, i as u8, 7]).unwrap();
        }
    }
    for i in 0..9 {
        std::fs::write(src.path().join(format!("Big/top{i}.txt")), [i as u8]).unwrap();
    }
    eprintln!("create 99,009 files: {:?}", t.elapsed());
    let t = std::time::Instant::now();
    let m = folder_manifest(src.path(), &["Big"]);
    eprintln!("enumerate + manifest ({} entries, {} bytes encoded): {:?}", m.entries.len(), m.encode().len(), t.elapsed());
    assert_eq!(m.entries.len(), 100_000, "1 root + 990 folders + 99,009 files");
    eprintln!("peak memory after manifest: {:?}", peak_mib());
    let t = std::time::Instant::now();
    let (s, r, events) = to_target(&mut w, m, NativeFiles::new(src.path()).unwrap(), new_transfer_id(), false, no_cmds()).await;
    assert_eq!((s, r), (Outcome::Completed, Outcome::Completed));
    eprintln!("transfer: {:?}, {} sender events", t.elapsed(), events.len());
    eprintln!("peak memory after transfer: {:?}", peak_mib());
    assert!(events.len() < 5000, "events grew with file count: {}", events.len());
    assert!(w.target_dir.path().join("Big/d989/f099.txt").is_file());
    assert!(w.target_dir.path().join("Big/top8.txt").is_file());
    let n = walk_count(&w.target_dir.path().join("Big"));
    assert_eq!(n, 99_999, "every folder and file under the root arrived");

    // One more entry is refused before anything is sent.
    std::fs::write(src.path().join("Big/one-too-many.txt"), [0]).unwrap();
    let sel = idr_transfer::native::enumerate(&cap_std::fs::Dir::open_ambient_dir(src.path(), cap_std::ambient_authority()).unwrap(), &[vec!["Big".into()]]).unwrap();
    assert_eq!(build(ManifestKind::Folder, sel.selected, &Limits::default()).err(), Some(K::LimitExceeded));
}

fn walk_count(dir: &Path) -> usize {
    std::fs::read_dir(dir).unwrap().flatten().map(|e| if e.path().is_dir() { 1 + walk_count(&e.path()) } else { 1 }).sum()
}

/// TURN, negative: relay-only ICE towards a TURN address nothing answers on
/// must not connect. Proves relay-only is enforced (no host candidate sneaks
/// in), so a passing `relayed_transfer_reports_turn_on_both_peers` really
/// went through the relay.
#[tokio::test(flavor = "multi_thread")]
async fn relay_only_without_turn_does_not_connect() {
    let presence = LoopPresence {
        connectors: services().await,
        transfers: None,
        attested_ski: None,
        relay: Some(vec![idr_protocol::webrtc_ice::IceServer {
            urls: vec!["turn:127.0.0.1:9".into()],
            username: Some("u".into()),
            credential: Some("p".into()),
        }]),
    };
    match timeout(Duration::from_secs(20), try_connect(presence)).await {
        Ok(Ok(_)) => panic!("connected although only an unreachable relay was allowed"),
        Ok(Err(_)) | Err(_) => {}
    }
}

/// TURN, positive: a real relay end to end, both peers relay-only. Needs a
/// TURN server, e.g. coturn in WSL:
/// `turnserver -n --listening-ip=127.0.0.1 --relay-ip=127.0.0.1 --lt-cred-mech --user=idr:idr --realm=idr.test`
/// then `IDR_TEST_TURN_URL=turn:127.0.0.1:3478 IDR_TEST_TURN_USER=idr IDR_TEST_TURN_PASS=idr
/// cargo test -p idr-target --features webrtc --test transfer_loopback -- --ignored relayed --nocapture`.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn relayed_transfer_reports_turn_on_both_peers() {
    use idr_protocol::webrtc_ice::IcePath;
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("set {k} (see the doc comment)"));
    let servers = vec![idr_protocol::webrtc_ice::IceServer {
        urls: vec![env("IDR_TEST_TURN_URL")],
        username: Some(env("IDR_TEST_TURN_USER")),
        credential: Some(env("IDR_TEST_TURN_PASS")),
    }];
    let mut w = world_via(Setup { attest: true, source_ski: SOURCE_SKI }, Some(servers)).await;
    assert!(target_bound(&w).await);
    assert_eq!(w.target_peer.as_ref().unwrap().path, Some(IcePath::Turn), "Source's view of the pair");
    assert_eq!(w.endpoint.peer(session_uuid(&w.session)).unwrap().path, Some(IcePath::Turn), "Target's view of the pair");
    let src = tempfile::tempdir().unwrap();
    write(src.path(), "relayed.bin", &bytes(8 << 20, 5));
    let (files, sel) = NativeFiles::loose(&[src.path().join("relayed.bin")]).unwrap();
    let m = build(ManifestKind::Files, sel, &Limits::default()).unwrap();
    let t = std::time::Instant::now();
    let (s, r, _) = to_target(&mut w, m, files, new_transfer_id(), false, no_cmds()).await;
    assert_eq!((s, r), (Outcome::Completed, Outcome::Completed));
    eprintln!("8 MiB through TURN in {:?}", t.elapsed());
    assert_eq!(sha_file(&src.path().join("relayed.bin")), sha_file(&w.target_dir.path().join("relayed.bin")));
}

#[allow(dead_code)]
fn _unused(_: PathBuf) {}
