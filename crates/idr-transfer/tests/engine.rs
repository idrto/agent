//! Engine tests over mock peers: in-memory streams with injectable disconnects
//! and corruption, plus a scripted (hostile) sender.

mod common;
use common::*;

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use idr_protocol::transfer::{
    new_transfer_id, ControlFrame, ControlMsg, DataRecord, EntryKind, Manifest, ManifestEntry,
    ManifestKind, StreamHeader, StreamRole, TransferErrorKind as K, TransferId,
    MANIFEST_CHUNK_BYTES, STREAM_MAGIC, TRANSFER_VERSION,
};
use idr_transfer::io::Framed;
use idr_transfer::manifest::{build, Selected};
use idr_transfer::mem::{AcceptAll, DenyAll, MemFiles, MemSink};
use idr_transfer::storage::{Approval, StreamOpener};
use idr_transfer::{
    Command, Limits, Outcome, Routed, Router, TransferEvent,
};
use sha2::Digest;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::timeout;

async fn run(manifest: Manifest, files: MemFiles, sink: MemSink, opts: Opts) -> Run {
    run_with(manifest, files, sink, AcceptAll(Approval::User), opts).await
}

fn bytes(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

fn files_manifest(files: &MemFiles, items: &[(&[&str], Vec<u8>)], kind: ManifestKind) -> Manifest {
    let mut sel = Vec::new();
    for (path, data) in items {
        files.insert(path, data.clone());
        sel.push(Selected::file(path, data.len() as u64));
    }
    build(kind, sel, &Limits::default()).unwrap()
}

fn sha(b: &[u8]) -> Vec<u8> {
    sha2::Sha256::digest(b).to_vec()
}

// ---- Functional -----------------------------------------------------------

/// FT-001 / REL-001 / UX-001 / EVT-001 / EVT-002.
#[tokio::test(flavor = "multi_thread")]
async fn single_file_roundtrip() {
    let files = MemFiles::default();
    let data = bytes(300_000, 1);
    let m = files_manifest(&files, &[(&["report.pdf"], data.clone())], ManifestKind::Files);
    let sink = MemSink::default();
    let r = run(m, files, sink.clone(), Opts::default()).await;
    assert_eq!((r.sender.clone(), r.receiver.clone()), (Outcome::Completed, Outcome::Completed));
    let got = sink.visible()["report.pdf"].clone().unwrap();
    assert_eq!(sha(&got), sha(&data));

    let offered = r.rx_events.iter().find_map(|e| match e {
        TransferEvent::Offered(s) => Some(s.clone()),
        _ => None,
    });
    let s = offered.expect("no Offered event");
    assert!(s.is_single_file());
    assert_eq!((s.top_level.as_slice(), s.total_bytes), (&["report.pdf".to_string()][..], 300_000));
    assert!(r.rx_events.contains(&TransferEvent::Accepted {
        approval: Some(Approval::User)
    }));
    assert!(r.tx_events.contains(&TransferEvent::Accepted { approval: None }));
    assert_eq!(r.tx_events.last(), Some(&TransferEvent::Finished(Outcome::Completed)));
}

/// FT-003 / FT-004 / FT-007: empty, binary and several files in one transfer.
#[tokio::test(flavor = "multi_thread")]
async fn multiple_files_including_empty_and_binary() {
    let files = MemFiles::default();
    let all: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();
    let m = files_manifest(
        &files,
        &[
            (&["empty.txt"], vec![]),
            (&["all-bytes.bin"], all.clone()),
            (&["notes with spaces ü.md"], b"hi".to_vec()),
        ],
        ManifestKind::Files,
    );
    let sink = MemSink::default();
    let r = run(m, files, sink.clone(), Opts::default()).await;
    assert_eq!(r.receiver, Outcome::Completed);
    let v = sink.visible();
    assert_eq!(v["empty.txt"], Some(vec![]));
    assert_eq!(v["all-bytes.bin"], Some(all));
    assert_eq!(v["notes with spaces ü.md"], Some(b"hi".to_vec()));
    let last_progress = r.rx_events.iter().rev().find_map(|e| match e {
        TransferEvent::Progress(p) => Some(*p),
        _ => None,
    });
    let p = last_progress.unwrap();
    assert_eq!((p.files_done, p.files_total), (3, 3));
    assert_eq!(p.bytes_done, p.bytes_total);
}

fn project(files: &MemFiles) -> Vec<Selected> {
    let tree: &[(&[&str], usize)] = &[
        (&["Project", "README.md"], 100),
        (&["Project", "config.json"], 50),
        (&["Project", "empty.txt"], 0),
        (&["Project", "src", "main.dart"], 2000),
        (&["Project", "src", "auth.dart"], 1500),
        (&["Project", "src", "network", "client.dart"], 900),
        (&["Project", "src", "network", "socket.dart"], 800),
        (&["Project", "assets", "logo.png"], 90_000),
        (&["Project", "assets", "icon.png"], 4000),
        (&["Project", "docs", "setup.pdf"], 120_000),
        (&["Project", "docs", "guide.pdf"], 60_000),
    ];
    let mut sel = vec![Selected::dir(&["Project", "empty-folder"])];
    for (i, (p, n)) in tree.iter().enumerate() {
        files.insert(p, bytes(*n, i as u8));
        sel.push(Selected::file(p, *n as u64));
    }
    sel
}

/// FD-001..004 / REL-036 / SEC-FS-026: the folder appears only once complete.
#[tokio::test(flavor = "multi_thread")]
async fn complete_folder_appears_only_when_complete() {
    let files = MemFiles::default();
    let m = build(ManifestKind::Folder, project(&files), &Limits::default()).unwrap();
    let sink = MemSink::default();
    let r = run(m, files.clone(), sink.clone(), Opts::default()).await;
    assert_eq!(r.receiver, Outcome::Completed);
    let v = sink.visible();
    assert_eq!(v["Project/empty-folder"], None, "empty dir is an entry");
    assert_eq!(v["Project/empty.txt"], Some(vec![]));
    assert_eq!(
        v["Project/src/network/socket.dart"].as_deref(),
        Some(&files.file(&["Project", "src", "network", "socket.dart"]).lock().unwrap().data[..])
    );
    assert_eq!(v.len(), 17, "11 files + 6 dirs");
}

/// FS-001..006 / FS-012: only the selection and its parents arrive.
#[tokio::test(flavor = "multi_thread")]
async fn selective_folder_reconstructs_only_the_selection() {
    let files = MemFiles::default();
    project(&files);
    let sel = vec![
        Selected::file(&["Project", "src", "main.dart"], 2000),
        Selected::file(&["Project", "src", "network", "client.dart"], 900),
        Selected::file(&["Project", "docs", "guide.pdf"], 60_000),
    ];
    let m = build(ManifestKind::Folder, sel, &Limits::default()).unwrap();
    let sink = MemSink::default();
    let r = run(m, files, sink.clone(), Opts::default()).await;
    assert_eq!(r.receiver, Outcome::Completed);
    let keys: Vec<String> = sink.visible().keys().cloned().collect();
    assert_eq!(
        keys,
        [
            "Project",
            "Project/docs",
            "Project/docs/guide.pdf",
            "Project/src",
            "Project/src/main.dart",
            "Project/src/network",
            "Project/src/network/client.dart",
        ]
    );
}

/// FD-005 / EVT-012 / EVT-013: many small files, events stay bounded.
#[tokio::test(flavor = "multi_thread")]
async fn many_small_files_with_bounded_events() {
    let files = MemFiles::default();
    let mut sel = Vec::new();
    for i in 0..3000 {
        let name = format!("f{i:05}.txt");
        files.insert(&["Many", &name], bytes(64, i as u8));
        sel.push(Selected {
            path: vec!["Many".into(), name],
            ..Selected::file(&[], 64)
        });
    }
    let m = build(ManifestKind::Folder, sel, &Limits::default()).unwrap();
    let sink = MemSink::default();
    let started = std::time::Instant::now();
    let r = run(m, files, sink.clone(), Opts::default()).await;
    assert_eq!(r.receiver, Outcome::Completed);
    assert_eq!(sink.visible().len(), 3001);
    let progress = r
        .rx_events
        .iter()
        .filter(|e| matches!(e, TransferEvent::Progress(_)))
        .count();
    let budget = (started.elapsed().as_millis() / 250) as usize + 3;
    assert!(progress <= budget, "{progress} progress events (budget {budget})");
    assert!(r.rx_events.len() < 3000 / 10, "per-file events: {}", r.rx_events.len());
}

// ---- Integrity and failures -----------------------------------------------

/// Flip one payload byte of the first large data record.
fn corrupt_once() -> Hook {
    let done = Arc::new(AtomicBool::new(false));
    Arc::new(move |b: &mut Vec<u8>| {
        if b.len() > 1000 && !done.swap(true, Ordering::SeqCst) {
            let i = b.len() - 1;
            b[i] ^= 0x01;
        }
    })
}

/// REL-002 / REL-004 / REL-032 / REL-031 / UI-012: a corrupted file never appears;
/// the others do; the result is "completed with errors", not success.
#[tokio::test(flavor = "multi_thread")]
async fn corrupted_file_fails_alone() {
    let files = MemFiles::default();
    let m = files_manifest(
        &files,
        &[(&["a.bin"], bytes(100_000, 1)), (&["b.bin"], bytes(5_000, 2))],
        ManifestKind::Files,
    );
    let sink = MemSink::default();
    let opts = Opts {
        data_hook: Some(corrupt_once()),
        ..Opts::default()
    };
    let r = run(m, files, sink.clone(), opts).await;
    assert_eq!(r.receiver, Outcome::CompletedWithErrors { failed: 1 });
    assert_eq!(r.sender, Outcome::CompletedWithErrors { failed: 1 });
    let v = sink.visible();
    assert!(!v.contains_key("a.bin"), "corrupted file was finalized");
    assert!(v.contains_key("b.bin"));
    assert!(r.rx_events.contains(&TransferEvent::EntryFailed {
        entry: 0,
        code: K::HashMismatch
    }));
}

/// REL-037 / REL-038: a failed entry keeps a folder staged, never visible.
#[tokio::test(flavor = "multi_thread")]
async fn folder_with_failed_entry_stays_staged() {
    let files = MemFiles::default();
    let m = build(ManifestKind::Folder, project(&files), &Limits::default()).unwrap();
    let id = new_transfer_id();
    let sink = MemSink::default();
    let opts = Opts {
        data_hook: Some(corrupt_once()),
        id: Some(id),
        ..Opts::default()
    };
    let r = run(m, files, sink.clone(), opts).await;
    assert!(matches!(r.receiver, Outcome::CompletedWithErrors { failed: 1 }));
    assert!(sink.visible().is_empty(), "incomplete folder became visible");
    assert!(sink.holds(&id), "verified entries kept staged for retry");
}

/// FT-011 / FD-014 / LOG-007: a file that changes while sending fails as
/// "changed during transfer", not as corruption.
#[tokio::test(flavor = "multi_thread")]
async fn file_changed_during_transfer() {
    let files = MemFiles::default();
    let m = files_manifest(
        &files,
        &[(&["live.log"], bytes(10_000, 3)), (&["grows.log"], bytes(10_000, 4)), (&["ok"], vec![1])],
        ManifestKind::Files,
    );
    files.file(&["live.log"]).lock().unwrap().mtime = Some(42);
    files.file(&["grows.log"]).lock().unwrap().data.extend_from_slice(b"more");
    let sink = MemSink::default();
    let r = run(m, files, sink.clone(), Opts::default()).await;
    assert_eq!(r.receiver, Outcome::CompletedWithErrors { failed: 2 });
    for entry in [0, 1] {
        assert!(r.rx_events.contains(&TransferEvent::EntryFailed {
            entry,
            code: K::ChangedDuringTransfer
        }));
    }
    assert_eq!(sink.visible().keys().collect::<Vec<_>>(), ["ok"]);
}

/// PERF-010: storage failure fails the entry; nothing incomplete is finalized.
#[tokio::test(flavor = "multi_thread")]
async fn storage_failure_fails_entry() {
    let files = MemFiles::default();
    let m = files_manifest(
        &files,
        &[(&["full.bin"], bytes(50_000, 1)), (&["fits.bin"], bytes(10, 2))],
        ManifestKind::Files,
    );
    let sink = MemSink::default();
    sink.fail_writes_to(Some(1));
    let r = run(m, files, sink.clone(), Opts::default()).await;
    assert_eq!(r.receiver, Outcome::CompletedWithErrors { failed: 1 });
    assert!(r.rx_events.contains(&TransferEvent::EntryFailed {
        entry: 1,
        code: K::StorageFailed
    }));
    assert!(!sink.visible().contains_key("full.bin"));
}

// ---- Resume, pause, cancel ------------------------------------------------

/// REL-005 / REL-010..013 / REL-017..019 / REL-033 / RTC-008: disconnect mid-transfer,
/// restart the receiver's storage handle, resume with the same id. Verified files
/// are skipped and the partial file continues from its last checkpoint.
#[tokio::test(flavor = "multi_thread")]
async fn resume_after_disconnect_skips_verified_data() {
    let files = MemFiles::default();
    let big = bytes(1_200_000, 9);
    let m = files_manifest(
        &files,
        &[
            (&["a-small"], bytes(20_000, 1)),
            (&["b-big"], big.clone()),
            (&["c-pending"], bytes(30_000, 3)),
        ],
        ManifestKind::Files,
    );
    let id = new_transfer_id();
    let sink = MemSink::default();
    let first = run(
        m.clone(),
        files.clone(),
        sink.clone(),
        Opts {
            id: Some(id),
            cut_after: Some(700_000),
            ..Opts::default()
        },
    )
    .await;
    assert!(matches!(first.sender, Outcome::Interrupted(_)), "{:?}", first.sender);
    assert!(matches!(first.receiver, Outcome::Interrupted(_)), "{:?}", first.receiver);
    assert!(sink.holds(&id));
    assert!(sink.visible().contains_key("a-small"));
    let kept = sink.partial_len(&id, 1);

    // "Restart": a new storage handle over the same persisted state.
    let restarted = sink.reopen();
    let resent = Arc::new(AtomicU64::new(0));
    let r2 = resent.clone();
    let count: Hook = Arc::new(move |b: &mut Vec<u8>| {
        r2.fetch_add(b.len() as u64, Ordering::SeqCst);
    });
    let second = run(
        m,
        files,
        restarted.clone(),
        Opts {
            id: Some(id),
            resume: true,
            data_hook: Some(count),
            ..Opts::default()
        },
    )
    .await;
    assert_eq!(second.receiver, Outcome::Completed);
    assert_eq!(restarted.visible()["b-big"].as_deref(), Some(&big[..]));
    let total = 20_000 + 1_200_000 + 30_000;
    let resent = resent.load(Ordering::SeqCst);
    assert!(kept > 0, "no checkpointed partial data");
    assert!(
        resent < total - kept + 50_000,
        "resent {resent} bytes; {kept} were already verified"
    );
    assert!(!restarted.holds(&id), "metadata kept after completion");
}

/// REL-003 / SEC-FS-027: a partial file tampered with before resume is not
/// finalized (the full-file hash catches it).
#[tokio::test(flavor = "multi_thread")]
async fn tampered_partial_is_not_finalized() {
    let files = MemFiles::default();
    let m = files_manifest(&files, &[(&["big"], bytes(800_000, 5))], ManifestKind::Files);
    let id = new_transfer_id();
    let sink = MemSink::default();
    let first = run(
        m.clone(),
        files.clone(),
        sink.clone(),
        Opts {
            id: Some(id),
            cut_after: Some(400_000),
            ..Opts::default()
        },
    )
    .await;
    assert!(matches!(first.receiver, Outcome::Interrupted(_)));
    let restarted = sink.reopen();
    // prepare() truncates to the checkpoint; tamper inside what survives.
    restarted.tamper(&id, 0, 10);
    let second = run(m, files, restarted.clone(), Opts {
        id: Some(id),
        resume: true,
        ..Opts::default()
    })
    .await;
    assert_eq!(second.receiver, Outcome::CompletedWithErrors { failed: 1 });
    assert!(!restarted.visible().contains_key("big"));
}

/// REL-015 / PT-018: the same transfer id with a different manifest is refused.
#[tokio::test(flavor = "multi_thread")]
async fn conflicting_manifest_for_same_id_is_rejected() {
    let files = MemFiles::default();
    let m1 = files_manifest(&files, &[(&["x"], bytes(500_000, 1))], ManifestKind::Files);
    let id = new_transfer_id();
    let sink = MemSink::default();
    run(m1, files.clone(), sink.clone(), Opts {
        id: Some(id),
        cut_after: Some(200_000),
        ..Opts::default()
    })
    .await;
    let m2 = files_manifest(&files, &[(&["y"], bytes(10, 2))], ManifestKind::Files);
    let r = run(m2, files, sink.reopen(), Opts {
        id: Some(id),
        resume: true,
        ..Opts::default()
    })
    .await;
    assert_eq!(r.sender, Outcome::Rejected(K::ConflictingManifest));
}

/// REL-008 / REL-009 / PT-007: pause stops progress; resume completes. Duplicate
/// pause/resume are harmless.
#[tokio::test(flavor = "multi_thread")]
async fn pause_then_resume_completes() {
    let files = MemFiles::default();
    let m = files_manifest(&files, &[(&["p"], bytes(3_000_000, 7))], ManifestKind::Files);
    let sink = MemSink::default();
    let ms = Duration::from_millis;
    let r = run(m, files, sink.clone(), Opts {
        sender_cmds: vec![
            (ms(5), Command::Pause),
            (ms(6), Command::Pause),
            (ms(400), Command::Resume),
            (ms(401), Command::Resume),
        ],
        ..Opts::default()
    })
    .await;
    assert_eq!(r.receiver, Outcome::Completed);
    assert!(r.rx_events.contains(&TransferEvent::Paused { by_peer: true }));
    assert!(r.rx_events.contains(&TransferEvent::Resumed { by_peer: true }));
    assert_eq!(sink.visible()["p"].as_ref().unwrap().len(), 3_000_000);
}

/// REL-024 / REL-026 / EVT-011: receiver cancels mid-folder; staging and metadata
/// are removed; cancelling twice is harmless.
#[tokio::test(flavor = "multi_thread")]
async fn receiver_cancel_cleans_up() {
    let files = MemFiles::default();
    files.insert(&["F", "huge"], bytes(5_000_000, 1));
    let mut sel = project(&files);
    sel.iter_mut().for_each(|s| s.path[0] = "F".into());
    sel.push(Selected::file(&["F", "huge"], 5_000_000));
    for s in &sel {
        if s.kind == EntryKind::File {
            let p: Vec<&str> = s.path.iter().map(String::as_str).collect();
            let mut orig = p.clone();
            orig[0] = "Project";
            if p[1] != "huge" {
                files.insert(&p, files.file(&orig).lock().unwrap().data.clone());
            }
        }
    }
    let m = build(ManifestKind::Folder, sel, &Limits::default()).unwrap();
    let id = new_transfer_id();
    let sink = MemSink::default();
    let ms = Duration::from_millis;
    let r = run(m, files, sink.clone(), Opts {
        id: Some(id),
        receiver_cmds: vec![(ms(20), Command::Cancel), (ms(21), Command::Cancel)],
        ..Opts::default()
    })
    .await;
    assert_eq!((r.sender, r.receiver), (Outcome::Cancelled, Outcome::Cancelled));
    assert!(!sink.holds(&id), "staging kept after cancel");
    assert!(sink.visible().is_empty());
    assert_eq!(sink.discarded(), 1);
}

/// REL-022 / REL-028: sender cancels while paused; the receiver discards.
#[tokio::test(flavor = "multi_thread")]
async fn sender_cancel_while_paused_cleans_up() {
    let files = MemFiles::default();
    let m = files_manifest(&files, &[(&["c"], bytes(4_000_000, 1))], ManifestKind::Files);
    let id = new_transfer_id();
    let sink = MemSink::default();
    let ms = Duration::from_millis;
    let r = run(m, files, sink.clone(), Opts {
        id: Some(id),
        sender_cmds: vec![(ms(5), Command::Pause), (ms(100), Command::Cancel)],
        ..Opts::default()
    })
    .await;
    assert_eq!((r.sender, r.receiver), (Outcome::Cancelled, Outcome::Cancelled));
    assert!(!sink.holds(&id));
    assert!(sink.visible().is_empty());
}

// ---- Authorization at the engine boundary ---------------------------------

/// AUTH-012 / AUTH-016 / CLI-014: a denying receiver refuses; nothing is stored.
#[tokio::test(flavor = "multi_thread")]
async fn denied_offer_stores_nothing() {
    let files = MemFiles::default();
    let m = files_manifest(&files, &[(&["x"], bytes(10, 1))], ManifestKind::Files);
    let sink = MemSink::default();
    let r = run_with(m, files, sink.clone(), DenyAll(K::Unauthorized), Opts::default()).await;
    assert_eq!(r.sender, Outcome::Rejected(K::Unauthorized));
    assert_eq!(r.receiver, Outcome::Rejected(K::Unauthorized));
    assert!(sink.visible().is_empty());
}

// ---- Hostile sender (scripted) --------------------------------------------

struct Raw {
    control: Framed,
    data: Option<Framed>,
    link: Link,
    id: TransferId,
    done: oneshot::Receiver<(Outcome, Vec<TransferEvent>)>,
    router: Router,
    consent_calls: Arc<AtomicU32>,
    sink: MemSink,
}

async fn raw_link(limits: Limits) -> Raw {
    let (in_tx, in_rx) = mpsc::unbounded_channel();
    let (_cut_tx, cut_rx) = watch::channel(false);
    std::mem::forget(_cut_tx);
    let calls = Arc::new(AtomicU32::new(0));
    let sink = MemSink::default();
    let (_cmd_tx, cmd_rx) = mpsc::channel(1);
    std::mem::forget(_cmd_tx);
    let (done, router) = spawn_receiver(
        in_rx,
        sink.clone(),
        Counting(calls.clone(), Approval::Auto),
        limits,
        cmd_rx,
    );
    let mut link = Link {
        incoming: in_tx,
        cut: cut_rx,
        data_hook: None,
        opened: 0,
    };
    let id = new_transfer_id();
    let control = Framed::new(link.open().await.unwrap());
    Raw {
        control,
        data: None,
        link,
        id,
        done,
        router,
        consent_calls: calls,
        sink,
    }
}

impl Raw {
    async fn header(&mut self, role: StreamRole, version: u16) {
        let h = StreamHeader {
            magic: STREAM_MAGIC,
            version,
            transfer_id: self.id,
            role,
        };
        match role {
            StreamRole::Control => self.control.send(&h).await.unwrap(),
            StreamRole::Data => self.data.as_mut().unwrap().send(&h).await.unwrap(),
        }
    }

    async fn offer(&mut self, m: &Manifest) {
        let enc = m.encode();
        self.offer_raw(&enc, Manifest::digest_of(&enc), m.entries.len() as u32).await;
    }

    async fn offer_raw(&mut self, enc: &[u8], digest: [u8; 32], count: u32) {
        self.header(StreamRole::Control, TRANSFER_VERSION).await;
        self.ctl(ControlMsg::Offer {
            digest,
            manifest_len: enc.len() as u32,
            entry_count: count,
            resume: false,
        })
        .await;
        for c in enc.chunks(MANIFEST_CHUNK_BYTES) {
            self.ctl(ControlMsg::ManifestChunk { bytes: c.to_vec() }).await;
        }
    }

    async fn ctl(&mut self, m: ControlMsg) {
        let _ = self.control.send_control(&m).await;
    }

    async fn reply(&mut self) -> Option<ControlMsg> {
        timeout(Duration::from_secs(5), self.control.next_control())
            .await
            .ok()?
            .ok()?
    }

    async fn accept_and_open_data(&mut self) {
        assert!(matches!(self.reply().await, Some(ControlMsg::Accept { .. })));
        self.data = Some(Framed::new(self.link.open().await.unwrap()));
        self.header(StreamRole::Data, TRANSFER_VERSION).await;
    }

    async fn rec(&mut self, r: DataRecord) {
        let _ = self.data.as_mut().unwrap().send(&r).await;
    }

    async fn outcome(self) -> Outcome {
        timeout(Duration::from_secs(10), self.done).await.unwrap().unwrap().0
    }
}

fn one_file(size: u64) -> Manifest {
    Manifest {
        kind: ManifestKind::Files,
        entries: vec![ManifestEntry {
            id: 0,
            kind: EntryKind::File,
            path: vec!["f".into()],
            size,
            mtime: None,
            mime: Some("text/plain".into()),
        }],
    }
}

fn digest(b: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(b).into()
}

/// PT-001 / SEC-FS-001 / UX-008: a hostile manifest is refused before consent.
#[tokio::test(flavor = "multi_thread")]
async fn hostile_manifest_rejected_before_consent() {
    let mut raw = raw_link(limits()).await;
    let mut m = one_file(1);
    m.entries[0].path = vec!["..".into(), "secret.txt".into()];
    raw.offer(&m).await;
    assert_eq!(
        raw.reply().await,
        Some(ControlMsg::Reject {
            code: K::ManifestInvalid
        })
    );
    let calls = raw.consent_calls.clone();
    assert_eq!(raw.outcome().await, Outcome::Rejected(K::ManifestInvalid));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// PERF-003: an oversized manifest is refused from the offer alone.
#[tokio::test(flavor = "multi_thread")]
async fn oversized_manifest_rejected_up_front() {
    let mut raw = raw_link(Limits {
        max_manifest_bytes: 1000,
        ..limits()
    })
    .await;
    raw.header(StreamRole::Control, TRANSFER_VERSION).await;
    raw.ctl(ControlMsg::Offer {
        digest: [0; 32],
        manifest_len: 1001,
        entry_count: 1,
        resume: false,
    })
    .await;
    assert_eq!(raw.reply().await, Some(ControlMsg::Reject { code: K::LimitExceeded }));
}

/// Manifest bytes that don't match the offered digest (PT-017).
#[tokio::test(flavor = "multi_thread")]
async fn manifest_digest_mismatch_rejected() {
    let mut raw = raw_link(limits()).await;
    let enc = one_file(1).encode();
    raw.offer_raw(&enc, [7; 32], 1).await;
    assert_eq!(raw.reply().await, Some(ControlMsg::Reject { code: K::ManifestInvalid }));
}

/// PT-002: unsupported protocol version.
#[tokio::test(flavor = "multi_thread")]
async fn unsupported_version_rejected() {
    let mut raw = raw_link(limits()).await;
    raw.header(StreamRole::Control, 99).await;
    assert_eq!(
        raw.reply().await,
        Some(ControlMsg::Reject {
            code: K::IncompatibleVersion
        })
    );
}

/// PT-008 / PT-019: a data stream for a transfer nobody accepted is refused.
#[tokio::test(flavor = "multi_thread")]
async fn data_stream_without_accepted_offer_is_refused() {
    let router = Router::default();
    let (a, b) = tokio::io::duplex(1024);
    let (_c, cut) = watch::channel(false);
    let mut sender = Framed::new(Box::new(MemStream { io: a, cut: cut.clone(), hook: None }));
    sender
        .send(&StreamHeader {
            magic: STREAM_MAGIC,
            version: TRANSFER_VERSION,
            transfer_id: new_transfer_id(),
            role: StreamRole::Data,
        })
        .await
        .unwrap();
    let routed = router
        .route(Box::new(MemStream { io: b, cut, hook: None }), Duration::from_secs(1))
        .await;
    assert!(matches!(routed, Routed::Refused));
}

/// PT-003 / PT-004: unknown optional control messages are skipped, unknown
/// mandatory ones fail the transfer.
#[tokio::test(flavor = "multi_thread")]
async fn unknown_control_messages() {
    let content = b"hello".to_vec();
    let mut raw = raw_link(limits()).await;
    raw.offer(&one_file(5)).await;
    raw.accept_and_open_data().await;
    raw.control
        .send(&ControlFrame {
            msg_type: 900,
            mandatory: false,
            body: vec![1],
        })
        .await
        .unwrap();
    raw.rec(DataRecord::Chunk { entry: 0, offset: 0, bytes: content.clone() }).await;
    raw.rec(DataRecord::EntryEnd { entry: 0, size: 5, sha256: digest(&content) }).await;
    let sink = raw.sink.clone();
    assert_eq!(raw.outcome().await, Outcome::Completed);
    assert_eq!(sink.visible()["f"], Some(content));

    let mut raw = raw_link(limits()).await;
    raw.offer(&one_file(5)).await;
    raw.accept_and_open_data().await;
    raw.control
        .send(&ControlFrame {
            msg_type: 901,
            mandatory: true,
            body: vec![],
        })
        .await
        .unwrap();
    assert_eq!(raw.outcome().await, Outcome::Failed(K::ProtocolViolation));
}

async fn violation_case(records: Vec<DataRecord>, size: u64) -> (Outcome, MemSink) {
    let mut raw = raw_link(limits()).await;
    raw.offer(&one_file(size)).await;
    raw.accept_and_open_data().await;
    for r in records {
        raw.rec(r).await;
    }
    let sink = raw.sink.clone();
    (raw.outcome().await, sink)
}

/// PT-012 / PT-013 / PT-014 / PT-015: unknown entry, bad offset, overlap and
/// oversized chunks fail the transfer; nothing is finalized.
#[tokio::test(flavor = "multi_thread")]
async fn invalid_data_records_fail_the_transfer() {
    let chunk = |entry, offset, n| DataRecord::Chunk { entry, offset, bytes: vec![1; n] };
    let cases = vec![
        vec![chunk(5, 0, 10)],
        vec![chunk(0, 3, 10)],
        vec![chunk(0, 0, 10), chunk(0, 5, 10)],
        vec![chunk(0, 0, idr_protocol::transfer::MAX_CHUNK_BYTES + 1)],
        vec![chunk(0, 0, 0)],
    ];
    for records in cases {
        let (o, sink) = violation_case(records.clone(), 100_000).await;
        assert_eq!(o, Outcome::Failed(K::ProtocolViolation), "{records:?}");
        assert!(sink.visible().is_empty());
    }
}

/// PT-016 / FT-012: a sender sending past the declared size is cut off; the
/// entry fails and nothing is finalized.
#[tokio::test(flavor = "multi_thread")]
async fn sender_exceeding_declared_size_is_cut_off() {
    let (o, sink) = violation_case(
        vec![
            DataRecord::Chunk { entry: 0, offset: 0, bytes: vec![1; 10] },
            DataRecord::Chunk { entry: 0, offset: 10, bytes: vec![1; 10] },
        ],
        15,
    )
    .await;
    assert_eq!(o, Outcome::CompletedWithErrors { failed: 1 });
    assert!(sink.visible().is_empty());
    // A trailer claiming a different size is refused too.
    let (o, _) = violation_case(
        vec![
            DataRecord::Chunk { entry: 0, offset: 0, bytes: vec![1; 10] },
            DataRecord::EntryEnd { entry: 0, size: 10, sha256: digest(&[1; 10]) },
        ],
        12,
    )
    .await;
    assert_eq!(o, Outcome::CompletedWithErrors { failed: 1 });
}

/// PERF-019: a stalled sender interrupts the transfer (resumable), not fails it.
#[tokio::test(flavor = "multi_thread")]
async fn stalled_sender_interrupts() {
    let mut raw = raw_link(Limits {
        stall_timeout: Duration::from_millis(300),
        ..limits()
    })
    .await;
    raw.offer(&one_file(100)).await;
    raw.accept_and_open_data().await;
    raw.rec(DataRecord::Chunk { entry: 0, offset: 0, bytes: vec![1; 10] }).await;
    let id = raw.id;
    let sink = raw.sink.clone();
    let _keep = raw.router.clone();
    assert_eq!(raw.outcome().await, Outcome::Interrupted(K::Stalled));
    assert!(sink.holds(&id), "partial state must survive a stall");
}

/// PERF-001 at the real default (`Limits::default().max_entries` = 100,000,
/// counting every file and directory, the root included): exactly 100,000
/// entries build; 100,001 are refused.
#[test]
fn entry_limit_is_exactly_one_hundred_thousand() {
    assert_eq!(Limits::default().max_entries, 100_000);
    let files = |n: usize| -> Vec<Selected> {
        let mut v = vec![Selected::dir(&["P"])];
        v.extend((0..n).map(|i| Selected::file(&["P", &format!("f{i:06}")], 1)));
        v
    };
    let at = build(ManifestKind::Folder, files(99_999), &Limits::default()).unwrap();
    assert_eq!(at.entries.len(), 100_000, "the root folder + 99,999 files");
    assert_eq!(build(ManifestKind::Folder, files(100_000), &Limits::default()), Err(K::LimitExceeded));
}

/// A sender that ignores the limit and offers 100,001 entries is refused
/// from the offer alone, before any manifest byte is read or consent asked.
#[tokio::test(flavor = "multi_thread")]
async fn over_limit_entry_count_rejected_up_front() {
    let mut raw = raw_link(limits()).await;
    raw.header(StreamRole::Control, TRANSFER_VERSION).await;
    raw.ctl(ControlMsg::Offer { digest: [0; 32], manifest_len: 1000, entry_count: 100_001, resume: false }).await;
    assert_eq!(raw.reply().await, Some(ControlMsg::Reject { code: K::LimitExceeded }));
}
