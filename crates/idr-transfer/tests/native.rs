//! Native storage tests on the real filesystem (feature `native`).

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use idr_protocol::transfer::{new_transfer_id, Manifest, ManifestKind, TransferErrorKind as K};
use idr_transfer::manifest::{build, Selected};
use idr_transfer::mem::{AcceptAll, MemFiles};
use idr_transfer::names::NamePolicy;
use idr_transfer::native::{resolve_destination, NativeFiles, NativeSink, STAGING_PREFIX};
use idr_transfer::storage::Approval;
use idr_transfer::{Command, Limits, Outcome, TransferEvent};

fn bytes(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(13).wrapping_add(seed)).collect()
}

fn write(root: &Path, rel: &[&str], data: &[u8]) {
    let p: PathBuf = rel.iter().fold(root.to_path_buf(), |p, c| p.join(c));
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, data).unwrap();
}

fn read(root: &Path, rel: &str) -> Vec<u8> {
    std::fs::read(root.join(rel)).unwrap()
}

fn listing(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn staging_dirs(dest: &Path) -> Vec<String> {
    listing(dest).into_iter().filter(|n| n.starts_with(STAGING_PREFIX)).collect()
}

/// Selection of everything under `root/top`, with sizes and mtimes from disk.
fn select_tree(root: &Path, top: &str) -> Vec<Selected> {
    fn walk(root: &Path, rel: Vec<String>, out: &mut Vec<Selected>) {
        let p: PathBuf = rel.iter().fold(root.to_path_buf(), |p, c| p.join(c));
        let meta = std::fs::symlink_metadata(&p).unwrap();
        if meta.is_dir() {
            out.push(Selected { path: rel.clone(), ..Selected::dir(&[]) });
            for e in std::fs::read_dir(&p).unwrap() {
                let mut r = rel.clone();
                r.push(e.unwrap().file_name().to_string_lossy().into_owned());
                walk(root, r, out);
            }
        } else if meta.is_file() {
            let mtime = meta
                .modified()
                .unwrap()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            out.push(Selected {
                path: rel,
                mtime: Some(mtime),
                ..Selected::file(&[], meta.len())
            });
        }
    }
    let mut out = Vec::new();
    walk(root, vec![top.to_string()], &mut out);
    out
}

fn project(src: &Path) -> Vec<(String, Vec<u8>)> {
    let files = [
        ("Project/README.md", 100),
        ("Project/empty.txt", 0),
        ("Project/src/main.dart", 3000),
        ("Project/src/network/client.dart", 900),
        ("Project/assets/logo.png", 150_000),
        ("Project/docs/guide.pdf", 70_000),
    ];
    std::fs::create_dir_all(src.join("Project/empty-folder")).unwrap();
    files
        .iter()
        .enumerate()
        .map(|(i, (p, n))| {
            let data = bytes(*n, i as u8);
            write(src, &p.split('/').collect::<Vec<_>>(), &data);
            (p.to_string(), data)
        })
        .collect()
}

async fn transfer(m: Manifest, src: &Path, dest: &Path, opts: Opts) -> Run {
    run_with(
        m,
        NativeFiles::new(src).unwrap(),
        NativeSink::new(dest).unwrap(),
        AcceptAll(Approval::User),
        opts,
    )
    .await
}

fn counting() -> (Hook, Arc<AtomicU64>) {
    let n = Arc::new(AtomicU64::new(0));
    let c = n.clone();
    (Arc::new(move |b: &mut Vec<u8>| { c.fetch_add(b.len() as u64, Ordering::SeqCst); }), n)
}

/// FD-001..004 / RTC-003 shape on disk / REL-029: tree, empty dir and empty file
/// arrive intact; staging and journal are gone afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn folder_lands_on_disk_and_staging_is_removed() {
    let (src, dest) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let expected = project(src.path());
    let m = build(ManifestKind::Folder, select_tree(src.path(), "Project"), &Limits::default())
        .unwrap();
    let r = transfer(m, src.path(), dest.path(), Opts::default()).await;
    assert_eq!((r.sender, r.receiver), (Outcome::Completed, Outcome::Completed));
    for (p, data) in expected {
        assert_eq!(read(dest.path(), &p), data, "{p}");
    }
    assert!(dest.path().join("Project/empty-folder").is_dir());
    assert_eq!(listing(dest.path()), ["Project"], "staging left behind");
}

/// FD-010: the sender's mtime is applied.
#[tokio::test(flavor = "multi_thread")]
async fn mtime_is_applied() {
    let (src, dest) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    write(src.path(), &["old.txt"], b"x");
    let mut sel = select_tree(src.path(), "old.txt");
    sel[0].mtime = Some(1_000_000_000);
    let m = build(ManifestKind::Files, sel, &Limits::default()).unwrap();
    // NativeFiles checks the file still matches the manifest's mtime.
    let files = MemFiles::default();
    files.insert(&["old.txt"], b"x".to_vec());
    files.file(&["old.txt"]).lock().unwrap().mtime = Some(1_000_000_000);
    let r = run_with(m, files, NativeSink::new(dest.path()).unwrap(), AcceptAll(Approval::User), Opts::default()).await;
    assert_eq!(r.receiver, Outcome::Completed);
    let t = std::fs::metadata(dest.path().join("old.txt")).unwrap().modified().unwrap();
    assert_eq!(t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(), 1_000_000_000);
}

/// SEC-FS-026 / SEC-FS-031 / REL-011..013 / REL-017/018: an interrupted folder never
/// shows under its final name; after a "restart" it resumes from proven data.
#[tokio::test(flavor = "multi_thread")]
async fn interrupted_folder_is_invisible_then_resumes() {
    let (src, dest) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let mut expected = project(src.path());
    let big = bytes(1_500_000, 77);
    write(src.path(), &["Project", "zz-big.bin"], &big);
    expected.push(("Project/zz-big.bin".into(), big));
    let m = build(ManifestKind::Folder, select_tree(src.path(), "Project"), &Limits::default())
        .unwrap();
    let id = new_transfer_id();
    let first = transfer(m.clone(), src.path(), dest.path(), Opts {
        id: Some(id),
        cut_after: Some(900_000),
        ..Opts::default()
    })
    .await;
    assert!(matches!(first.receiver, Outcome::Interrupted(_)), "{:?}", first.receiver);
    assert_eq!(staging_dirs(dest.path()).len(), 1);
    assert!(!dest.path().join("Project").exists(), "half-received folder is visible");

    let (hook, resent) = counting();
    let second = transfer(m, src.path(), dest.path(), Opts {
        id: Some(id),
        resume: true,
        data_hook: Some(hook),
        ..Opts::default()
    })
    .await;
    assert_eq!(second.receiver, Outcome::Completed);
    for (p, data) in expected {
        assert_eq!(read(dest.path(), &p), data, "{p}");
    }
    assert_eq!(listing(dest.path()), ["Project"]);
    let total: u64 = 1_500_000 + 100 + 3000 + 900 + 150_000 + 70_000;
    assert!(resent.load(Ordering::SeqCst) < total - 500_000, "verified data was resent");
}

/// FD-011 / SEC-FS-028 / SEC-FS-029 / UI-014: taken top-level names get a number;
/// existing data is untouched and never merged.
#[tokio::test(flavor = "multi_thread")]
async fn taken_names_get_numbers_and_nothing_is_overwritten() {
    let (src, dest) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    project(src.path());
    write(src.path(), &["report.pdf"], b"new report");
    write(dest.path(), &["report.pdf"], b"old report");
    write(dest.path(), &["Project", "README.md"], b"mine");

    let m = build(ManifestKind::Folder, select_tree(src.path(), "Project"), &Limits::default())
        .unwrap();
    let r = transfer(m, src.path(), dest.path(), Opts::default()).await;
    assert_eq!(r.receiver, Outcome::Completed);
    let m = build(ManifestKind::Files, select_tree(src.path(), "report.pdf"), &Limits::default())
        .unwrap();
    let r2 = transfer(m, src.path(), dest.path(), Opts::default()).await;
    assert_eq!(r2.receiver, Outcome::Completed);

    assert_eq!(read(dest.path(), "Project/README.md"), b"mine");
    assert_eq!(listing(&dest.path().join("Project")), ["README.md"], "merged into existing folder");
    assert_eq!(read(dest.path(), "Project (2)/src/main.dart").len(), 3000);
    assert_eq!(read(dest.path(), "report.pdf"), b"old report");
    assert_eq!(read(dest.path(), "report (2).pdf"), b"new report");
    assert!(r.rx_events.contains(&TransferEvent::Renamed { entry: 0, to: "Project (2)".into() }));
    assert!(r2.rx_events.contains(&TransferEvent::Renamed { entry: 0, to: "report (2).pdf".into() }));
}

/// SEC-FS-011 / SEC-FS-012 / SEC-FS-017 / LOG-006 / UI-014: Windows-incompatible
/// names are mapped and reported; no alternate data stream is ever created.
#[tokio::test(flavor = "multi_thread")]
async fn incompatible_names_are_mapped_and_reported() {
    let dest = tempfile::tempdir().unwrap();
    let files = MemFiles::default();
    let mut sel = Vec::new();
    for (name, data) in [("a:b.txt", b"ads?".to_vec()), ("CON.txt", b"dev".to_vec()), ("ok.txt", vec![1])] {
        files.insert(&[name], data.clone());
        sel.push(Selected::file(&[name], data.len() as u64));
    }
    let m = build(ManifestKind::Files, sel, &Limits::default()).unwrap();
    let sink = NativeSink::with_policy(dest.path(), NamePolicy { windows: true }).unwrap();
    let r = run_with(m, files, sink, AcceptAll(Approval::User), Opts::default()).await;
    assert_eq!(r.receiver, Outcome::Completed);
    assert_eq!(listing(dest.path()), ["CON_.txt", "a_b.txt", "ok.txt"]);
    assert_eq!(read(dest.path(), "a_b.txt"), b"ads?");
    assert!(!dest.path().join("a").exists(), "alternate data stream host created");
    let renamed: Vec<_> = r
        .rx_events
        .iter()
        .filter_map(|e| match e {
            TransferEvent::Renamed { to, .. } => Some(to.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(renamed, ["CON_.txt", "a_b.txt"]);
}

fn partial_file(dest: &Path, entry: u32) -> PathBuf {
    dest.join(&staging_dirs(dest)[0]).join("p").join(entry.to_string())
}

/// REL-003 / REL-006 / SEC-FS-027: a block tampered with on disk is detected on
/// resume; only proven bytes are advertised and the file completes correctly.
#[tokio::test(flavor = "multi_thread")]
async fn tampered_block_is_cut_back_on_resume() {
    let (src, dest) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let data = bytes(2_000_000, 9);
    write(src.path(), &["big.bin"], &data);
    let m = build(ManifestKind::Files, select_tree(src.path(), "big.bin"), &Limits::default())
        .unwrap();
    let id = new_transfer_id();
    transfer(m.clone(), src.path(), dest.path(), Opts {
        id: Some(id),
        cut_after: Some(1_200_000),
        ..Opts::default()
    })
    .await;
    let part = partial_file(dest.path(), 0);
    let mut on_disk = std::fs::read(&part).unwrap();
    assert!(on_disk.len() > 300_000);
    on_disk[300_000] ^= 0xff;
    std::fs::write(&part, &on_disk).unwrap();

    let (hook, resent) = counting();
    let r = transfer(m, src.path(), dest.path(), Opts {
        id: Some(id),
        resume: true,
        data_hook: Some(hook),
        ..Opts::default()
    })
    .await;
    assert_eq!(r.receiver, Outcome::Completed);
    assert_eq!(read(dest.path(), "big.bin"), data);
    let resent = resent.load(Ordering::SeqCst);
    assert!(resent > 2_000_000 - 300_000, "tampered bytes were advertised as verified");
    assert!(resent < 2_000_000, "nothing before the tampered block was kept");
}

/// REL-007: bytes past the last durable checkpoint (e.g. a crash mid-write) are
/// never trusted.
#[tokio::test(flavor = "multi_thread")]
async fn unproven_tail_is_dropped() {
    let (src, dest) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let data = bytes(1_000_000, 3);
    write(src.path(), &["f.bin"], &data);
    let m = build(ManifestKind::Files, select_tree(src.path(), "f.bin"), &Limits::default())
        .unwrap();
    let id = new_transfer_id();
    transfer(m.clone(), src.path(), dest.path(), Opts {
        id: Some(id),
        cut_after: Some(500_000),
        ..Opts::default()
    })
    .await;
    let part = partial_file(dest.path(), 0);
    let mut f = std::fs::OpenOptions::new().append(true).open(&part).unwrap();
    std::io::Write::write_all(&mut f, &[0xEE; 70_000]).unwrap();
    drop(f);
    let r = transfer(m, src.path(), dest.path(), Opts {
        id: Some(id),
        resume: true,
        ..Opts::default()
    })
    .await;
    assert_eq!(r.receiver, Outcome::Completed);
    assert_eq!(read(dest.path(), "f.bin"), data);
}

/// REL-024 / REL-025: cancel removes staging, partial data and the journal.
#[tokio::test(flavor = "multi_thread")]
async fn cancel_removes_everything() {
    let (src, dest) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    project(src.path());
    write(src.path(), &["Project", "huge.bin"], &bytes(6_000_000, 1));
    let m = build(ManifestKind::Folder, select_tree(src.path(), "Project"), &Limits::default())
        .unwrap();
    let r = transfer(m, src.path(), dest.path(), Opts {
        receiver_cmds: vec![(Duration::from_millis(30), Command::Cancel)],
        ..Opts::default()
    })
    .await;
    assert_eq!(r.receiver, Outcome::Cancelled);
    assert!(listing(dest.path()).is_empty(), "left behind: {:?}", listing(dest.path()));
}

/// REL-020 / PERF-020: idle staging past retention is swept; fresh staging is kept.
#[tokio::test(flavor = "multi_thread")]
async fn retention_sweeps_stale_staging() {
    let (src, dest) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    write(src.path(), &["f.bin"], &bytes(800_000, 3));
    let m = build(ManifestKind::Files, select_tree(src.path(), "f.bin"), &Limits::default())
        .unwrap();
    transfer(m, src.path(), dest.path(), Opts { cut_after: Some(300_000), ..Opts::default() }).await;
    let sink = NativeSink::new(dest.path()).unwrap();
    assert_eq!(sink.sweep(Duration::from_secs(3600)).unwrap(), 0);
    assert_eq!(staging_dirs(dest.path()).len(), 1);
    std::thread::sleep(Duration::from_millis(1100));
    assert_eq!(sink.sweep(Duration::ZERO).unwrap(), 1);
    assert!(listing(dest.path()).is_empty());
}

/// A directory symlink (Unix) or junction (Windows); false if this host can't make one.
fn dir_link(link: &Path, target: &Path) -> bool {
    #[cfg(windows)]
    {
        std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).is_ok()
    }
}

/// SEC-FS-021 / SEC-FS-022: staging swapped for a link to elsewhere between
/// attempts can't redirect writes outside the destination.
#[tokio::test(flavor = "multi_thread")]
async fn swapped_staging_link_cannot_escape() {
    let (src, dest, outside) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    write(src.path(), &["f.bin"], &bytes(900_000, 3));
    let m = build(ManifestKind::Files, select_tree(src.path(), "f.bin"), &Limits::default())
        .unwrap();
    let id = new_transfer_id();
    transfer(m.clone(), src.path(), dest.path(), Opts {
        id: Some(id),
        cut_after: Some(300_000),
        ..Opts::default()
    })
    .await;
    let parts = dest.path().join(&staging_dirs(dest.path())[0]).join("p");
    std::fs::remove_dir_all(&parts).unwrap();
    assert!(dir_link(&parts, outside.path()), "could not create a directory link here");

    let r = transfer(m, src.path(), dest.path(), Opts {
        id: Some(id),
        resume: true,
        ..Opts::default()
    })
    .await;
    assert!(
        !matches!(r.receiver, Outcome::Completed),
        "transfer completed through a link out of the destination"
    );
    assert!(listing(outside.path()).is_empty(), "wrote outside: {:?}", listing(outside.path()));
}

/// SEC-FS-019 / SEC-FS-020: a selected path that goes through a link out of the
/// sender's root is not read.
#[tokio::test(flavor = "multi_thread")]
async fn sender_does_not_follow_links_out_of_root() {
    let (src, dest, outside) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    write(outside.path(), &["secret.txt"], b"top secret");
    write(src.path(), &["Project", "ok.txt"], b"fine");
    assert!(dir_link(&src.path().join("Project").join("link"), outside.path()));
    let m = build(
        ManifestKind::Folder,
        vec![
            Selected::file(&["Project", "ok.txt"], 4),
            Selected::file(&["Project", "link", "secret.txt"], 10),
        ],
        &Limits::default(),
    )
    .unwrap();
    let r = transfer(m, src.path(), dest.path(), Opts::default()).await;
    assert!(matches!(r.receiver, Outcome::CompletedWithErrors { failed: 1 }), "{:?}", r.receiver);
    // Entries sort as Project, Project/link, Project/link/secret.txt, Project/ok.txt.
    assert!(r.rx_events.contains(&TransferEvent::EntryFailed { entry: 2, code: K::SourceReadFailed }));
    assert!(!dest.path().join("Project").exists(), "folder with a failed entry was committed");
}

/// SEC-FS-024: no remote permission bits are applied (Unix only).
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn no_executable_bits_are_applied() {
    use std::os::unix::fs::PermissionsExt;
    let (src, dest) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    write(src.path(), &["run.sh"], b"#!/bin/sh");
    std::fs::set_permissions(src.path().join("run.sh"), std::fs::Permissions::from_mode(0o4755)).unwrap();
    let m = build(ManifestKind::Files, select_tree(src.path(), "run.sh"), &Limits::default()).unwrap();
    let r = transfer(m, src.path(), dest.path(), Opts::default()).await;
    assert_eq!(r.receiver, Outcome::Completed);
    let mode = std::fs::metadata(dest.path().join("run.sh")).unwrap().permissions().mode();
    assert_eq!(mode & 0o7111, 0, "mode {mode:o}");
}

/// PERF: per-file cost of small files, storage only (no WebRTC). Prints raw
/// filesystem baselines next to the engine. Run in release:
/// `cargo test --release -p idr-transfer --features native --test native -- --ignored small_file_cost --nocapture`.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn small_file_cost() {
    const N: usize = 5000;
    let raw = |sync: bool| {
        let d = tempfile::tempdir().unwrap();
        let t = std::time::Instant::now();
        for i in 0..N {
            let p = d.path().join(format!("p{i}"));
            let mut f = std::fs::File::create(&p).unwrap();
            std::io::Write::write_all(&mut f, b"abc").unwrap();
            if sync {
                f.sync_all().unwrap();
            }
            drop(f);
            std::fs::rename(&p, d.path().join(format!("f{i}"))).unwrap();
        }
        t.elapsed()
    };
    eprintln!("raw create+write+rename, no fsync: {:?} per file", raw(false) / N as u32);
    eprintln!("raw create+write+fsync+rename:     {:?} per file", raw(true) / N as u32);

    let (src, dest) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    for i in 0..N {
        write(src.path(), &["Many", &format!("d{}", i % 50), &format!("f{i:05}.txt")], b"abc");
    }
    let t = std::time::Instant::now();
    let m = build(ManifestKind::Folder, select_tree(src.path(), "Many"), &Limits::default()).unwrap();
    eprintln!("manifest: {:?} per entry", t.elapsed() / m.entries.len() as u32);
    let t = std::time::Instant::now();
    let r = transfer(m, src.path(), dest.path(), Opts::default()).await;
    assert_eq!(r.receiver, Outcome::Completed);
    eprintln!("engine (sender + receiver + journal): {:?} per file", t.elapsed() / N as u32);
}

/// AUTH-017 / CLI-016 / SEC-FS-021: an accept destination can't reach outside the
/// permitted directories through a link (Windows junction / Unix symlink):
/// (a) a link inside a permitted dir pointing outside is refused at accept;
/// (b) a dir swapped for such a link *after* accept is refused when storage
///     opens it (opened relative to the permitted root's handle, not by path).
#[test]
fn destination_links_cannot_escape_permitted_dirs() {
    let (root, outside) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let inbox = root.path().join("inbox");
    std::fs::create_dir_all(inbox.join("sub")).unwrap();
    let permitted = vec![inbox.clone()];

    let link = inbox.join("link");
    assert!(dir_link(&link, outside.path()), "could not create a directory link here");
    assert_eq!(resolve_destination(&permitted, &link), Err(K::Unauthorized), "(a) link out of the inbox accepted");
    assert_eq!(resolve_destination(&permitted, &link.join("..").join("..")), Err(K::Unauthorized));

    // A plain subdirectory is fine; then it is swapped for a link before use.
    let d = resolve_destination(&permitted, &inbox.join("sub")).unwrap();
    assert!(NativeSink::open_in(&d.root, &d.rel).is_ok());
    std::fs::remove_dir(inbox.join("sub")).unwrap();
    assert!(dir_link(&inbox.join("sub"), outside.path()));
    assert!(NativeSink::open_in(&d.root, &d.rel).is_err(), "(b) storage followed a link swapped in after accept");
    // What the previous by-path open did: it follows the swapped link.
    assert!(NativeSink::new(&d.path()).is_ok(), "expected the by-path open to follow the link");
    assert!(listing(outside.path()).is_empty());

    // The permitted dir itself (empty rel) opens.
    let d = resolve_destination(&permitted, &inbox).unwrap();
    assert!(d.rel.as_os_str().is_empty());
    assert!(NativeSink::open_in(&d.root, &d.rel).is_ok());
}
