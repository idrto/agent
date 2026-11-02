//! Real WebRTC (libdatachannel) mux tests: Source ↔ Target in one process.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use idr_core::PeerSession;
use tokio::time::timeout;

// ---- Tests ----------------------------------------------------------------

/// Baseline: a real WebRTC echo round trip (pumping manually, works before 0b).
#[tokio::test(flavor = "multi_thread")]
async fn echo_round_trip_over_real_webrtc() {
    let mut session = connect().await;
    let mut stream = session.open_named_stream("echo").await.unwrap();
    stream.write(b"hello").await.unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 16];
    while got.len() < 5 {
        let _ = timeout(Duration::from_millis(50), session.poll_incoming()).await;
        if let Ok(Ok(n)) = timeout(Duration::from_millis(50), stream.read(&mut buf)).await {
            got.extend_from_slice(&buf[..n]);
        }
    }
    assert_eq!(got, b"hello");
}

/// B7: stream reads must complete without the caller pumping the session.
#[tokio::test(flavor = "multi_thread")]
async fn read_completes_without_manual_pump() {
    let mut session = connect().await;
    let mut stream = session.open_named_stream("echo").await.unwrap();
    stream.write(b"ping").await.unwrap();
    let mut buf = [0u8; 16];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .expect("read never completed: nothing drives the session")
        .unwrap();
    assert_eq!(&buf[..n], b"ping");
}

/// B7: a write larger than the stream window must wait for credit, not fail.
#[tokio::test(flavor = "multi_thread")]
async fn large_write_waits_for_credit() {
    let mut session = connect().await;
    let mut stream = session.open_named_stream("echo").await.unwrap();
    let data: Vec<u8> = (0..2 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let mut got = Vec::with_capacity(data.len());
    let mut sent = 0;
    let mut buf = vec![0u8; 64 * 1024];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while got.len() < data.len() {
        assert!(tokio::time::Instant::now() < deadline, "2 MiB echo stalled at {}", got.len());
        if sent < data.len() {
            match timeout(Duration::from_millis(50), stream.write(&data[sent..])).await {
                Ok(Ok(n)) => sent += n,
                Ok(Err(e)) => panic!("write failed instead of waiting for credit: {e}"),
                Err(_) => {}
            }
        }
        if let Ok(Ok(n)) = timeout(Duration::from_millis(5), stream.read(&mut buf)).await {
            got.extend_from_slice(&buf[..n]);
        }
    }
    assert_eq!(got, data);
}

/// B10: a slow upstream connect must not stall the Target session loop.
#[tokio::test(flavor = "multi_thread")]
async fn slow_open_does_not_stall_other_streams() {
    let mut session = connect().await;
    let mut echo = session.open_named_stream("echo").await.unwrap();
    // Start opening the 3 s service; give up waiting for it after 100 ms.
    let _ = timeout(Duration::from_millis(100), session.open_named_stream("slow")).await;

    let started = std::time::Instant::now();
    echo.write(b"still here").await.unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 32];
    while got.len() < 10 {
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "echo stalled behind a slow open"
        );
        let _ = timeout(Duration::from_millis(20), session.poll_incoming()).await;
        if let Ok(Ok(n)) = timeout(Duration::from_millis(20), echo.read(&mut buf)).await {
            got.extend_from_slice(&buf[..n]);
        }
    }
}

/// B10: open streams per session are capped.
#[tokio::test(flavor = "multi_thread")]
async fn stream_count_is_capped() {
    let mut session = connect().await;
    let mut streams = Vec::new();
    let mut refused = 0;
    for _ in 0..300 {
        match session.open_named_stream("echo").await {
            Ok(s) => streams.push(s),
            Err(e) => {
                assert_eq!(e.kind(), idr_core::IdrErrorKind::ConnectionRefused);
                refused += 1;
            }
        }
    }
    assert!(
        streams.len() <= idr_protocol::stream_mux::MAX_STREAMS_PER_SESSION,
        "{} streams open, none refused",
        streams.len()
    );
    assert!(refused > 0);
}

/// Regression (REG-004 / PERF-016): an interactive tunnel stays responsive while a
/// bulk upload saturates the same DataChannel.
#[tokio::test(flavor = "multi_thread")]
async fn tunnel_stays_responsive_during_bulk_upload() {
    let mut session = connect().await;
    let mut bulk = session
        .open_named_stream_with("sink", idr_core::StreamPriority::Bulk)
        .await
        .unwrap();
    let mut tunnel = session.open_named_stream("echo").await.unwrap();

    let uploaded = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let up = uploaded.clone();
    let uploader = tokio::spawn(async move {
        let chunk = vec![0xAB; 60 * 1024];
        loop {
            match bulk.write(&chunk).await {
                Ok(n) => up.fetch_add(n, std::sync::atomic::Ordering::Relaxed),
                Err(_) => return,
            };
        }
    });

    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut worst = Duration::ZERO;
    for i in 0..20 {
        let ping = format!("q{i:02}");
        let started = std::time::Instant::now();
        tunnel.write(ping.as_bytes()).await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 16];
        while got.len() < ping.len() {
            let n = timeout(Duration::from_secs(2), tunnel.read(&mut buf))
                .await
                .expect("tunnel starved by bulk upload")
                .unwrap();
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, ping.as_bytes());
        worst = worst.max(started.elapsed());
    }
    let bytes = uploaded.load(std::sync::atomic::Ordering::Relaxed);
    uploader.abort();
    eprintln!("bulk uploaded {} KiB; worst tunnel RTT {worst:?}", bytes / 1024);
    assert!(bytes > 1024 * 1024, "bulk barely moved: {bytes} bytes");
    assert!(worst < Duration::from_millis(250), "worst tunnel RTT {worst:?}");
}
