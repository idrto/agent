//! Source mux flow control and delivery (Phase 0a: B1, B4, B6; 0b: B7, B8).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use idr_core::LogicalStream;
use idr_protocol::stream_mux::{
    MuxProfile, ServiceCatalogEntry, StreamFrame, CREDIT_CONN_WINDOW, FEATURE_FLOW_CREDIT,
    INITIAL_STREAM_WINDOW,
};
use idr_protocol::webrtc_signaling::SourceAuthMode;
use idr_signaling::mock::MockSignalingClient;
use idr_source::{SourceRuntime, SourceSession};
use idr_webrtc::{PeerEvent, PeerTransport, RecordingPeer};
use tokio::time::timeout;

/// Scripted Target: answers Hello/catalog/Open like a credit-capable Target and
/// lets the test inject frames after connect.
#[derive(Clone, Default)]
struct Wire {
    inbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    sent: Arc<Mutex<Vec<StreamFrame>>>,
    /// Wakes the session driver parked in `next_event`.
    wake: Arc<tokio::sync::Notify>,
    /// Pre-credit Target: acks Hello without `flow_credit_v1`.
    old_target: bool,
}

impl Wire {
    fn inject(&self, frame: StreamFrame) {
        self.inbound.lock().unwrap().push_back(frame.encode().unwrap());
        self.wake.notify_one();
    }
    fn sent(&self) -> Vec<StreamFrame> {
        self.sent.lock().unwrap().clone()
    }
}

struct ScriptPeer {
    inner: RecordingPeer,
    wire: Wire,
}

#[async_trait::async_trait]
impl PeerTransport for ScriptPeer {
    async fn start(&mut self, r: idr_webrtc::PeerConnectRequest) -> idr_core::Result<()> {
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
    fn send_binary(&mut self, message: &[u8]) -> idr_core::Result<()> {
        self.inner.send_binary(message)?;
        let frame = StreamFrame::decode(message).unwrap();
        match &frame {
            StreamFrame::Hello { version, features, .. } => {
                let mut ack = MuxProfile::from_features(features).advertised_features();
                if !self.wire.old_target && features.iter().any(|f| f == FEATURE_FLOW_CREDIT) {
                    ack.push(FEATURE_FLOW_CREDIT.into());
                }
                self.wire.inject(StreamFrame::HelloAck {
                    version: *version,
                    features: ack,
                    conn_window: CREDIT_CONN_WINDOW,
                });
            }
            StreamFrame::ServicesCatalogRequest => {
                self.wire.inject(StreamFrame::ServicesCatalogDetailed {
                    entries: vec![ServiceCatalogEntry::name_only("http")],
                });
            }
            StreamFrame::Open { stream_id, .. } => self.wire.inject(StreamFrame::OpenOk {
                stream_id: *stream_id,
                initial_window: INITIAL_STREAM_WINDOW,
            }),
            _ => {}
        }
        self.wire.sent.lock().unwrap().push(frame);
        Ok(())
    }
    async fn next_event(&mut self) -> idr_core::Result<PeerEvent> {
        loop {
            if let Some(bytes) = self.wire.inbound.lock().unwrap().pop_front() {
                return Ok(PeerEvent::BinaryMessage(bytes));
            }
            let wake = self.wire.wake.clone();
            tokio::select! {
                _ = wake.notified() => {}
                ev = self.inner.next_event() => return ev,
            }
        }
    }
    fn close(&mut self) {
        self.inner.close();
    }
}

async fn connect() -> (SourceSession, Wire) {
    connect_to(Wire::default()).await
}

async fn connect_to(wire: Wire) -> (SourceSession, Wire) {
    let w = wire.clone();
    let mut runtime = SourceRuntime::with_auth(
        Box::new(MockSignalingClient::default()),
        move || {
            Box::new(ScriptPeer {
                inner: RecordingPeer::new(),
                wire: w.clone(),
            })
        },
        "src",
        "eu",
        SourceAuthMode::Bearer,
        Some("test-token".into()),
    );
    let session = runtime.connect("t.idr.to").await.unwrap();
    (session, wire)
}

/// Wait until the driver has taken every injected frame; fails if the demux blocks.
async fn pump_all(session: &mut SourceSession, wire: &Wire) {
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while !wire.inbound.lock().unwrap().is_empty() {
        assert!(
            std::time::Instant::now() < deadline,
            "demux blocked while ingesting a frame"
        );
        session.poll_incoming().await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(20)).await;
}

/// Bytes written before a write waits for credit.
async fn write_until_blocked(stream: &mut Box<dyn LogicalStream>, chunk: usize) -> usize {
    let buf = vec![5u8; chunk];
    let mut total = 0;
    loop {
        match timeout(Duration::from_millis(200), stream.write(&buf)).await {
            Ok(Ok(n)) => total += n,
            Ok(Err(e)) => panic!("write failed instead of waiting for credit: {e}"),
            Err(_) => return total,
        }
        assert!(total <= 64 * 1024 * 1024, "send window never closed");
    }
}

/// B1: credit the Target returns must reopen the Source's send window.
/// (0b: an exhausted window makes `write` wait instead of failing.)
#[tokio::test]
async fn window_update_reopens_send_window() {
    let (mut session, wire) = connect().await;
    let mut stream = session.open_named_stream("http").await.unwrap();

    let first = write_until_blocked(&mut stream, 32 * 1024).await;
    assert_eq!(first, INITIAL_STREAM_WINDOW as usize);

    wire.inject(StreamFrame::WindowUpdate {
        stream_id: 1,
        credit: 128 * 1024,
    });
    pump_all(&mut session, &wire).await;
    let second = write_until_blocked(&mut stream, 32 * 1024).await;
    assert_eq!(second, 128 * 1024, "returned credit was not applied");
}

/// B6: a frame larger than the caller's buffer must be delivered in full across reads.
#[tokio::test]
async fn small_read_buffer_receives_whole_frame() {
    let (mut session, wire) = connect().await;
    let mut stream = session.open_named_stream("http").await.unwrap();
    let payload: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
    wire.inject(StreamFrame::Data {
        stream_id: 1,
        bytes: payload.clone(),
    });
    pump_all(&mut session, &wire).await;

    let mut got = Vec::new();
    let mut buf = [0u8; 100];
    while got.len() < payload.len() {
        let n = timeout(Duration::from_secs(1), stream.read(&mut buf))
            .await
            .expect("rest of the frame was lost")
            .unwrap();
        assert!(n > 0);
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got, payload);
}

/// B4: an unread stream must not block delivery to other streams. A peer that
/// overruns the stream window gets that stream reset.
#[tokio::test]
async fn unread_stream_does_not_block_others() {
    let (mut session, wire) = connect().await;
    let _bulk = session.open_named_stream("http").await.unwrap();
    let mut tunnel = session.open_named_stream("http").await.unwrap();

    for _ in 0..64 {
        wire.inject(StreamFrame::Data {
            stream_id: 1,
            bytes: vec![0; 16 * 1024],
        });
    }
    wire.inject(StreamFrame::Data {
        stream_id: 3,
        bytes: b"select 1".to_vec(),
    });
    pump_all(&mut session, &wire).await;

    let mut buf = [0u8; 64];
    let n = timeout(Duration::from_secs(1), tunnel.read(&mut buf))
        .await
        .expect("tunnel data never delivered")
        .unwrap();
    assert_eq!(&buf[..n], b"select 1");
    assert!(
        wire.sent()
            .iter()
            .any(|f| matches!(f, StreamFrame::Reset { stream_id: 1, .. })),
        "window overrun on stream 1 was not reset"
    );
}

/// Version skew: a Target that does not ack credit gets the pre-credit behavior.
#[tokio::test]
async fn hello_negotiates_credit() {
    let (_session, wire) = connect().await;
    let hello = wire
        .sent()
        .into_iter()
        .find_map(|f| match f {
            StreamFrame::Hello { features, .. } => Some(features),
            _ => None,
        })
        .expect("Source never sent Hello");
    assert!(hello.iter().any(|f| f == FEATURE_FLOW_CREDIT));
}

/// B4 (control path): window updates and other unsolicited control frames must
/// not fill the demux's control channel and stall the session.
#[tokio::test]
async fn unsolicited_control_frames_do_not_stall_demux() {
    let (mut session, wire) = connect().await;
    let mut stream = session.open_named_stream("http").await.unwrap();
    for _ in 0..200 {
        wire.inject(StreamFrame::WindowUpdate {
            stream_id: 1,
            credit: 1,
        });
    }
    wire.inject(StreamFrame::Data {
        stream_id: 1,
        bytes: b"after".to_vec(),
    });
    pump_all(&mut session, &wire).await;
    let mut buf = [0u8; 16];
    let n = timeout(Duration::from_secs(1), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"after");
}

/// Version skew: a Target that doesn't ack `flow_credit_v1` never returns credit,
/// so the Source must not window-limit sends to it (it would stall at 256 KiB).
#[tokio::test]
async fn pre_credit_target_is_not_window_limited() {
    let (mut session, _wire) = connect_to(Wire {
        old_target: true,
        ..Wire::default()
    })
    .await;
    let mut stream = session.open_named_stream("http").await.unwrap();
    let chunk = vec![1u8; 32 * 1024];
    for _ in 0..32 {
        assert_eq!(stream.write(&chunk).await.unwrap(), chunk.len());
    }
}

/// B6 (write side): a write larger than one frame is accepted partially, not rejected.
#[tokio::test]
async fn oversized_write_is_split_not_rejected() {
    let (mut session, _wire) = connect().await;
    let mut stream = session.open_named_stream("http").await.unwrap();
    let n = stream.write(&vec![0u8; 200 * 1024]).await.unwrap();
    assert_eq!(n, idr_protocol::stream_mux::MAX_DATA_PAYLOAD);
}

/// B8: a Target-initiated Open must be answered; services the Source doesn't
/// accept get `OpenError` (before 0b the Source ignored it and the Target hung).
#[tokio::test]
async fn target_initiated_open_is_answered() {
    let (mut session, wire) = connect().await;
    wire.inject(StreamFrame::Open {
        stream_id: 2,
        kind: idr_protocol::stream_mux::StreamKind::TcpConnect,
        meta: idr_protocol::stream_mux::StreamOpenMeta {
            target_fqhn: "t.idr.to".into(),
            host: None,
            port: None,
            service_name: Some("not-offered".into()),
        },
    });
    pump_all(&mut session, &wire).await;
    let answered = |w: &Wire| {
        w.sent()
            .iter()
            .any(|f| matches!(f, StreamFrame::OpenError { stream_id: 2, .. }))
    };
    for _ in 0..50 {
        if answered(&wire) {
            return;
        }
        let _ = timeout(Duration::from_millis(10), session.poll_incoming()).await;
    }
    panic!("Target-initiated Open got no reply");
}

/// B8: the Source accepts Target-initiated streams for the services it registered.
#[tokio::test]
async fn accepted_service_yields_incoming_stream() {
    let (mut session, wire) = connect().await;
    let mut incoming = session.accept_streams(&["idr.test"]).await;
    wire.inject(StreamFrame::Open {
        stream_id: 2,
        kind: idr_protocol::stream_mux::StreamKind::TcpConnect,
        meta: idr_protocol::stream_mux::StreamOpenMeta {
            target_fqhn: String::new(),
            host: None,
            port: None,
            service_name: Some("idr.test".into()),
        },
    });
    let mut accepted = timeout(Duration::from_secs(1), incoming.recv())
        .await
        .expect("no incoming stream")
        .unwrap();
    assert_eq!(accepted.service, "idr.test");
    assert!(wire
        .sent()
        .iter()
        .any(|f| matches!(f, StreamFrame::OpenOk { stream_id: 2, .. })));

    wire.inject(StreamFrame::Data {
        stream_id: 2,
        bytes: b"from-target".to_vec(),
    });
    let mut buf = [0u8; 32];
    let n = timeout(Duration::from_secs(1), accepted.stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"from-target");

    accepted.stream.write(b"from-source").await.unwrap();
    pump_all(&mut session, &wire).await;
    assert!(wire.sent().iter().any(|f| matches!(f,
        StreamFrame::Data { stream_id: 2, bytes } if bytes == b"from-source")));
}

/// B7: injected frames are delivered with nobody pumping the session.
#[tokio::test]
async fn frames_arrive_without_pumping() {
    let (mut session, wire) = connect().await;
    let mut stream = session.open_named_stream("http").await.unwrap();
    wire.inject(StreamFrame::Data {
        stream_id: 1,
        bytes: b"pushed".to_vec(),
    });
    let mut buf = [0u8; 16];
    let n = timeout(Duration::from_secs(1), stream.read(&mut buf))
        .await
        .expect("read waited for a manual pump")
        .unwrap();
    assert_eq!(&buf[..n], b"pushed");
}
