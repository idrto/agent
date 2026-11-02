//! Per-session table of mux streams bridged to upstream TCP connections (or
//! in-process pipes for Target-local endpoints).
//!
//! Transport-independent so the stream/flow logic is testable without
//! libdatachannel; `session.rs` feeds it decoded frames and sends what it queues.
//!
//! - Each stream has its own upstream writer task behind a bounded inbox, so a
//!   slow upstream never blocks the session loop. Upstream connects run off the
//!   loop too, admitted against per-session stream, in-flight and rate limits.
//! - When the Source negotiates `flow_credit_v1` in `Hello`, both directions are
//!   credit-controlled; a Source that doesn't keeps the pre-credit behavior.
//! - Frames leave through [`MuxOut`]: control first, then interactive, then bulk.
//! - With `peer_open_v1` the Target may open streams to the Source ([`MuxStreams::open_local`]).

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use idr_core::{MuxOut, SendCredit, StreamPriority};
use idr_protocol::stream_mux::{
    data_charge, MuxProfile, OpenErrorCode, StreamFrame, StreamKind, StreamOpenMeta,
    CREDIT_CONN_WINDOW, FEATURE_FLOW_CREDIT, FEATURE_PEER_OPEN, INITIAL_CONN_WINDOW,
    INITIAL_STREAM_WINDOW, MAX_STREAMS_PER_SESSION, MIN_DATA_CHARGE, RESET_FLOW_CONTROL,
    STREAM_MUX_VERSION,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use crate::webrtc::mux::encode_datachannel_message;

/// A credit-respecting Source can't have more frames than this in flight per stream.
const STREAM_INBOX_FRAMES: usize = (INITIAL_STREAM_WINDOW / MIN_DATA_CHARGE) as usize;
const STREAM_CREDIT_THRESHOLD: u32 = INITIAL_STREAM_WINDOW / 2;
const CONN_CREDIT_THRESHOLD: u32 = CREDIT_CONN_WINDOW / 4;
/// Upstream connects allowed in flight per session.
pub const MAX_PENDING_OPENS: usize = 16;
/// Open rate per session: sustained per second, and burst.
const OPENS_PER_SEC: f64 = 32.0;
const OPEN_BURST: f64 = 64.0;
/// Buffer of the in-process pipe behind a Target-local stream.
const LOCAL_PIPE_BYTES: usize = 64 * 1024;

pub type OpenRefusal = (OpenErrorCode, String);

struct Slot {
    inbound: mpsc::Sender<Vec<u8>>,
    /// Some when this stream runs under `flow_credit_v1`.
    send_credit: Option<SendCredit>,
    reset: Arc<AtomicBool>,
}

/// A Target-initiated open waiting for the Source's `OpenOk`.
struct LocalOpen {
    priority: StreamPriority,
    reply: oneshot::Sender<Result<DuplexStream, String>>,
}

struct OpenBucket {
    tokens: f64,
    last: Instant,
}

impl OpenBucket {
    fn take(&mut self, now: Instant) -> bool {
        let refill = now.duration_since(self.last).as_secs_f64() * OPENS_PER_SEC;
        self.tokens = (self.tokens + refill).min(OPEN_BURST);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct MuxStreams {
    out: MuxOut,
    /// Source negotiated `flow_credit_v1`.
    credit: bool,
    /// Source accepts Target-initiated opens.
    peer_open: bool,
    conn_send: SendCredit,
    /// Connection credit received but not yet returned.
    conn_recv_pending: u32,
    streams: HashMap<u32, Slot>,
    connecting: Arc<AtomicUsize>,
    /// Streams whose upstream connect failed; reaped before admitting new ones.
    dead_tx: mpsc::UnboundedSender<u32>,
    dead_rx: mpsc::UnboundedReceiver<u32>,
    opens: OpenBucket,
    next_local_id: u32,
    local_opens: HashMap<u32, LocalOpen>,
}

impl MuxStreams {
    pub fn new(out: MuxOut) -> Self {
        let (dead_tx, dead_rx) = mpsc::unbounded_channel();
        Self {
            out,
            credit: false,
            peer_open: false,
            conn_send: SendCredit::new(0),
            conn_recv_pending: 0,
            streams: HashMap::new(),
            connecting: Arc::new(AtomicUsize::new(0)),
            dead_tx,
            dead_rx,
            opens: OpenBucket {
                tokens: OPEN_BURST,
                last: Instant::now(),
            },
            next_local_id: 2,
            local_opens: HashMap::new(),
        }
    }

    pub fn contains(&self, stream_id: u32) -> bool {
        self.streams.contains_key(&stream_id)
    }

    /// Reply to the peer's `Hello`. `conn_window` is the Source's receive window.
    pub fn on_hello(&mut self, version: u32, features: &[String], conn_window: u32) -> StreamFrame {
        let mut ack = MuxProfile::from_features(features).advertised_features();
        let has = |f: &str| features.iter().any(|x| x == f);
        if !self.credit && has(FEATURE_FLOW_CREDIT) {
            self.credit = true;
            self.conn_send = SendCredit::new(conn_window);
        }
        self.peer_open |= self.credit && has(FEATURE_PEER_OPEN);
        let conn_window = if self.credit {
            ack.push(FEATURE_FLOW_CREDIT.into());
            CREDIT_CONN_WINDOW
        } else {
            conn_window.min(INITIAL_CONN_WINDOW)
        };
        if self.peer_open {
            ack.push(FEATURE_PEER_OPEN.into());
        }
        StreamFrame::HelloAck {
            version: version.min(STREAM_MUX_VERSION),
            features: ack,
            conn_window,
        }
    }

    fn reap(&mut self) {
        while let Ok(id) = self.dead_rx.try_recv() {
            self.streams.remove(&id);
        }
    }

    fn at_capacity(&self) -> bool {
        self.streams.len() + self.local_opens.len() >= MAX_STREAMS_PER_SESSION
    }

    /// Check a Source `Open` before any resources are spent on it.
    pub fn admit_open(&mut self, stream_id: u32) -> Result<(), OpenRefusal> {
        self.admit_open_at(stream_id, Instant::now())
    }

    fn admit_open_at(&mut self, stream_id: u32, now: Instant) -> Result<(), OpenRefusal> {
        self.reap();
        let refuse = |code, msg: &str| Err((code, msg.to_string()));
        if stream_id % 2 == 0 {
            return refuse(OpenErrorCode::InvalidArgument, "Source stream ids are odd");
        }
        if self.streams.contains_key(&stream_id) {
            return refuse(OpenErrorCode::InvalidArgument, "duplicate stream id");
        }
        if self.at_capacity() {
            return refuse(OpenErrorCode::ResourceExhausted, "too many open streams");
        }
        if self.connecting.load(Ordering::Acquire) >= MAX_PENDING_OPENS {
            return refuse(OpenErrorCode::ResourceExhausted, "too many opens in progress");
        }
        if !self.opens.take(now) {
            return refuse(OpenErrorCode::ResourceExhausted, "open rate limit");
        }
        Ok(())
    }

    fn new_slot(&mut self, stream_id: u32, send_window: u32) -> (mpsc::Receiver<Vec<u8>>, Pipe) {
        let (inbound, inbox) = mpsc::channel::<Vec<u8>>(STREAM_INBOX_FRAMES);
        let send_credit = self.credit.then(|| SendCredit::new(send_window));
        let reset = Arc::new(AtomicBool::new(false));
        self.streams.insert(
            stream_id,
            Slot {
                inbound,
                send_credit: send_credit.clone(),
                reset: reset.clone(),
            },
        );
        let pipe = Pipe {
            stream_id,
            out: self.out.clone(),
            credit: send_credit.map(|s| (s, self.conn_send.clone())),
            reset,
        };
        (inbox, pipe)
    }

    /// Accept an admitted Source `Open`: data is buffered while `connect` runs off
    /// the session loop, then `OpenOk` (or `OpenError`) is sent and the stream bridged.
    pub fn open_with<F, T>(
        &mut self,
        stream_id: u32,
        priority: StreamPriority,
        connect: F,
        on_reader_done: impl FnOnce() + Send + 'static,
    ) where
        F: Future<Output = Result<T, OpenRefusal>> + Send + 'static,
        T: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (inbox, pipe) = self.new_slot(stream_id, INITIAL_STREAM_WINDOW);
        let connecting = self.connecting.clone();
        let dead = self.dead_tx.clone();
        connecting.fetch_add(1, Ordering::AcqRel);
        tokio::spawn(async move {
            let result = connect.await;
            connecting.fetch_sub(1, Ordering::AcqRel);
            match result {
                Err((code, message)) => {
                    let _ = dead.send(stream_id);
                    pipe.control(&StreamFrame::OpenError {
                        stream_id,
                        code: code as u16,
                        message,
                    })
                    .await;
                }
                Ok(_) if pipe.reset.load(Ordering::Acquire) => {}
                Ok(io) => {
                    pipe.control(&StreamFrame::OpenOk {
                        stream_id,
                        initial_window: INITIAL_STREAM_WINDOW,
                    })
                    .await;
                    pipe.bridge(io, inbox, priority, on_reader_done).await;
                }
            }
        });
    }

    /// Bridge an already-connected upstream (accepts the stream immediately).
    pub fn attach(
        &mut self,
        stream_id: u32,
        tcp: TcpStream,
        on_reader_done: impl FnOnce() + Send + 'static,
    ) {
        self.open_with(
            stream_id,
            StreamPriority::Interactive,
            async { Ok(tcp) },
            on_reader_done,
        );
    }

    /// Open a stream to the Source for `service`. The receiver yields the local end
    /// once the Source accepts, or the Source's refusal.
    pub async fn open_local(
        &mut self,
        service: &str,
        priority: StreamPriority,
    ) -> Result<oneshot::Receiver<Result<DuplexStream, String>>, &'static str> {
        if !self.peer_open {
            return Err("Source does not accept Target-initiated streams");
        }
        self.reap();
        if self.at_capacity() {
            return Err("too many open streams");
        }
        let stream_id = self.next_local_id;
        self.next_local_id = self.next_local_id.wrapping_add(2).max(2);
        let open = StreamFrame::Open {
            stream_id,
            kind: StreamKind::TcpConnect,
            meta: StreamOpenMeta {
                target_fqhn: String::new(),
                host: None,
                port: None,
                service_name: Some(service.to_string()),
            },
        };
        if !send_control(&self.out, &open).await {
            return Err("session closed");
        }
        let (reply, rx) = oneshot::channel();
        self.local_opens
            .insert(stream_id, LocalOpen { priority, reply });
        Ok(rx)
    }

    /// The Source accepted a Target-initiated stream.
    pub fn on_open_ok(&mut self, stream_id: u32, initial_window: u32) {
        let Some(open) = self.local_opens.remove(&stream_id) else {
            return;
        };
        let (local, remote) = tokio::io::duplex(LOCAL_PIPE_BYTES);
        let (inbox, pipe) = self.new_slot(stream_id, initial_window);
        tokio::spawn(pipe.bridge(remote, inbox, open.priority, || {}));
        let _ = open.reply.send(Ok(local));
    }

    pub fn on_open_error(&mut self, stream_id: u32, message: String) {
        if let Some(open) = self.local_opens.remove(&stream_id) {
            let _ = open.reply.send(Err(message));
        }
    }

    /// Deliver peer DATA. Returns frames to send back to the peer right away.
    ///
    /// Never waits under `flow_credit_v1`: a full inbox means the Source sent past
    /// its window, and only that stream is reset. Pre-credit streams wait for room
    /// (the old behavior).
    pub async fn on_data(&mut self, stream_id: u32, bytes: Vec<u8>) -> Vec<StreamFrame> {
        let mut replies = Vec::new();
        let charge = data_charge(bytes.len());
        match self.streams.get(&stream_id) {
            Some(slot) if slot.send_credit.is_some() => {
                if let Err(mpsc::error::TrySendError::Full(_)) = slot.inbound.try_send(bytes) {
                    warn!(stream_id, "Source overran stream window; resetting stream");
                    self.on_reset(stream_id);
                    replies.push(StreamFrame::Reset {
                        stream_id,
                        reason: RESET_FLOW_CONTROL,
                    });
                }
            }
            Some(slot) => {
                let _ = slot.inbound.send(bytes).await;
            }
            None => {}
        }
        // Connection credit returns as soon as a frame leaves the DataChannel
        // queue; per-stream memory is bounded by the stream window instead.
        if self.credit {
            self.conn_recv_pending += charge;
            if self.conn_recv_pending >= CONN_CREDIT_THRESHOLD {
                replies.push(StreamFrame::WindowUpdate {
                    stream_id: 0,
                    credit: std::mem::take(&mut self.conn_recv_pending),
                });
            }
        }
        replies
    }

    /// Source finished sending; queued data is still written, then upstream is shut down.
    /// Returns true when the stream existed.
    pub fn on_half_close(&mut self, stream_id: u32) -> bool {
        self.streams.remove(&stream_id).is_some()
    }

    /// Returns true when the stream existed.
    pub fn on_reset(&mut self, stream_id: u32) -> bool {
        match self.streams.remove(&stream_id) {
            Some(slot) => {
                slot.reset.store(true, Ordering::Release);
                if let Some(c) = slot.send_credit {
                    c.close();
                }
                true
            }
            None => false,
        }
    }

    pub fn on_window_update(&mut self, stream_id: u32, credit: u32) {
        if stream_id == 0 {
            self.conn_send.grant(credit);
        } else if let Some(c) = self.streams.get(&stream_id).and_then(|s| s.send_credit.as_ref()) {
            c.grant(credit);
        }
    }
}

/// One stream's outbound side, moved into its bridge tasks.
struct Pipe {
    stream_id: u32,
    out: MuxOut,
    /// (stream, connection) send credit under `flow_credit_v1`.
    credit: Option<(SendCredit, SendCredit)>,
    reset: Arc<AtomicBool>,
}

impl Pipe {
    async fn control(&self, frame: &StreamFrame) -> bool {
        send_control(&self.out, frame).await
    }

    /// Pump `io` ↔ the peer until upstream EOF or failure.
    async fn bridge<T>(
        self,
        io: T,
        mut inbox: mpsc::Receiver<Vec<u8>>,
        priority: StreamPriority,
        on_reader_done: impl FnOnce() + Send + 'static,
    ) where
        T: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (mut read_half, mut write_half) = tokio::io::split(io);
        let stream_id = self.stream_id;

        // Peer → upstream.
        let out = self.out.clone();
        let credit = self.credit.is_some();
        let dead = self.reset.clone();
        tokio::spawn(async move {
            let mut pending = 0u32;
            while let Some(bytes) = inbox.recv().await {
                if dead.load(Ordering::Acquire) {
                    continue;
                }
                if let Err(e) = write_half.write_all(&bytes).await {
                    warn!(error = %e, stream_id, "upstream write failed");
                    dead.store(true, Ordering::Release);
                    send_control(&out, &StreamFrame::Reset { stream_id, reason: 1 }).await;
                    continue;
                }
                if credit {
                    pending += data_charge(bytes.len());
                    if pending >= STREAM_CREDIT_THRESHOLD {
                        let update = StreamFrame::WindowUpdate {
                            stream_id,
                            credit: std::mem::take(&mut pending),
                        };
                        send_control(&out, &update).await;
                    }
                }
            }
            if !dead.load(Ordering::Acquire) {
                let _ = write_half.shutdown().await;
            }
        });

        // Upstream → peer.
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let frame = match read_half.read(&mut buf).await {
                Ok(0) => {
                    // In order behind this stream's data.
                    send_data(&self.out, priority, &StreamFrame::HalfClose { stream_id }).await;
                    break;
                }
                Ok(n) => {
                    if let Some((stream, conn)) = &self.credit {
                        let charge = data_charge(n);
                        if stream.take(charge).await.is_err() || conn.take(charge).await.is_err() {
                            break;
                        }
                    }
                    StreamFrame::Data {
                        stream_id,
                        bytes: buf[..n].to_vec(),
                    }
                }
                Err(e) => {
                    warn!(error = %e, stream_id, "upstream read failed");
                    self.control(&StreamFrame::Reset { stream_id, reason: 1 }).await;
                    break;
                }
            };
            if !send_data(&self.out, priority, &frame).await {
                break;
            }
        }
        on_reader_done();
    }
}

fn encode(frame: &StreamFrame) -> Option<Vec<u8>> {
    encode_datachannel_message(frame)
        .map_err(|e| warn!(error = %e, "encode frame failed"))
        .ok()
}

async fn send_control(out: &MuxOut, frame: &StreamFrame) -> bool {
    match encode(frame) {
        Some(bytes) => out.control(bytes).await,
        None => false,
    }
}

async fn send_data(out: &MuxOut, priority: StreamPriority, frame: &StreamFrame) -> bool {
    match encode(frame) {
        Some(bytes) => out.data(priority, bytes).await,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use idr_protocol::stream_mux::{
        CREDIT_CONN_WINDOW, FEATURE_FLOW_CONTROL, FEATURE_FLOW_CREDIT, INITIAL_STREAM_WINDOW,
    };
    use idr_core::{mux_out, MuxOutRx};
    use tokio::time::timeout;

    use super::*;

    const CHUNK: usize = 32 * 1024;

    fn credit_streams() -> (MuxStreams, MuxOutRx) {
        let (out, rx) = mux_out(128);
        let mut streams = MuxStreams::new(out);
        streams.on_hello(
            1,
            &[FEATURE_FLOW_CONTROL.into(), FEATURE_FLOW_CREDIT.into()],
            CREDIT_CONN_WINDOW,
        );
        (streams, rx)
    }

    /// Upstream whose accepted socket is handed to `serve`.
    async fn upstream<F, Fut>(serve: F) -> TcpStream
    where
        F: FnOnce(TcpStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        // Small kernel buffers so a consumer that stops reading stalls writers
        // quickly (Windows loopback otherwise absorbs tens of MiB).
        let server = tokio::net::TcpSocket::new_v4().unwrap();
        server.set_recv_buffer_size(4096).unwrap();
        server.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = server.listen(1).unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            serve(sock).await;
        });
        let client = tokio::net::TcpSocket::new_v4().unwrap();
        client.set_send_buffer_size(4096).unwrap();
        client.connect(addr).await.unwrap()
    }

    async fn next_frame(rx: &mut MuxOutRx, wait: Duration) -> Option<StreamFrame> {
        let bytes = timeout(wait, rx.next(true)).await.ok()??;
        Some(StreamFrame::decode(&bytes).unwrap())
    }

    /// B2: Target→Source DATA must stop at the Source's granted credit.
    #[tokio::test(flavor = "multi_thread")]
    async fn target_send_respects_peer_credit() {
        let (mut streams, mut rx) = credit_streams();
        let tcp = upstream(|mut s| async move {
            let chunk = vec![7u8; 64 * 1024];
            for _ in 0..64 {
                if s.write_all(&chunk).await.is_err() {
                    return;
                }
            }
            std::future::pending::<()>().await;
        })
        .await;
        streams.attach(1, tcp, || {});

        let mut sent = 0usize;
        while let Some(f) = next_frame(&mut rx, Duration::from_millis(500)).await {
            if let StreamFrame::Data { bytes, .. } = f {
                sent += bytes.len();
            }
        }
        assert!(
            sent <= INITIAL_STREAM_WINDOW as usize,
            "sent {sent} bytes without credit (window {INITIAL_STREAM_WINDOW})"
        );

        streams.on_window_update(1, 128 * 1024);
        let mut more = 0usize;
        while let Some(f) = next_frame(&mut rx, Duration::from_millis(300)).await {
            if let StreamFrame::Data { bytes, .. } = f {
                more += bytes.len();
            }
        }
        assert!(more > 0 && more <= 128 * 1024, "credit 128 KiB released {more} bytes");
    }

    /// B1 (Target half): consumed DATA must be credited back, per stream and per connection.
    #[tokio::test(flavor = "multi_thread")]
    async fn target_returns_credit_as_upstream_consumes() {
        let (mut streams, mut rx) = credit_streams();
        let tcp = upstream(|mut s| async move {
            let mut buf = vec![0u8; 64 * 1024];
            while matches!(s.read(&mut buf).await, Ok(n) if n > 0) {}
        })
        .await;
        streams.attach(1, tcp, || {});

        let mut stream_credit = 0u64;
        let mut conn_credit = 0u64;
        for round in 0..10 {
            for _ in 0..4 {
                for f in streams.on_data(1, vec![1; CHUNK]).await {
                    if let StreamFrame::WindowUpdate { stream_id: 0, credit } = f {
                        conn_credit += credit as u64;
                    }
                }
            }
            let got = loop {
                match next_frame(&mut rx, Duration::from_secs(2)).await {
                    Some(StreamFrame::WindowUpdate { stream_id: 1, credit }) => break credit,
                    Some(StreamFrame::WindowUpdate { stream_id: 0, credit }) => {
                        conn_credit += credit as u64;
                    }
                    Some(_) => {}
                    None => panic!("no stream credit returned in round {round}"),
                }
            };
            stream_credit += got as u64;
        }
        assert_eq!(stream_credit, 10 * 4 * CHUNK as u64);
        assert!(conn_credit > 0, "no connection credit after 1.25 MiB");
    }

    fn refused(r: Result<(), OpenRefusal>) -> OpenErrorCode {
        r.expect_err("open was admitted").0
    }

    /// B10: opens are refused for bad ids, past the rate limit and the in-flight cap.
    #[tokio::test]
    async fn opens_are_admitted_within_limits() {
        let (mut streams, _rx) = credit_streams();
        let t0 = Instant::now();
        assert_eq!(refused(streams.admit_open_at(2, t0)), OpenErrorCode::InvalidArgument);

        // Burst, then the rate limit.
        let mut id = 1;
        for _ in 0..OPEN_BURST as usize {
            streams.admit_open_at(id, t0).unwrap();
            id += 2;
        }
        assert_eq!(refused(streams.admit_open_at(id, t0)), OpenErrorCode::ResourceExhausted);
        let later = t0 + Duration::from_secs(1);
        streams.admit_open_at(id, later).unwrap();

        // In-flight connects.
        for i in 0..MAX_PENDING_OPENS as u32 {
            streams.open_with(
                1001 + 2 * i,
                StreamPriority::Interactive,
                std::future::pending::<Result<TcpStream, OpenRefusal>>(),
                || {},
            );
        }
        tokio::task::yield_now().await;
        let much_later = t0 + Duration::from_secs(60);
        assert_eq!(
            refused(streams.admit_open_at(9001, much_later)),
            OpenErrorCode::ResourceExhausted
        );
        assert_eq!(
            refused(streams.admit_open_at(1001, much_later)),
            OpenErrorCode::InvalidArgument,
            "duplicate id"
        );
    }

    /// B10: the per-session stream cap.
    #[tokio::test]
    async fn stream_cap_refuses_new_opens() {
        let (mut streams, _rx) = credit_streams();
        let mut keep = Vec::new();
        for i in 0..MAX_STREAMS_PER_SESSION as u32 {
            let (a, b) = tokio::io::duplex(64);
            keep.push(b);
            streams.open_with(1 + 2 * i, StreamPriority::Interactive, async { Ok(a) }, || {});
        }
        let later = Instant::now() + Duration::from_secs(60);
        assert_eq!(
            refused(streams.admit_open_at(100_001, later)),
            OpenErrorCode::ResourceExhausted
        );
    }

    /// B10: data sent while the upstream connect is in flight is delivered after it.
    #[tokio::test(flavor = "multi_thread")]
    async fn data_during_slow_connect_is_buffered() {
        let (mut streams, mut rx) = credit_streams();
        let (tx, connected) = oneshot::channel::<TcpStream>();
        streams.open_with(
            1,
            StreamPriority::Interactive,
            async move { Ok(connected.await.unwrap()) },
            || {},
        );
        assert!(streams.on_data(1, b"early".to_vec()).await.is_empty());

        let echo = upstream(|s| async move {
            let (mut r, mut w) = s.into_split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        })
        .await;
        tx.send(echo).unwrap();
        let mut saw_ok = false;
        loop {
            match next_frame(&mut rx, Duration::from_secs(2)).await {
                Some(StreamFrame::OpenOk { stream_id: 1, .. }) => saw_ok = true,
                Some(StreamFrame::Data { stream_id: 1, bytes }) => {
                    assert!(saw_ok, "data before OpenOk");
                    assert_eq!(bytes, b"early");
                    return;
                }
                Some(_) => {}
                None => panic!("buffered data never reached upstream"),
            }
        }
    }

    /// B10: a failed upstream connect answers OpenError and frees the slot.
    #[tokio::test]
    async fn failed_connect_answers_open_error() {
        let (mut streams, mut rx) = credit_streams();
        streams.open_with(
            1,
            StreamPriority::Interactive,
            async { Err::<TcpStream, _>((OpenErrorCode::ConnectionRefused, "down".into())) },
            || {},
        );
        match next_frame(&mut rx, Duration::from_secs(1)).await {
            Some(StreamFrame::OpenError { stream_id: 1, .. }) => {}
            other => panic!("expected OpenError, got {other:?}"),
        }
        streams.reap();
        assert!(!streams.contains(1));
    }

    /// B8: Target-initiated open, only toward a Source that negotiated it.
    #[tokio::test(flavor = "multi_thread")]
    async fn target_opens_stream_to_source() {
        let (out, mut rx) = mux_out(128);
        let mut old_source = MuxStreams::new(out.clone());
        old_source.on_hello(1, &[FEATURE_FLOW_CREDIT.into()], CREDIT_CONN_WINDOW);
        assert!(old_source.open_local("idr.test", StreamPriority::Bulk).await.is_err());

        let mut streams = MuxStreams::new(out);
        let ack = streams.on_hello(
            1,
            &[FEATURE_FLOW_CREDIT.into(), FEATURE_PEER_OPEN.into()],
            CREDIT_CONN_WINDOW,
        );
        assert!(matches!(ack, StreamFrame::HelloAck { ref features, .. }
            if features.iter().any(|f| f == FEATURE_PEER_OPEN)));
        let pending = streams.open_local("idr.test", StreamPriority::Bulk).await.unwrap();
        let id = match next_frame(&mut rx, Duration::from_secs(1)).await {
            Some(StreamFrame::Open { stream_id, meta, .. }) => {
                assert_eq!(stream_id % 2, 0, "Target-initiated ids are even");
                assert_eq!(meta.service_name.as_deref(), Some("idr.test"));
                stream_id
            }
            other => panic!("expected Open, got {other:?}"),
        };
        streams.on_open_ok(id, INITIAL_STREAM_WINDOW);
        let mut local = timeout(Duration::from_secs(1), pending).await.unwrap().unwrap().unwrap();

        local.write_all(b"to-source").await.unwrap();
        match next_frame(&mut rx, Duration::from_secs(1)).await {
            Some(StreamFrame::Data { stream_id, bytes }) if stream_id == id => {
                assert_eq!(bytes, b"to-source")
            }
            other => panic!("expected Data, got {other:?}"),
        }
        streams.on_data(id, b"to-target".to_vec()).await;
        let mut buf = [0u8; 16];
        let n = timeout(Duration::from_secs(1), local.read(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"to-target");

        let refused = streams.open_local("nope", StreamPriority::Bulk).await.unwrap();
        let id2 = match next_frame(&mut rx, Duration::from_secs(1)).await {
            Some(StreamFrame::Open { stream_id, .. }) => stream_id,
            other => panic!("expected Open, got {other:?}"),
        };
        streams.on_open_error(id2, "service not offered".into());
        assert!(timeout(Duration::from_secs(1), refused).await.unwrap().unwrap().is_err());
    }

    /// B5: credit for one stream must not queue behind another stream's bulk data.
    #[tokio::test(flavor = "multi_thread")]
    async fn control_frames_overtake_queued_data() {
        let (mut streams, mut rx) = credit_streams();
        let bulk = upstream(|mut s| async move {
            let chunk = vec![9u8; 64 * 1024];
            while s.write_all(&chunk).await.is_ok() {}
        })
        .await;
        streams.attach(1, bulk, || {});
        streams.on_window_update(1, 8 * 1024 * 1024);
        tokio::time::sleep(Duration::from_millis(300)).await;

        let sink = upstream(|mut s| async move {
            let mut buf = vec![0u8; 64 * 1024];
            while matches!(s.read(&mut buf).await, Ok(n) if n > 0) {}
        })
        .await;
        streams.attach(3, sink, || {});
        for _ in 0..4 {
            streams.on_data(3, vec![1; CHUNK]).await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;

        for i in 0..400 {
            match next_frame(&mut rx, Duration::from_secs(1)).await {
                Some(StreamFrame::WindowUpdate { stream_id: 3, .. }) => {
                    assert!(i < 4, "credit frame was behind {i} queued frames");
                    return;
                }
                Some(_) => {}
                None => break,
            }
        }
        panic!("credit for stream 3 never sent");
    }

    /// Version skew: a Source that never sent `Hello` with `flow_credit_v1` gets the
    /// pre-credit behavior: no send window, no credit frames.
    #[tokio::test(flavor = "multi_thread")]
    async fn pre_credit_source_keeps_old_behavior() {
        let (out, mut rx) = mux_out(128);
        let mut streams = MuxStreams::new(out);
        let tcp = upstream(|mut s| async move {
            let chunk = vec![7u8; 64 * 1024];
            for _ in 0..16 {
                if s.write_all(&chunk).await.is_err() {
                    return;
                }
            }
            let mut buf = vec![0u8; 64 * 1024];
            while matches!(s.read(&mut buf).await, Ok(n) if n > 0) {}
        })
        .await;
        streams.attach(1, tcp, || {});
        for _ in 0..16 {
            assert!(streams.on_data(1, vec![1; CHUNK]).await.is_empty());
        }

        let (mut sent, mut credit_frames) = (0usize, 0);
        while let Some(f) = next_frame(&mut rx, Duration::from_millis(500)).await {
            match f {
                StreamFrame::Data { bytes, .. } => sent += bytes.len(),
                StreamFrame::WindowUpdate { .. } => credit_frames += 1,
                _ => {}
            }
        }
        assert_eq!(sent, 1024 * 1024, "pre-credit sends are not window-limited");
        assert_eq!(credit_frames, 0);
    }

    /// B4 + regression: a stalled bulk upstream must not block the session loop;
    /// a tunnel-style echo stream stays responsive throughout.
    #[tokio::test(flavor = "multi_thread")]
    async fn tunnel_stays_responsive_while_bulk_upstream_stalls() {
        let (mut streams, mut rx) = credit_streams();
        let stalled = upstream(|s| async move {
            let _held_open_never_read = s;
            std::future::pending::<()>().await;
        })
        .await;
        let echo = upstream(|s| async move {
            let (mut r, mut w) = s.into_split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        })
        .await;
        streams.attach(1, stalled, || {});
        streams.attach(3, echo, || {});

        let mut reset_bulk = false;
        for i in 0..1024 {
            let replies = timeout(Duration::from_secs(1), streams.on_data(1, vec![0; 64 * 1024]))
                .await
                .unwrap_or_else(|_| panic!("session loop blocked by bulk stream at frame {i}"));
            reset_bulk |= replies
                .iter()
                .any(|f| matches!(f, StreamFrame::Reset { stream_id: 1, .. }));

            if i % 64 == 0 {
                let ping = format!("ping-{i}").into_bytes();
                let started = std::time::Instant::now();
                timeout(Duration::from_secs(1), streams.on_data(3, ping.clone()))
                    .await
                    .expect("tunnel write blocked");
                loop {
                    match next_frame(&mut rx, Duration::from_secs(1)).await {
                        Some(StreamFrame::Data { stream_id: 3, bytes }) => {
                            assert_eq!(bytes, ping);
                            break;
                        }
                        Some(_) => {}
                        None => panic!("tunnel echo lost at frame {i}"),
                    }
                }
                assert!(started.elapsed() < Duration::from_millis(500));
            }
        }
        assert!(reset_bulk, "bulk stream overran its window without a reset");
    }
}
