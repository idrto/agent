//! Multiplexed logical streams over one DataChannel, fed by the session driver.
//!
//! When the Target acks `flow_credit_v1`, sends are limited by stream and
//! connection credit (writes wait for it) and the demux never waits on a
//! stream's reader: a Target that overruns a stream window gets that stream
//! reset. Without the ack the pre-credit behavior is kept.
//!
//! Outbound frames go through [`MuxOut`] (control > interactive > bulk); the
//! driver task in `runtime.rs` is the only one touching the transport.

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use idr_core::error::{IdrError, IdrErrorKind, Result};
use idr_core::flow::SendCredit;
use idr_core::stream::{LogicalStream, StreamId};
use idr_core::{MuxOut, StreamPriority};
use idr_protocol::stream_mux::{
    data_charge, MuxProfile, OpenErrorCode, StreamFrame, StreamOpenMeta, CREDIT_CONN_WINDOW,
    FEATURE_FLOW_CREDIT, INITIAL_STREAM_WINDOW, MAX_DATA_PAYLOAD, MAX_STREAMS_PER_SESSION,
    MIN_DATA_CHARGE, RESET_FLOW_CONTROL,
};
use tokio::sync::{mpsc, oneshot};

/// A credit-respecting Target can't have more frames than this in flight per stream.
pub(crate) const STREAM_INBOX_FRAMES: usize = (INITIAL_STREAM_WINDOW / MIN_DATA_CHARGE) as usize;
const STREAM_CREDIT_THRESHOLD: u32 = INITIAL_STREAM_WINDOW / 2;
const CONN_CREDIT_THRESHOLD: u32 = CREDIT_CONN_WINDOW / 4;

/// Stream and connection send credit under `flow_credit_v1`.
#[derive(Debug, Clone)]
pub struct StreamCredit {
    pub stream: SendCredit,
    pub conn: SendCredit,
}

fn closed() -> IdrError {
    IdrError::new(IdrErrorKind::TransportClosed, "session closed")
}

pub struct MuxLogicalStream {
    id: StreamId,
    out: MuxOut,
    priority: StreamPriority,
    inbound: mpsc::Receiver<Vec<u8>>,
    half_closed: bool,
    profile: MuxProfile,
    /// None when the Target didn't negotiate credit: sends are not window-limited.
    credit: Option<StreamCredit>,
    /// Receive credit consumed but not yet returned.
    recv_pending: u32,
    /// Unread tail of the last DATA frame (`unread[pos..]`).
    unread: Vec<u8>,
    pos: usize,
}

impl MuxLogicalStream {
    pub fn new(
        id: StreamId,
        out: MuxOut,
        priority: StreamPriority,
        inbound: mpsc::Receiver<Vec<u8>>,
        profile: MuxProfile,
        credit: Option<StreamCredit>,
    ) -> Self {
        Self {
            id,
            out,
            priority,
            inbound,
            half_closed: false,
            profile,
            credit,
            recv_pending: 0,
            unread: Vec::new(),
            pos: 0,
        }
    }

    /// Credit for up to `want` bytes: whatever is available now, otherwise wait
    /// for a full charge. Returns how many bytes may be sent.
    async fn reserve(&self, want: usize) -> Result<usize> {
        let Some(c) = &self.credit else {
            return Ok(want);
        };
        if c.stream.is_closed() {
            return Err(IdrError::new(IdrErrorKind::StreamReset, "stream reset"));
        }
        let avail = c.stream.available().min(c.conn.available()) as usize;
        let n = want.min(avail);
        let charge = data_charge(n);
        if n > 0 && charge as usize <= avail && c.stream.try_take(charge) {
            if c.conn.try_take(charge) {
                return Ok(n);
            }
            c.stream.grant(charge);
        }
        let charge = data_charge(want);
        c.stream.take(charge).await?;
        if c.conn.take(charge).await.is_err() {
            return Err(closed());
        }
        Ok(want)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl LogicalStream for MuxLogicalStream {
    fn id(&self) -> StreamId {
        self.id
    }

    /// Sends at most one frame and returns the bytes accepted. Waits for credit
    /// when the window is exhausted.
    async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if self.half_closed {
            return Err(IdrError::new(
                IdrErrorKind::TransportClosed,
                "stream half-closed",
            ));
        }
        // An empty DATA frame would read as EOF on the far side.
        if buf.is_empty() {
            return Ok(0);
        }
        let n = self.reserve(buf.len().min(MAX_DATA_PAYLOAD)).await?;
        let frame = StreamFrame::Data {
            stream_id: self.id.0,
            bytes: buf[..n].to_vec(),
        };
        if !self.out.data(self.priority, frame.encode()?).await {
            return Err(closed());
        }
        Ok(n)
    }

    /// Cancel-safe: received bytes are kept before any await, and unsent credit
    /// stays pending until its `WindowUpdate` is queued.
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.pos == self.unread.len() {
            match self.inbound.recv().await {
                Some(bytes) if !bytes.is_empty() => {
                    if self.profile == MuxProfile::FlowControlV1 {
                        self.recv_pending += data_charge(bytes.len());
                    }
                    self.unread = bytes;
                    self.pos = 0;
                }
                _ => return Ok(0),
            }
        }
        if self.recv_pending >= STREAM_CREDIT_THRESHOLD {
            let credit = self.recv_pending;
            let frame = StreamFrame::WindowUpdate {
                stream_id: self.id.0,
                credit,
            };
            if self.out.control(frame.encode()?).await {
                self.recv_pending -= credit;
            }
        }
        let n = (self.unread.len() - self.pos).min(buf.len());
        buf[..n].copy_from_slice(&self.unread[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }

    async fn half_close(&mut self) -> Result<()> {
        if self.half_closed {
            return Ok(());
        }
        self.half_closed = true;
        let frame = StreamFrame::HalfClose {
            stream_id: self.id.0,
        };
        // In order behind this stream's data.
        if !self.out.data(self.priority, frame.encode()?).await {
            return Err(closed());
        }
        Ok(())
    }

    async fn reset(&mut self, reason: u16) -> Result<()> {
        let frame = StreamFrame::Reset {
            stream_id: self.id.0,
            reason,
        };
        if !self.out.control(frame.encode()?).await {
            return Err(closed());
        }
        Ok(())
    }
}

/// A stream the Target opened to this Source (`peer_open_v1`).
pub struct IncomingStream {
    pub service: String,
    pub stream: Box<dyn LogicalStream>,
}

/// Replies the session is waiting for, demuxed from the DataChannel.
#[derive(Debug, Clone)]
pub enum DemuxEvent {
    OpenOk {
        stream_id: u32,
        initial_window: u32,
    },
    OpenError {
        stream_id: u32,
        code: u16,
        message: String,
    },
    GoAway {
        last_stream_id: u32,
    },
    ServicesCatalog {
        services: Vec<String>,
    },
    ServicesCatalogDetailed {
        entries: Vec<idr_protocol::stream_mux::ServiceCatalogEntry>,
    },
}

/// Demux DataChannel binary frames into per-stream inboxes and control waiters.
pub struct StreamDemux {
    pub inboxes: HashMap<u32, mpsc::Sender<Vec<u8>>>,
    pub control_tx: Option<mpsc::Sender<DemuxEvent>>,
    outbound_cap: usize,
    out: MuxOut,
    send_credits: HashMap<u32, SendCredit>,
    /// Connection send credit; Some once the Target acked `flow_credit_v1`.
    conn_send: Option<SendCredit>,
    /// Connection credit received but not yet returned.
    conn_recv_pending: u32,
    /// Services the Target may open streams for, and where they go.
    accepts: HashSet<String>,
    incoming: Option<mpsc::Sender<IncomingStream>>,
    /// Our `Open`s waiting for `OpenOk` (Ok) or `OpenError` (Err(message)).
    pending_opens: HashMap<u32, oneshot::Sender<std::result::Result<(), String>>>,
}

impl StreamDemux {
    pub fn new(outbound_cap: usize, out: MuxOut, control_tx: mpsc::Sender<DemuxEvent>) -> Self {
        Self {
            inboxes: HashMap::new(),
            control_tx: Some(control_tx),
            outbound_cap,
            out,
            send_credits: HashMap::new(),
            conn_send: None,
            conn_recv_pending: 0,
            accepts: HashSet::new(),
            incoming: None,
            pending_opens: HashMap::new(),
        }
    }

    /// Wait for the Target's answer to our `Open` of `stream_id`.
    pub fn expect_open(&mut self, stream_id: u32) -> oneshot::Receiver<std::result::Result<(), String>> {
        let (tx, rx) = oneshot::channel();
        self.pending_opens.insert(stream_id, tx);
        rx
    }

    pub fn forget_open(&mut self, stream_id: u32) {
        self.pending_opens.remove(&stream_id);
    }

    pub fn register(&mut self, stream_id: u32) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel(self.outbound_cap.max(1));
        self.inboxes.insert(stream_id, tx);
        rx
    }

    /// Send credit for a stream the Target accepted, when credit was negotiated.
    pub fn credit_for(&self, stream_id: u32) -> Option<StreamCredit> {
        Some(StreamCredit {
            stream: self.send_credits.get(&stream_id)?.clone(),
            conn: self.conn_send.clone()?,
        })
    }

    /// Accept Target-initiated streams for `services`; they arrive on `incoming`.
    pub fn accept(&mut self, services: HashSet<String>, incoming: mpsc::Sender<IncomingStream>) {
        self.accepts = services;
        self.incoming = Some(incoming);
    }

    /// Session ended: readers see EOF, writers and `open` calls fail.
    pub fn close_all(&mut self) {
        self.inboxes.clear();
        for (_, c) in self.send_credits.drain() {
            c.close();
        }
        if let Some(c) = &self.conn_send {
            c.close();
        }
        self.control_tx = None;
        self.incoming = None;
        self.pending_opens.clear();
    }

    /// Replies are only awaited by `open`/catalog calls; never block the demux on them.
    fn emit_control(&self, ev: DemuxEvent) {
        if let Some(tx) = &self.control_tx {
            let _ = tx.try_send(ev);
        }
    }

    /// Dropping the inbox sender ends the reader with EOF after queued data.
    fn drop_stream(&mut self, stream_id: u32) {
        self.inboxes.remove(&stream_id);
        if let Some(c) = self.send_credits.remove(&stream_id) {
            c.close();
        }
    }

    /// Answer a Target-initiated `Open`.
    fn accept_open(&mut self, stream_id: u32, meta: StreamOpenMeta) -> StreamFrame {
        let refuse = |code: OpenErrorCode, message: &str| StreamFrame::OpenError {
            stream_id,
            code: code as u16,
            message: message.into(),
        };
        if stream_id == 0 || stream_id % 2 == 1 || self.inboxes.contains_key(&stream_id) {
            return refuse(OpenErrorCode::InvalidArgument, "invalid stream id");
        }
        let service = meta.service_name.unwrap_or_default();
        let (Some(incoming), Some(conn)) = (&self.incoming, &self.conn_send) else {
            return refuse(OpenErrorCode::ServiceNotFound, "service not offered");
        };
        if !self.accepts.contains(&service) {
            return refuse(OpenErrorCode::ServiceNotFound, "service not offered");
        }
        if self.inboxes.len() >= MAX_STREAMS_PER_SESSION {
            return refuse(OpenErrorCode::ResourceExhausted, "too many open streams");
        }
        let (incoming, conn) = (incoming.clone(), conn.clone());
        let rx = self.register(stream_id);
        let send = SendCredit::new(INITIAL_STREAM_WINDOW);
        self.send_credits.insert(stream_id, send.clone());
        let stream = MuxLogicalStream::new(
            StreamId(stream_id),
            self.out.clone(),
            StreamPriority::Interactive,
            rx,
            MuxProfile::FlowControlV1,
            Some(StreamCredit { stream: send, conn }),
        );
        let accepted = IncomingStream {
            service,
            stream: Box::new(stream),
        };
        if incoming.try_send(accepted).is_err() {
            self.drop_stream(stream_id);
            return refuse(OpenErrorCode::ResourceExhausted, "not accepting streams now");
        }
        StreamFrame::OpenOk {
            stream_id,
            initial_window: INITIAL_STREAM_WINDOW,
        }
    }

    /// Route one frame. Returns frames to send back to the Target.
    pub async fn handle_frame(&mut self, frame: StreamFrame) -> Result<Vec<StreamFrame>> {
        let mut replies = Vec::new();
        match frame {
            StreamFrame::Data { stream_id, bytes } if self.conn_send.is_some() => {
                let charge = data_charge(bytes.len());
                if let Some(tx) = self.inboxes.get(&stream_id) {
                    match tx.try_send(bytes) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            tracing::warn!(stream_id, "Target overran stream window; resetting");
                            self.drop_stream(stream_id);
                            replies.push(StreamFrame::Reset {
                                stream_id,
                                reason: RESET_FLOW_CONTROL,
                            });
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => self.drop_stream(stream_id),
                    }
                }
                // Connection credit returns once a frame leaves the DataChannel queue;
                // per-stream memory is bounded by the stream window.
                self.conn_recv_pending += charge;
                if self.conn_recv_pending >= CONN_CREDIT_THRESHOLD {
                    replies.push(StreamFrame::WindowUpdate {
                        stream_id: 0,
                        credit: std::mem::take(&mut self.conn_recv_pending),
                    });
                }
            }
            StreamFrame::Data { stream_id, bytes } => {
                // Pre-credit Target: wait for the reader (old behavior).
                if let Some(tx) = self.inboxes.get(&stream_id) {
                    tx.send(bytes).await.map_err(|_| {
                        IdrError::new(IdrErrorKind::TransportClosed, "stream reader gone")
                    })?;
                }
            }
            StreamFrame::HalfClose { stream_id } => {
                self.inboxes.remove(&stream_id);
            }
            StreamFrame::Reset { stream_id, .. } => self.drop_stream(stream_id),
            StreamFrame::WindowUpdate { stream_id: 0, credit } => {
                if let Some(c) = &self.conn_send {
                    c.grant(credit);
                }
            }
            StreamFrame::WindowUpdate { stream_id, credit } => {
                if let Some(c) = self.send_credits.get(&stream_id) {
                    c.grant(credit);
                }
            }
            StreamFrame::HelloAck {
                features,
                conn_window,
                ..
            } => {
                if self.conn_send.is_none() && features.iter().any(|f| f == FEATURE_FLOW_CREDIT) {
                    self.conn_send = Some(SendCredit::new(conn_window));
                }
            }
            StreamFrame::Open { stream_id, meta, .. } => {
                replies.push(self.accept_open(stream_id, meta));
            }
            StreamFrame::OpenOk {
                stream_id,
                initial_window,
            } => {
                if self.conn_send.is_some() {
                    self.send_credits
                        .insert(stream_id, SendCredit::new(initial_window));
                }
                match self.pending_opens.remove(&stream_id) {
                    Some(tx) => {
                        let _ = tx.send(Ok(()));
                    }
                    None => self.emit_control(DemuxEvent::OpenOk {
                        stream_id,
                        initial_window,
                    }),
                }
            }
            StreamFrame::OpenError {
                stream_id,
                code,
                message,
            } => {
                self.inboxes.remove(&stream_id);
                match self.pending_opens.remove(&stream_id) {
                    Some(tx) => {
                        let _ = tx.send(Err(message));
                    }
                    None => self.emit_control(DemuxEvent::OpenError {
                        stream_id,
                        code,
                        message,
                    }),
                }
            }
            StreamFrame::GoAway { last_stream_id, .. } => {
                self.emit_control(DemuxEvent::GoAway { last_stream_id })
            }
            StreamFrame::ServicesCatalog { services } => {
                self.emit_control(DemuxEvent::ServicesCatalog { services })
            }
            StreamFrame::ServicesCatalogDetailed { entries } => {
                self.emit_control(DemuxEvent::ServicesCatalogDetailed { entries })
            }
            StreamFrame::Ping { opaque } => replies.push(StreamFrame::Pong { opaque }),
            StreamFrame::Pong { .. }
            | StreamFrame::Hello { .. }
            | StreamFrame::AuthRefresh { .. }
            | StreamFrame::ServicesCatalogRequest => {}
        }
        Ok(replies)
    }
}
