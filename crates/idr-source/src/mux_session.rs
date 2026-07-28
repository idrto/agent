//! Multiplexed logical stream over a shared DataChannel sender/receiver.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use idr_core::error::{IdrError, IdrErrorKind, Result};
use idr_core::flow::FlowController;
use idr_core::stream::{LogicalStream, StreamId};
use idr_protocol::stream_mux::{MuxProfile, StreamFrame, INITIAL_STREAM_WINDOW};
use tokio::sync::{mpsc, Mutex};

type SharedPeer = Arc<Mutex<Box<dyn idr_webrtc::PeerTransport>>>;

pub struct MuxLogicalStream {
    id: StreamId,
    peer: SharedPeer,
    inbound: mpsc::Receiver<Vec<u8>>,
    half_closed: bool,
    flow: FlowController,
    profile: MuxProfile,
}

impl MuxLogicalStream {
    pub fn new(
        id: StreamId,
        peer: SharedPeer,
        inbound: mpsc::Receiver<Vec<u8>>,
        profile: MuxProfile,
        initial_peer_window: u32,
    ) -> Self {
        let mut flow = FlowController::default();
        flow.set_peer_initial_window(initial_peer_window, None);
        Self {
            id,
            peer,
            inbound,
            half_closed: false,
            flow,
            profile,
        }
    }

    pub fn credit_window(&mut self, credit: u32) {
        self.flow.credit_send_stream(credit);
    }
}

#[async_trait]
impl LogicalStream for MuxLogicalStream {
    fn id(&self) -> StreamId {
        self.id
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if self.half_closed {
            return Err(IdrError::new(
                IdrErrorKind::TransportClosed,
                "stream half-closed",
            ));
        }
        let n = buf.len() as u32;
        if self.profile == MuxProfile::FlowControlV1 {
            self.flow.consume_send(n)?;
        }
        let frame = StreamFrame::Data {
            stream_id: self.id.0,
            bytes: buf.to_vec(),
        };
        let enc = frame.encode()?;
        let mut peer = self.peer.lock().await;
        peer.send_binary(&enc)?;
        Ok(buf.len())
    }

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self.inbound.recv().await {
            Some(bytes) if bytes.is_empty() => Ok(0),
            Some(bytes) => {
                if self.profile == MuxProfile::FlowControlV1 {
                    if let Some(credit) = self.flow.on_recv_data(bytes.len() as u32) {
                        let frame = StreamFrame::WindowUpdate {
                            stream_id: self.id.0,
                            credit,
                        };
                        let enc = frame.encode()?;
                        let mut peer = self.peer.lock().await;
                        let _ = peer.send_binary(&enc);
                    }
                }
                let n = bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                Ok(n)
            }
            None => Ok(0),
        }
    }

    async fn half_close(&mut self) -> Result<()> {
        if self.half_closed {
            return Ok(());
        }
        self.half_closed = true;
        let frame = StreamFrame::HalfClose {
            stream_id: self.id.0,
        };
        let enc = frame.encode()?;
        let mut peer = self.peer.lock().await;
        peer.send_binary(&enc)?;
        Ok(())
    }

    async fn reset(&mut self, reason: u16) -> Result<()> {
        let frame = StreamFrame::Reset {
            stream_id: self.id.0,
            reason,
        };
        let enc = frame.encode()?;
        let mut peer = self.peer.lock().await;
        peer.send_binary(&enc)?;
        Ok(())
    }
}

/// Control / data events demuxed from the DataChannel.
#[derive(Debug, Clone)]
pub enum DemuxEvent {
    Data { stream_id: u32, bytes: Vec<u8> },
    OpenOk { stream_id: u32, initial_window: u32 },
    OpenError { stream_id: u32, code: u16, message: String },
    WindowUpdate { stream_id: u32, credit: u32 },
    HalfClose { stream_id: u32 },
    Reset { stream_id: u32 },
    Pong { opaque: u64 },
    GoAway { last_stream_id: u32 },
    HelloAck { features: Vec<String>, conn_window: u32 },
}

/// Demux DataChannel binary frames into per-stream inboxes and control waiters.
pub struct StreamDemux {
    pub inboxes: HashMap<u32, mpsc::Sender<Vec<u8>>>,
    pub control_tx: Option<mpsc::Sender<DemuxEvent>>,
    outbound_cap: usize,
}

impl StreamDemux {
    pub fn new(outbound_cap: usize) -> Self {
        Self {
            inboxes: HashMap::new(),
            control_tx: None,
            outbound_cap,
        }
    }

    pub fn with_control(outbound_cap: usize, control_tx: mpsc::Sender<DemuxEvent>) -> Self {
        Self {
            inboxes: HashMap::new(),
            control_tx: Some(control_tx),
            outbound_cap,
        }
    }

    pub fn register(&mut self, stream_id: u32) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel(self.outbound_cap.max(1));
        self.inboxes.insert(stream_id, tx);
        rx
    }

    async fn emit_control(&self, ev: DemuxEvent) {
        if let Some(tx) = &self.control_tx {
            let _ = tx.send(ev).await;
        }
    }

    pub async fn handle_frame(&mut self, frame: StreamFrame) -> Result<()> {
        match frame {
            StreamFrame::Data { stream_id, bytes } => {
                if let Some(tx) = self.inboxes.get(&stream_id) {
                    tx.send(bytes).await.map_err(|_| {
                        IdrError::new(IdrErrorKind::TransportClosed, "stream reader gone")
                    })?;
                }
            }
            StreamFrame::HalfClose { stream_id } => {
                self.emit_control(DemuxEvent::HalfClose { stream_id }).await;
                if let Some(tx) = self.inboxes.remove(&stream_id) {
                    let _ = tx.send(Vec::new()).await;
                }
            }
            StreamFrame::Reset { stream_id, .. } => {
                self.emit_control(DemuxEvent::Reset { stream_id }).await;
                if let Some(tx) = self.inboxes.remove(&stream_id) {
                    let _ = tx.send(Vec::new()).await;
                }
            }
            StreamFrame::OpenOk {
                stream_id,
                initial_window,
            } => {
                self.emit_control(DemuxEvent::OpenOk {
                    stream_id,
                    initial_window,
                })
                .await;
            }
            StreamFrame::OpenError {
                stream_id,
                code,
                message,
            } => {
                self.emit_control(DemuxEvent::OpenError {
                    stream_id,
                    code,
                    message,
                })
                .await;
            }
            StreamFrame::WindowUpdate { stream_id, credit } => {
                self.emit_control(DemuxEvent::WindowUpdate { stream_id, credit })
                    .await;
            }
            StreamFrame::Pong { opaque } => {
                self.emit_control(DemuxEvent::Pong { opaque }).await;
            }
            StreamFrame::GoAway { last_stream_id, .. } => {
                self.emit_control(DemuxEvent::GoAway { last_stream_id })
                    .await;
            }
            StreamFrame::HelloAck {
                features,
                conn_window,
                ..
            } => {
                self.emit_control(DemuxEvent::HelloAck {
                    features,
                    conn_window,
                })
                .await;
            }
            StreamFrame::Open { .. }
            | StreamFrame::Ping { .. }
            | StreamFrame::Hello { .. }
            | StreamFrame::AuthRefresh { .. } => {
                // Source ignores inbound Open (Target-initiated reserved) and locally handled pings.
            }
        }
        Ok(())
    }
}

/// Allocate odd stream ids for Source-initiated streams.
pub struct StreamIdAllocator {
    next_odd: u32,
}

impl Default for StreamIdAllocator {
    fn default() -> Self {
        Self { next_odd: 1 }
    }
}

impl StreamIdAllocator {
    pub fn next(&mut self) -> StreamId {
        let id = StreamId(self.next_odd);
        self.next_odd = self.next_odd.saturating_add(2);
        id
    }
}

/// Wait for OpenOk / OpenError on the control channel, or time out → legacy.
pub async fn wait_open_result(
    control_rx: &mut mpsc::Receiver<DemuxEvent>,
    stream_id: u32,
    timeout: Duration,
) -> Result<(MuxProfile, u32)> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return Ok((MuxProfile::Legacy, INITIAL_STREAM_WINDOW));
        }
        match tokio::time::timeout(left, control_rx.recv()).await {
            Ok(Some(DemuxEvent::OpenOk {
                stream_id: sid,
                initial_window,
            })) if sid == stream_id => {
                return Ok((MuxProfile::FlowControlV1, initial_window));
            }
            Ok(Some(DemuxEvent::OpenError {
                stream_id: sid,
                message,
                ..
            })) if sid == stream_id => {
                return Err(IdrError::new(IdrErrorKind::ConnectionRefused, message));
            }
            Ok(Some(_)) => continue,
            Ok(None) => {
                return Err(IdrError::new(
                    IdrErrorKind::TransportClosed,
                    "control channel closed",
                ));
            }
            Err(_) => return Ok((MuxProfile::Legacy, INITIAL_STREAM_WINDOW)),
        }
    }
}
