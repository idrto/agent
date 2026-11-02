//! Shared mock-peer harness: in-memory streams with injectable disconnects
//! and corruption, a receiver task, and a one-call transfer runner.
#![allow(dead_code)]

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use idr_core::{IdrError, IdrErrorKind, LogicalStream, StreamId};
use idr_protocol::transfer::{new_transfer_id, Manifest, TransferErrorKind as K, TransferId};
use idr_transfer::storage::{Approval, Consent, OfferInfo, Sink, SourceFiles, StreamOpener};
use idr_transfer::{receive, send, Command, Limits, Outcome, Outgoing, Routed, Router, TransferEvent};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::timeout;

// ---- Mock transport -------------------------------------------------------

pub type Hook = Arc<dyn Fn(&mut Vec<u8>) + Send + Sync>;

pub struct MemStream {
    pub io: DuplexStream,
    pub cut: watch::Receiver<bool>,
    pub hook: Option<Hook>,
}

pub fn closed() -> IdrError {
    IdrError::new(IdrErrorKind::TransportClosed, "link cut")
}

#[async_trait]
impl LogicalStream for MemStream {
    fn id(&self) -> StreamId {
        StreamId(1)
    }
    async fn write(&mut self, buf: &[u8]) -> idr_core::Result<usize> {
        if *self.cut.borrow() {
            return Err(closed());
        }
        let mut bytes = buf.to_vec();
        if let Some(h) = &self.hook {
            h(&mut bytes);
        }
        tokio::select! {
            r = self.io.write_all(&bytes) => r.map_err(|_| closed())?,
            _ = self.cut.wait_for(|c| *c) => return Err(closed()),
        }
        Ok(buf.len())
    }
    async fn read(&mut self, buf: &mut [u8]) -> idr_core::Result<usize> {
        if *self.cut.borrow() {
            return Err(closed());
        }
        tokio::select! {
            r = self.io.read(buf) => r.map_err(|_| closed()),
            _ = self.cut.wait_for(|c| *c) => Err(closed()),
        }
    }
    async fn half_close(&mut self) -> idr_core::Result<()> {
        let _ = self.io.shutdown().await;
        Ok(())
    }
    async fn reset(&mut self, _: u16) -> idr_core::Result<()> {
        let _ = self.io.shutdown().await;
        Ok(())
    }
}

/// One "session": the sender opens streams, the receiver side gets their far ends.
pub struct Link {
    pub incoming: mpsc::UnboundedSender<Box<dyn LogicalStream>>,
    pub cut: watch::Receiver<bool>,
    /// Applied to writes on the sender's data stream (second stream opened).
    pub data_hook: Option<Hook>,
    pub opened: u32,
}

#[async_trait]
impl StreamOpener for Link {
    async fn open(&mut self) -> idr_core::Result<Box<dyn LogicalStream>> {
        let (a, b) = tokio::io::duplex(64 * 1024);
        self.opened += 1;
        let hook = if self.opened == 2 { self.data_hook.clone() } else { None };
        self.incoming
            .send(Box::new(MemStream {
                io: b,
                cut: self.cut.clone(),
                hook: None,
            }))
            .map_err(|_| closed())?;
        Ok(Box::new(MemStream {
            io: a,
            cut: self.cut.clone(),
            hook,
        }))
    }
}

/// Counts how often consent was asked.
pub struct Counting(pub Arc<AtomicU32>, pub Approval);

#[async_trait]
impl Consent for Counting {
    async fn decide(&mut self, _: &OfferInfo<'_>) -> Result<Approval, K> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(self.1)
    }
}

pub struct Run {
    pub sender: Outcome,
    pub receiver: Outcome,
    pub rx_events: Vec<TransferEvent>,
    pub tx_events: Vec<TransferEvent>,
}

#[derive(Default)]
pub struct Opts {
    pub resume: bool,
    pub data_hook: Option<Hook>,
    /// Cut the link once this many data-stream bytes were written.
    pub cut_after: Option<u64>,
    pub sender_cmds: Vec<(Duration, Command)>,
    pub receiver_cmds: Vec<(Duration, Command)>,
    pub id: Option<TransferId>,
}

pub fn limits() -> Limits {
    Limits {
        checkpoint_bytes: 64 * 1024,
        step_timeout: Duration::from_secs(5),
        stall_timeout: Duration::from_secs(5),
        ..Limits::default()
    }
}

/// Spawn the receiving side: routes streams and runs `receive` for the control stream.
pub fn spawn_receiver<S: Sink + 'static, C: Consent + 'static>(
    mut incoming: mpsc::UnboundedReceiver<Box<dyn LogicalStream>>,
    sink: S,
    mut consent: C,
    limits: Limits,
    cmds: mpsc::Receiver<Command>,
) -> (oneshot::Receiver<(Outcome, Vec<TransferEvent>)>, Router) {
    let router = Router::default();
    let (done_tx, done_rx) = oneshot::channel();
    let r = router.clone();
    tokio::spawn(async move {
        let mut cmds = Some(cmds);
        let mut done_tx = Some(done_tx);
        let mut sink = Some(sink);
        while let Some(stream) = incoming.recv().await {
            if let Routed::Control { header, stream } = r.route(stream, Duration::from_secs(2)).await {
                let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
                let router = r.clone();
                let limits = limits.clone();
                let cmds = cmds.take().unwrap();
                let done = done_tx.take().unwrap();
                let mut sink2 = sink.take().unwrap();
                tokio::spawn(async move {
                    let o = receive(
                        &router, header, stream, &mut sink2, &mut consent, &limits, ev_tx, cmds,
                    )
                    .await;
                    let mut evs = Vec::new();
                    while let Ok(e) = ev_rx.try_recv() {
                        evs.push(e);
                    }
                    let _ = done.send((o, evs));
                });
                // Only one transfer per link in these tests.
                let r2 = r.clone();
                tokio::spawn(async move {
                    while let Some(s) = incoming.recv().await {
                        r2.route(s, Duration::from_secs(2)).await;
                    }
                });
                return;
            }
        }
    });
    (done_rx, router)
}

pub async fn run_with<F: SourceFiles, S: Sink + 'static, C: Consent + 'static>(
    manifest: Manifest,
    files: F,
    sink: S,
    consent: C,
    opts: Opts,
) -> Run {
    let (in_tx, in_rx) = mpsc::unbounded_channel();
    let (cut_tx, cut_rx) = watch::channel(false);
    let cut_tx = Arc::new(cut_tx);
    let written = Arc::new(AtomicU64::new(0));
    let user_hook = opts.data_hook.clone();
    let cut_after = opts.cut_after;
    let (w, c) = (written.clone(), cut_tx.clone());
    let hook: Hook = Arc::new(move |bytes: &mut Vec<u8>| {
        if let Some(h) = &user_hook {
            h(bytes);
        }
        let total = w.fetch_add(bytes.len() as u64, Ordering::SeqCst) + bytes.len() as u64;
        if cut_after.is_some_and(|n| total >= n) {
            let _ = c.send(true);
        }
    });
    let mut link = Link {
        incoming: in_tx,
        cut: cut_rx,
        data_hook: Some(hook),
        opened: 0,
    };
    let (rcmd_tx, rcmd_rx) = mpsc::channel(8);
    let (done_rx, _router) = spawn_receiver(in_rx, sink, consent, limits(), rcmd_rx);
    for (after, cmd) in opts.receiver_cmds {
        let tx = rcmd_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(after).await;
            let _ = tx.send(cmd).await;
        });
    }
    let (scmd_tx, scmd_rx) = mpsc::channel(8);
    for (after, cmd) in opts.sender_cmds {
        let tx = scmd_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(after).await;
            let _ = tx.send(cmd).await;
        });
    }
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
    let req = Outgoing {
        transfer_id: opts.id.unwrap_or_else(new_transfer_id),
        manifest,
        files,
        resume: opts.resume,
    };
    let sender = timeout(Duration::from_secs(60), send(&mut link, req, &limits(), ev_tx, scmd_rx))
        .await
        .expect("sender hung");
    let (receiver, rx_events) = timeout(Duration::from_secs(60), done_rx)
        .await
        .expect("receiver hung")
        .expect("receiver task died");
    let mut tx_events = Vec::new();
    while let Ok(e) = ev_rx.try_recv() {
        tx_events.push(e);
    }
    drop(scmd_tx);
    Run {
        sender,
        receiver,
        rx_events,
        tx_events,
    }
}

