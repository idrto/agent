//! Receiving side: validate the offer, decide, then verify every entry before it
//! is committed. Every message is checked against the current state.

use idr_protocol::transfer::{
    ControlMsg, DataRecord, EntryKind, Manifest, ResumePoint, StreamHeader, TransferErrorKind,
    MAX_CHUNK_BYTES, MAX_RECORD_BYTES, TRANSFER_VERSION,
};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, watch};

use crate::events::{keeps_data, Command, EventTx, Meter, Outcome, Progress, TransferEvent};
use crate::io::Framed;
use crate::manifest::{validate, OfferSummary};
use crate::router::Router;
use crate::storage::{Consent, OfferInfo, Sink};
use crate::Limits;

use TransferErrorKind::{
    HashMismatch, LimitExceeded, ManifestInvalid, ProtocolViolation, SizeMismatch, Stalled,
    StorageFailed, Timeout, TransportClosed,
};

/// Run one receive attempt for an incoming control stream (from [`Router::route`]).
/// Emits `Finished` with the outcome.
#[allow(clippy::too_many_arguments)]
pub async fn receive<S: Sink, C: Consent>(
    router: &Router,
    header: StreamHeader,
    control: Framed,
    sink: &mut S,
    consent: &mut C,
    limits: &Limits,
    events: EventTx,
    mut cmds: mpsc::Receiver<Command>,
) -> Outcome {
    let mut control = control;
    let outcome = run(
        router,
        &header,
        &mut control,
        sink,
        consent,
        limits,
        &events,
        &mut cmds,
    )
    .await;
    if outcome == Outcome::Cancelled {
        let _ = sink.discard().await;
    }
    consent.finished(&outcome).await;
    tracing::info!(outcome = ?outcome.code(), "transfer receive finished");
    let _ = events.send(TransferEvent::Finished(outcome.clone()));
    let _ = control.stream.half_close().await;
    outcome
}

async fn reject(control: &mut Framed, code: TransferErrorKind) -> Outcome {
    let _ = control.send_control(&ControlMsg::Reject { code }).await;
    Outcome::Rejected(code)
}

async fn step<T>(
    limits: &Limits,
    fut: impl std::future::Future<Output = Result<Option<T>, TransferErrorKind>>,
) -> Result<T, Outcome> {
    match tokio::time::timeout(limits.step_timeout, fut).await {
        Ok(Ok(Some(v))) => Ok(v),
        Ok(Err(ProtocolViolation)) => Err(Outcome::Failed(ProtocolViolation)),
        Ok(Ok(None)) | Ok(Err(_)) => Err(Outcome::Interrupted(TransportClosed)),
        Err(_) => Err(Outcome::Interrupted(Timeout)),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run<S: Sink, C: Consent>(
    router: &Router,
    header: &StreamHeader,
    control: &mut Framed,
    sink: &mut S,
    consent: &mut C,
    limits: &Limits,
    events: &EventTx,
    cmds: &mut mpsc::Receiver<Command>,
) -> Outcome {
    if header.version != TRANSFER_VERSION {
        return reject(control, TransferErrorKind::IncompatibleVersion).await;
    }
    let id = header.transfer_id;

    // Offer, then the whole manifest, checked before anything is shown.
    let (digest, manifest_len, entry_count, resume) = match step(limits, control.next_control())
        .await
    {
        Ok(ControlMsg::Offer {
            digest,
            manifest_len,
            entry_count,
            resume,
        }) => (digest, manifest_len, entry_count, resume),
        Ok(_) => return reject(control, ProtocolViolation).await,
        Err(o) => return o,
    };
    if manifest_len > limits.max_manifest_bytes || entry_count > limits.max_entries {
        return reject(control, LimitExceeded).await;
    }
    let mut encoded = Vec::with_capacity(manifest_len as usize);
    while encoded.len() < manifest_len as usize {
        match step(limits, control.next_control()).await {
            Ok(ControlMsg::ManifestChunk { bytes })
                if encoded.len() + bytes.len() <= manifest_len as usize && !bytes.is_empty() =>
            {
                encoded.extend_from_slice(&bytes)
            }
            Ok(ControlMsg::Cancel { .. }) => return Outcome::Cancelled,
            Ok(_) => return reject(control, ProtocolViolation).await,
            Err(o) => return o,
        }
    }
    if Manifest::digest_of(&encoded) != digest {
        return reject(control, ManifestInvalid).await;
    }
    let manifest: Manifest = match postcard::from_bytes(&encoded) {
        Ok(m) => m,
        Err(_) => return reject(control, ManifestInvalid).await,
    };
    if manifest.entries.len() != entry_count as usize {
        return reject(control, ManifestInvalid).await;
    }
    if let Err(k) = validate(&manifest, limits) {
        return reject(control, k).await;
    }

    let summary = OfferSummary::of(&manifest);
    let _ = events.send(TransferEvent::Offered(summary.clone()));
    let offer = OfferInfo {
        transfer_id: &id,
        digest: &digest,
        summary: &summary,
        resume,
    };
    let approval = match consent.decide(&offer).await {
        Ok(a) => a,
        Err(k) => return reject(control, k).await,
    };
    let points = match sink.prepare(&id, &digest, &manifest).await {
        Ok(p) => p,
        Err(k) => return reject(control, k).await,
    };

    // Data is only accepted once this offer is.
    let mut waiter = router.expect_data(id);
    if control
        .send_control(&ControlMsg::Accept {
            resume: points.clone(),
        })
        .await
        .is_err()
    {
        return Outcome::Interrupted(TransportClosed);
    }
    let _ = events.send(TransferEvent::Accepted {
        approval: Some(approval),
    });
    let mut data = tokio::select! {
        d = tokio::time::timeout(limits.step_timeout, &mut waiter.rx) => match d {
            Ok(Ok(d)) => d,
            _ => return Outcome::Interrupted(Timeout),
        },
        msg = control.next_control() => return match msg {
            Ok(Some(ControlMsg::Cancel { code })) if keeps_data(code) => Outcome::Interrupted(code),
            Ok(Some(ControlMsg::Cancel { .. })) => Outcome::Cancelled,
            Ok(Some(_)) | Err(ProtocolViolation) => violation(control).await,
            _ => Outcome::Interrupted(TransportClosed),
        },
    };

    let mut state = match Entries::load(sink, &manifest, &points).await {
        Ok(s) => s,
        Err(k) => return Outcome::Failed(k),
    };
    let meter = std::sync::Mutex::new(Meter::new(events.clone(), limits, state.progress));
    meter.lock().unwrap().renamed(sink.take_renamed());
    let (ctl_tx, ctl_rx) = watch::channel(false);
    let (results_tx, mut results_rx) = mpsc::channel::<(u32, Option<TransferErrorKind>)>(64);

    let finished = {
        let data_fut = state.receive(&mut data, sink, &manifest, ctl_rx, results_tx, limits, &meter);
        tokio::pin!(data_fut);
        let mut done: Option<Result<u32, TransferErrorKind>> = None;
        let mut cmds_open = true;
        loop {
            if let Some(r) = done {
                // Flush results the data side queued, in order, before Done.
                while let Ok((entry, code)) = results_rx.try_recv() {
                    let _ = control.send_control(&ControlMsg::EntryResult { entry, code }).await;
                }
                break Ok(r);
            }
            tokio::select! {
                r = &mut data_fut => done = Some(r),
                Some((entry, code)) = results_rx.recv() => {
                    if control.send_control(&ControlMsg::EntryResult { entry, code }).await.is_err() {
                        break Err(Outcome::Interrupted(TransportClosed));
                    }
                }
                msg = control.next_control() => match msg {
                    Ok(Some(ControlMsg::Pause)) => {
                        let _ = ctl_tx.send(true);
                        let _ = events.send(TransferEvent::Paused { by_peer: true });
                    }
                    Ok(Some(ControlMsg::Resume)) => {
                        let _ = ctl_tx.send(false);
                        let _ = events.send(TransferEvent::Resumed { by_peer: true });
                    }
                    Ok(Some(ControlMsg::Cancel { code })) if keeps_data(code) => {
                        break Err(Outcome::Interrupted(code))
                    }
                    Ok(Some(ControlMsg::Cancel { .. })) => break Err(Outcome::Cancelled),
                    Ok(Some(_)) | Err(ProtocolViolation) => break Err(violation(control).await),
                    Ok(None) | Err(_) => break Err(Outcome::Interrupted(TransportClosed)),
                },
                cmd = cmds.recv(), if cmds_open => match cmd {
                    Some(Command::Pause) => {
                        let _ = ctl_tx.send(true);
                        let _ = control.send_control(&ControlMsg::Pause).await;
                        let _ = events.send(TransferEvent::Paused { by_peer: false });
                    }
                    Some(Command::Resume) => {
                        let _ = ctl_tx.send(false);
                        let _ = control.send_control(&ControlMsg::Resume).await;
                        let _ = events.send(TransferEvent::Resumed { by_peer: false });
                    }
                    Some(Command::Cancel) => {
                        let _ = control
                            .send_control(&ControlMsg::Cancel { code: TransferErrorKind::Cancelled })
                            .await;
                        break Err(Outcome::Cancelled);
                    }
                    Some(cmd @ (Command::AuthExpired | Command::Revoked)) => {
                        let code = cmd.auth_stop().unwrap();
                        let _ = control.send_control(&ControlMsg::Cancel { code }).await;
                        break Err(Outcome::Interrupted(code));
                    }
                    Some(Command::Supersede) => break Err(Outcome::Interrupted(TransportClosed)),
                    None => cmds_open = false,
                },
            }
        }
    };
    let _ = data.stream.reset(0).await;
    if matches!(finished, Err(Outcome::Interrupted(_)) | Ok(Err(_))) {
        // Make what arrived resumable: checkpoint at the exact current offset.
        state.flush_checkpoints(sink).await;
    }

    let outcome = match finished {
        Err(o) => o,
        Ok(Err(ProtocolViolation)) => violation(control).await,
        // The data stream broke; if the sender cancelled, its Cancel is on the way.
        Ok(Err(Stalled)) => Outcome::Interrupted(Stalled),
        Ok(Err(k)) => match tokio::time::timeout(limits.step_timeout, control.next_control()).await {
            Ok(Ok(Some(ControlMsg::Cancel { .. }))) => Outcome::Cancelled,
            _ => Outcome::Interrupted(k),
        },
        Ok(Ok(0)) => match sink.finish().await {
            Err(k) => {
                let _ = control.send_control(&ControlMsg::Done { code: Some(k) }).await;
                Outcome::Failed(k)
            }
            Ok(()) => {
                let _ = control.send_control(&ControlMsg::Done { code: None }).await;
                Outcome::Completed
            }
        },
        Ok(Ok(failed)) => {
            let code = Some(TransferErrorKind::CompletedWithErrors);
            let _ = control.send_control(&ControlMsg::Done { code }).await;
            Outcome::CompletedWithErrors { failed }
        }
    };
    let mut m = meter.lock().unwrap();
    m.renamed(sink.take_renamed());
    m.tick(true);
    outcome
}

async fn violation(control: &mut Framed) -> Outcome {
    let _ = control
        .send_control(&ControlMsg::Cancel {
            code: ProtocolViolation,
        })
        .await;
    Outcome::Failed(ProtocolViolation)
}

#[derive(Clone)]
enum St {
    /// File in progress (or not started): bytes received so far and their hash.
    Receiving { received: u64, saved: u64, hasher: Sha256 },
    Verified,
    /// Failed this attempt; later records for it are ignored (cut off).
    Failed,
}

struct Entries {
    st: Vec<St>,
    /// Files not yet verified or failed.
    open: u32,
    failed: u32,
    progress: Progress,
}

impl Entries {
    /// Apply resume points; directories are created, partial files re-hashed.
    async fn load<S: Sink>(
        sink: &mut S,
        m: &Manifest,
        points: &[ResumePoint],
    ) -> Result<Self, TransferErrorKind> {
        let fresh = St::Receiving {
            received: 0,
            saved: 0,
            hasher: Sha256::new(),
        };
        let mut s = Self {
            st: vec![fresh; m.entries.len()],
            open: 0,
            failed: 0,
            progress: Progress::default(),
        };
        for p in points {
            let i = p.entry as usize;
            if p.complete {
                s.st[i] = St::Verified;
            } else {
                let mut hasher = Sha256::new();
                let mut buf = vec![0u8; MAX_CHUNK_BYTES];
                let mut at = 0;
                while at < p.verified {
                    let n = sink.read_partial(p.entry, at, &mut buf).await?;
                    if n == 0 {
                        return Err(StorageFailed);
                    }
                    let n = n.min((p.verified - at) as usize);
                    hasher.update(&buf[..n]);
                    at += n as u64;
                }
                s.st[i] = St::Receiving {
                    received: p.verified,
                    saved: p.verified,
                    hasher,
                };
            }
        }
        for e in &m.entries {
            let i = e.id as usize;
            match (e.kind, &s.st[i]) {
                (EntryKind::Dir, St::Verified) => {}
                (EntryKind::Dir, _) => {
                    s.st[i] = match sink.create_dir(e.id).await {
                        Ok(()) => St::Verified,
                        Err(_) => {
                            s.failed += 1;
                            St::Failed
                        }
                    }
                }
                (EntryKind::File, st) => {
                    s.progress.files_total += 1;
                    s.progress.bytes_total += e.size;
                    match st {
                        St::Verified => {
                            s.progress.files_done += 1;
                            s.progress.bytes_done += e.size;
                        }
                        St::Receiving { received, .. } => {
                            s.open += 1;
                            s.progress.bytes_done += received;
                        }
                        St::Failed => {}
                    }
                }
            }
        }
        Ok(s)
    }

    /// Read the data stream until every file is resolved. Returns the failed count.
    /// `Err(ProtocolViolation)` fails the transfer; other errors interrupt it.
    #[allow(clippy::too_many_arguments)]
    async fn receive<S: Sink>(
        &mut self,
        data: &mut Framed,
        sink: &mut S,
        m: &Manifest,
        mut paused: watch::Receiver<bool>,
        results: mpsc::Sender<(u32, Option<TransferErrorKind>)>,
        limits: &Limits,
        meter: &std::sync::Mutex<Meter>,
    ) -> Result<u32, TransferErrorKind> {
        while self.open > 0 {
            let next = data.next::<DataRecord>(MAX_RECORD_BYTES);
            let rec = if *paused.borrow_and_update() {
                next.await
            } else {
                tokio::time::timeout(limits.stall_timeout, next)
                    .await
                    .map_err(|_| Stalled)?
            };
            let rec = rec?.ok_or(TransportClosed)?;
            let (entry, outcome) = match rec {
                DataRecord::Chunk {
                    entry,
                    offset,
                    bytes,
                } => {
                    let e = self.file(m, entry)?;
                    if bytes.len() > MAX_CHUNK_BYTES || bytes.is_empty() {
                        return Err(ProtocolViolation);
                    }
                    let St::Receiving { received, saved, hasher } = &mut self.st[entry as usize] else {
                        if matches!(self.st[entry as usize], St::Failed) {
                            continue;
                        }
                        // Data for a verified entry.
                        return Err(ProtocolViolation);
                    };
                    if offset != *received {
                        return Err(ProtocolViolation);
                    }
                    if *received + bytes.len() as u64 > e.size {
                        (entry, Some(SizeMismatch))
                    } else if let Err(k) = sink.write(entry, offset, &bytes).await {
                        (entry, Some(k))
                    } else {
                        hasher.update(&bytes);
                        let before = *received;
                        *received += bytes.len() as u64;
                        if before / limits.checkpoint_bytes != *received / limits.checkpoint_bytes {
                            if let Err(k) = sink.checkpoint(entry, *received).await {
                                self.fail(sink, entry, k, &results, meter).await;
                                continue;
                            }
                            *saved = *received;
                        }
                        let mut mt = meter.lock().unwrap();
                        mt.p.bytes_done += bytes.len() as u64;
                        mt.tick(false);
                        continue;
                    }
                }
                DataRecord::EntryEnd {
                    entry,
                    size,
                    sha256,
                } => {
                    let e = self.file(m, entry)?;
                    match &self.st[entry as usize] {
                        St::Failed => continue,
                        St::Verified => return Err(ProtocolViolation),
                        St::Receiving { received, hasher, .. } => {
                            if size != e.size || *received != size {
                                (entry, Some(SizeMismatch))
                            } else if <[u8; 32]>::from(hasher.clone().finalize()) != sha256 {
                                (entry, Some(HashMismatch))
                            } else if let Err(k) = sink.commit(entry).await {
                                (entry, Some(k))
                            } else {
                                (entry, None)
                            }
                        }
                    }
                }
                DataRecord::EntryAbort { entry, code } => {
                    self.file(m, entry)?;
                    match self.st[entry as usize] {
                        St::Receiving { .. } => (entry, Some(code)),
                        _ => continue,
                    }
                }
            };
            match outcome {
                None => {
                    self.st[entry as usize] = St::Verified;
                    self.open -= 1;
                    {
                        let mut mt = meter.lock().unwrap();
                        mt.p.files_done += 1;
                        mt.tick(false);
                    }
                    let _ = results.send((entry, None)).await;
                }
                Some(k) => self.fail(sink, entry, k, &results, meter).await,
            }
        }
        Ok(self.failed)
    }

    async fn flush_checkpoints<S: Sink>(&mut self, sink: &mut S) {
        for (i, st) in self.st.iter_mut().enumerate() {
            if let St::Receiving { received, saved, .. } = st {
                if *received > *saved && sink.checkpoint(i as u32, *received).await.is_ok() {
                    *saved = *received;
                }
            }
        }
    }

    fn file<'m>(
        &self,
        m: &'m Manifest,
        entry: u32,
    ) -> Result<&'m idr_protocol::transfer::ManifestEntry, TransferErrorKind> {
        match m.entries.get(entry as usize) {
            Some(e) if e.kind == EntryKind::File => Ok(e),
            _ => Err(ProtocolViolation),
        }
    }

    async fn fail<S: Sink>(
        &mut self,
        sink: &mut S,
        entry: u32,
        code: TransferErrorKind,
        results: &mpsc::Sender<(u32, Option<TransferErrorKind>)>,
        meter: &std::sync::Mutex<Meter>,
    ) {
        let _ = sink.fail(entry).await;
        self.st[entry as usize] = St::Failed;
        self.open -= 1;
        self.failed += 1;
        meter.lock().unwrap().entry_failed(entry, code);
        let _ = results.send((entry, Some(code))).await;
    }
}
