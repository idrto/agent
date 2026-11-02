//! Sending side: offer, wait for the decision, stream entries, collect results.

use std::sync::{Arc, Mutex};

use idr_protocol::transfer::{
    ControlMsg, DataRecord, EntryKind, Manifest, StreamHeader, StreamRole, TransferErrorKind,
    TransferId, MANIFEST_CHUNK_BYTES, MAX_CHUNK_BYTES, STREAM_MAGIC, TRANSFER_VERSION,
};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, watch};

use crate::events::{keeps_data, Command, EventTx, Meter, Outcome, Progress, TransferEvent};
use crate::io::Framed;
use crate::storage::{SourceFiles, StreamOpener};
use crate::Limits;

use TransferErrorKind::{ProtocolViolation, Stalled, Timeout, TransportClosed};

pub struct Outgoing<F> {
    pub transfer_id: TransferId,
    pub manifest: Manifest,
    pub files: F,
    /// Continue an earlier attempt of this transfer id (same manifest).
    pub resume: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct Ctl {
    paused: bool,
}

async fn open(
    opener: &mut (impl StreamOpener + ?Sized),
    id: TransferId,
    role: StreamRole,
) -> Result<Framed, TransferErrorKind> {
    let stream = opener.open().await.map_err(|_| TransportClosed)?;
    let mut framed = Framed::new(stream);
    framed
        .send(&StreamHeader {
            magic: STREAM_MAGIC,
            version: TRANSFER_VERSION,
            transfer_id: id,
            role,
        })
        .await?;
    Ok(framed)
}

/// Run one send attempt to completion. Emits `Finished` with the outcome.
pub async fn send<O: StreamOpener + ?Sized, F: SourceFiles>(
    opener: &mut O,
    req: Outgoing<F>,
    limits: &Limits,
    events: EventTx,
    mut cmds: mpsc::Receiver<Command>,
) -> Outcome {
    let outcome = run(opener, req, limits, &events, &mut cmds).await;
    tracing::info!(outcome = ?outcome.code(), "transfer send finished");
    let _ = events.send(TransferEvent::Finished(outcome.clone()));
    outcome
}

async fn run<O: StreamOpener + ?Sized, F: SourceFiles>(
    opener: &mut O,
    mut req: Outgoing<F>,
    limits: &Limits,
    events: &EventTx,
    cmds: &mut mpsc::Receiver<Command>,
) -> Outcome {
    let id = req.transfer_id;
    let encoded = req.manifest.encode();
    let mut control = match open(opener, id, StreamRole::Control).await {
        Ok(c) => c,
        Err(k) => return Outcome::Interrupted(k),
    };
    let offer = ControlMsg::Offer {
        digest: Manifest::digest_of(&encoded),
        manifest_len: encoded.len() as u32,
        entry_count: req.manifest.entries.len() as u32,
        resume: req.resume,
    };
    if control.send_control(&offer).await.is_err() {
        return Outcome::Interrupted(TransportClosed);
    }
    for piece in encoded.chunks(MANIFEST_CHUNK_BYTES) {
        let chunk = ControlMsg::ManifestChunk {
            bytes: piece.to_vec(),
        };
        if control.send_control(&chunk).await.is_err() {
            return Outcome::Interrupted(TransportClosed);
        }
    }

    // Decision.
    let deadline = tokio::time::Instant::now() + limits.offer_timeout;
    let resume = loop {
        tokio::select! {
            msg = tokio::time::timeout_at(deadline, control.next_control()) => match msg {
                Ok(Ok(Some(ControlMsg::Accept { resume }))) => break resume,
                Ok(Ok(Some(ControlMsg::Reject { code }))) => return Outcome::Rejected(code),
                Ok(Ok(Some(ControlMsg::Cancel { code }))) if keeps_data(code) => {
                    return Outcome::Interrupted(code);
                }
                Ok(Ok(Some(ControlMsg::Cancel { .. }))) => return Outcome::Cancelled,
                Ok(Ok(Some(_))) | Ok(Err(ProtocolViolation)) => {
                    return violation(&mut control).await;
                }
                Ok(Ok(None)) | Ok(Err(_)) => return Outcome::Interrupted(TransportClosed),
                Err(_) => return Outcome::Interrupted(Timeout),
            },
            Some(cmd) = cmds.recv() => {
                if let Some(code) = cmd.auth_stop() {
                    let _ = control.send_control(&ControlMsg::Cancel { code }).await;
                    return Outcome::Interrupted(code);
                }
                if cmd == Command::Cancel {
                    let _ = control.send_control(&ControlMsg::Cancel { code: TransferErrorKind::Cancelled }).await;
                    return Outcome::Cancelled;
                }
            },
        }
    };

    // Where each file starts; None = already complete.
    let entries = &req.manifest.entries;
    let mut starts: Vec<Option<u64>> = entries
        .iter()
        .map(|e| (e.kind == EntryKind::File).then_some(0))
        .collect();
    let mut progress = Progress::default();
    for e in entries.iter().filter(|e| e.kind == EntryKind::File) {
        progress.files_total += 1;
        progress.bytes_total += e.size;
    }
    for p in &resume {
        let Some(e) = entries.get(p.entry as usize) else {
            return violation(&mut control).await;
        };
        if e.kind != EntryKind::File || p.verified > e.size {
            return violation(&mut control).await;
        }
        if p.complete {
            starts[p.entry as usize] = None;
            progress.files_done += 1;
            progress.bytes_done += e.size;
        } else {
            starts[p.entry as usize] = Some(p.verified);
            progress.bytes_done += p.verified;
        }
    }
    let files_to_send = starts.iter().filter(|s| s.is_some()).count() as u32;
    let _ = events.send(TransferEvent::Accepted { approval: None });
    // Where this attempt starts (the receiver's verified data), before any byte moves.
    let _ = events.send(TransferEvent::Progress(progress));

    let mut data = match open(opener, id, StreamRole::Data).await {
        Ok(d) => d,
        Err(k) => return Outcome::Interrupted(k),
    };
    let meter = Arc::new(Mutex::new(Meter::new(events.clone(), limits, progress)));
    let (ctl_tx, ctl_rx) = watch::channel(Ctl::default());
    let (acked_tx, acked_rx) = watch::channel(0u32);

    let outcome = {
        let data_fut = stream_entries(
            &mut data,
            &mut req.files,
            &req.manifest,
            &starts,
            ctl_rx,
            acked_rx,
            limits,
            meter.clone(),
        );
        tokio::pin!(data_fut);
        let mut data_done = false;
        // A data-stream failure may just be the receiver cancelling: give its
        // control message a moment before calling the transfer interrupted.
        let mut data_err: Option<TransferErrorKind> = None;
        let mut acked = 0u32;
        let mut failed = 0u32;
        let mut seen = std::collections::HashSet::new();
        let mut cmds_open = true;
        let stall = tokio::time::sleep(limits.stall_timeout);
        tokio::pin!(stall);
        loop {
            tokio::select! {
                r = &mut data_fut, if !data_done => match r {
                    Ok(()) => {
                        data_done = true;
                        stall.as_mut().reset(tokio::time::Instant::now() + limits.stall_timeout);
                    }
                    Err(k) => {
                        data_done = true;
                        data_err = Some(k);
                        stall.as_mut().reset(tokio::time::Instant::now() + limits.step_timeout);
                    }
                },
                // Every entry is sent; the receiver owes results and `Done`.
                _ = &mut stall, if data_done => break Outcome::Interrupted(data_err.unwrap_or(Stalled)),
                msg = control.next_control() => match msg {
                    Ok(Some(ControlMsg::EntryResult { entry, code })) => {
                        if (entry as usize) >= entries.len() || starts[entry as usize].is_none() {
                            break violation(&mut control).await;
                        }
                        if seen.insert(entry) {
                            acked += 1;
                            let _ = acked_tx.send(acked);
                            let mut m = meter.lock().unwrap();
                            match code {
                                None => m.p.files_done += 1,
                                Some(k) => {
                                    failed += 1;
                                    m.entry_failed(entry, k);
                                }
                            }
                            m.tick(false);
                        }
                        if data_done && data_err.is_none() {
                            stall.as_mut().reset(tokio::time::Instant::now() + limits.stall_timeout);
                        }
                    }
                    Ok(Some(ControlMsg::Pause)) => {
                        ctl_tx.send_modify(|c| c.paused = true);
                        let _ = events.send(TransferEvent::Paused { by_peer: true });
                    }
                    Ok(Some(ControlMsg::Resume)) => {
                        ctl_tx.send_modify(|c| c.paused = false);
                        let _ = events.send(TransferEvent::Resumed { by_peer: true });
                    }
                    Ok(Some(ControlMsg::Cancel { code })) if keeps_data(code) => {
                        break Outcome::Interrupted(code)
                    }
                    Ok(Some(ControlMsg::Cancel { .. })) => break Outcome::Cancelled,
                    Ok(Some(ControlMsg::Done { code })) => {
                        break match code {
                            None if acked == files_to_send && failed == 0 => Outcome::Completed,
                            Some(TransferErrorKind::CompletedWithErrors) => {
                                Outcome::CompletedWithErrors { failed }
                            }
                            None => violation(&mut control).await,
                            Some(k) => Outcome::Failed(k),
                        };
                    }
                    // Duplicate decision: idempotent.
                    Ok(Some(ControlMsg::Accept { .. })) => {}
                    Ok(Some(_)) | Err(ProtocolViolation) => break violation(&mut control).await,
                    Ok(None) | Err(_) => {
                        break Outcome::Interrupted(data_err.unwrap_or(TransportClosed))
                    }
                },
                cmd = cmds.recv(), if cmds_open => match cmd {
                    Some(Command::Pause) => {
                        ctl_tx.send_modify(|c| c.paused = true);
                        let _ = control.send_control(&ControlMsg::Pause).await;
                        let _ = events.send(TransferEvent::Paused { by_peer: false });
                    }
                    Some(Command::Resume) => {
                        ctl_tx.send_modify(|c| c.paused = false);
                        let _ = control.send_control(&ControlMsg::Resume).await;
                        let _ = events.send(TransferEvent::Resumed { by_peer: false });
                    }
                    Some(Command::Cancel) => {
                        let _ = control
                            .send_control(&ControlMsg::Cancel { code: TransferErrorKind::Cancelled })
                            .await;
                        break Outcome::Cancelled;
                    }
                    Some(cmd @ (Command::AuthExpired | Command::Revoked)) => {
                        let code = cmd.auth_stop().unwrap();
                        let _ = control.send_control(&ControlMsg::Cancel { code }).await;
                        break Outcome::Interrupted(code);
                    }
                    Some(Command::Supersede) => break Outcome::Interrupted(TransportClosed),
                    None => cmds_open = false,
                },
            }
        }
    };
    meter.lock().unwrap().tick(true);
    if outcome == Outcome::Completed {
        let _ = data.stream.half_close().await;
    } else {
        let _ = data.stream.reset(0).await;
    }
    let _ = control.stream.half_close().await;
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

#[allow(clippy::too_many_arguments)]
async fn stream_entries<F: SourceFiles>(
    data: &mut Framed,
    files: &mut F,
    manifest: &Manifest,
    starts: &[Option<u64>],
    mut ctl: watch::Receiver<Ctl>,
    mut acked: watch::Receiver<u32>,
    limits: &Limits,
    meter: Arc<Mutex<Meter>>,
) -> Result<(), TransferErrorKind> {
    let mut sent_files = 0u32;
    let mut buf = vec![0u8; MAX_CHUNK_BYTES];
    for e in &manifest.entries {
        let Some(start) = starts[e.id as usize] else {
            continue;
        };
        // Small files pipeline; results must keep up.
        let max = limits.max_pipelined_files as u32;
        let _ = acked.wait_for(|a| sent_files - a < max).await;
        let _ = ctl.wait_for(|c| !c.paused).await;

        let end = match send_file(data, files, e, start, &mut buf, &mut ctl, &meter).await? {
            Ok((size, sha256)) => DataRecord::EntryEnd {
                entry: e.id,
                size,
                sha256,
            },
            Err(code) => DataRecord::EntryAbort { entry: e.id, code },
        };
        data.send(&end).await?;
        sent_files += 1;
    }
    let _ = data.stream.half_close().await;
    Ok(())
}

/// Outer error: the stream failed. Inner error: only this entry failed.
async fn send_file<F: SourceFiles>(
    data: &mut Framed,
    files: &mut F,
    e: &idr_protocol::transfer::ManifestEntry,
    start: u64,
    buf: &mut [u8],
    ctl: &mut watch::Receiver<Ctl>,
    meter: &Arc<Mutex<Meter>>,
) -> Result<Result<(u64, [u8; 32]), TransferErrorKind>, TransferErrorKind> {
    use TransferErrorKind::{ChangedDuringTransfer, SourceReadFailed};
    let mut reader = match files.open(e).await {
        Ok(r) => r,
        Err(k) => return Ok(Err(k)),
    };
    let mut hasher = Sha256::new();
    let mut pos = 0u64;
    loop {
        let n = match reader.read(buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return Ok(Err(SourceReadFailed)),
        };
        if pos + n as u64 > e.size {
            return Ok(Err(ChangedDuringTransfer));
        }
        hasher.update(&buf[..n]);
        // Bytes before `start` are only hashed: the receiver already holds them.
        if pos + n as u64 > start {
            let from = start.saturating_sub(pos) as usize;
            data.send(&DataRecord::Chunk {
                entry: e.id,
                offset: pos + from as u64,
                bytes: buf[from..n].to_vec(),
            })
            .await?;
            let mut m = meter.lock().unwrap();
            m.p.bytes_done += (n - from) as u64;
            m.tick(false);
        }
        pos += n as u64;
        let _ = ctl.wait_for(|c| !c.paused).await;
    }
    if pos != e.size || reader.verify_unchanged().await.is_err() {
        return Ok(Err(ChangedDuringTransfer));
    }
    Ok(Ok((pos, hasher.finalize().into())))
}
