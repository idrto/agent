//! Agent-owned transfers.
//!
//! The agent, not the command that started a transfer, owns it. Outgoing
//! transfers are recorded in a small SQLite outbox (`transfers.db` in the
//! agent's data directory) with their manifest and how to reopen their files, so
//! they survive the CLI exiting, the session dropping, and the agent restarting:
//! each is re-run with `resume = true` whenever its peer's session is up again,
//! and the receiver skips what it already verified. Incoming transfers are
//! tracked for status; resuming them is the sender's job.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use idr_protocol::peer_bind::VerifiedPeer;
use idr_protocol::transfer::{Manifest, StreamHeader, TransferErrorKind, TransferId};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, watch, Notify};

use super::files::NativeFiles;
use crate::events::{Command, Outcome, Progress, TransferEvent};
use crate::io::Framed;
use crate::manifest::OfferSummary;
use crate::policy::SendPolicy;
use crate::policy::Prompt;
use crate::storage::{Consent, OfferInfo, Sink, StreamOpener};
use super::sink::NativeSink;
use crate::{receive, send, Limits, Outgoing, Router};

/// How to reopen an outgoing transfer's files, now or after a restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilesSpec {
    /// Manifest paths are relative to this directory (folders, selections).
    Root(PathBuf),
    /// Loose files, named in the manifest by file name.
    Loose(Vec<PathBuf>),
}

impl FilesSpec {
    pub fn open(&self) -> std::io::Result<NativeFiles> {
        match self {
            Self::Root(root) => NativeFiles::new(root),
            Self::Loose(paths) => Ok(NativeFiles::loose(paths)?.0),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Outgoing,
    Incoming,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Queued,
    Running,
    /// Paused by the user; stays paused across restarts.
    Paused,
    /// Interrupted; resumes when the peer's session is up again.
    Waiting(TransferErrorKind),
    /// Incoming offer waiting for the local user (`transfer accept` / `reject`).
    Pending,
    Done(Outcome),
}

impl State {
    fn code(&self) -> String {
        match self {
            Self::Queued | Self::Running | Self::Pending => "queued".into(),
            Self::Paused => "paused".into(),
            Self::Waiting(k) => format!("waiting:{}", *k as u32),
            Self::Done(Outcome::Completed) => "done:completed".into(),
            Self::Done(Outcome::CompletedWithErrors { failed }) => format!("done:errors:{failed}"),
            Self::Done(Outcome::Cancelled) => "done:cancelled".into(),
            Self::Done(Outcome::Failed(k)) => format!("done:failed:{}", *k as u32),
            Self::Done(Outcome::Rejected(k)) => format!("done:rejected:{}", *k as u32),
            Self::Done(Outcome::Interrupted(k)) => format!("waiting:{}", *k as u32),
        }
    }

    fn parse(s: &str) -> Self {
        let kind = |v: &str| {
            v.parse()
                .ok()
                .and_then(TransferErrorKind::from_u32)
                .unwrap_or(TransferErrorKind::TransportClosed)
        };
        match s.split(':').collect::<Vec<_>>().as_slice() {
            ["paused"] => Self::Paused,
            ["waiting", k] => Self::Waiting(kind(k)),
            ["done", "completed"] => Self::Done(Outcome::Completed),
            ["done", "errors", n] => Self::Done(Outcome::CompletedWithErrors {
                failed: n.parse().unwrap_or(0),
            }),
            ["done", "cancelled"] => Self::Done(Outcome::Cancelled),
            ["done", "failed", k] => Self::Done(Outcome::Failed(kind(k))),
            ["done", "rejected", k] => Self::Done(Outcome::Rejected(kind(k))),
            _ => Self::Queued,
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self, Self::Done(_))
    }
}

#[derive(Debug, Clone)]
pub struct TransferInfo {
    pub id: TransferId,
    pub direction: Direction,
    /// The peer's name as the agent knows it (e.g. the Target FQHN).
    pub peer: String,
    pub summary: Option<OfferSummary>,
    pub state: State,
    pub progress: Progress,
    /// The current (or last) session's path: direct (host / stun) or relayed (turn).
    pub path: Option<idr_protocol::webrtc_ice::IcePath>,
}

/// A live, identity-bound session to a peer, published by the agent.
pub trait Link: Send + Sync {
    fn opener(&self) -> Box<dyn StreamOpener>;
    fn peer(&self) -> &VerifiedPeer;
    /// Changes on every new session.
    fn generation(&self) -> u64;
}

pub type LinkRx = watch::Receiver<Option<Arc<dyn Link>>>;

struct Entry {
    info: TransferInfo,
    manifest: Option<Manifest>,
    files: Option<FilesSpec>,
    cmds: Option<mpsc::Sender<Command>>,
    wake: Arc<Notify>,
    /// Per entry, from this run's events (not persisted).
    failed: HashMap<u32, TransferErrorKind>,
    renamed: HashMap<u32, String>,
}

impl Entry {
    fn new(info: TransferInfo, manifest: Option<Manifest>, files: Option<FilesSpec>, cmds: Option<mpsc::Sender<Command>>) -> Self {
        Self { info, manifest, files, cmds, wake: Arc::new(Notify::new()), failed: HashMap::new(), renamed: HashMap::new() }
    }
}

/// Most entries one [`Manager::entries_json`] call returns.
pub const MAX_ENTRY_BATCH: u32 = 256;

pub struct Manager {
    db: Mutex<Connection>,
    entries: Mutex<HashMap<TransferId, Entry>>,
    links: Mutex<HashMap<String, LinkRx>>,
    links_changed: Notify,
    limits: Limits,
    send_policy: SendPolicy,
    events: broadcast::Sender<(TransferId, TransferEvent)>,
    /// Pause before re-running an interrupted transfer on the same session.
    retry_delay: Duration,
    /// Incoming offers waiting for a local decision.
    pending: Mutex<HashMap<TransferId, tokio::sync::oneshot::Sender<bool>>>,
    /// Destinations chosen at accept time.
    destinations: Mutex<HashMap<TransferId, super::Destination>>,
    /// Per peer: a transfer stopped for authorization; the session must re-authorize.
    reauth: Mutex<HashMap<String, Arc<Notify>>>,
    /// Held by each receive attempt of a transfer until its storage is closed.
    receiving: Mutex<HashMap<TransferId, Arc<tokio::sync::Mutex<()>>>>,
}

/// Outbox row: id, direction, peer, manifest, files, state.
type Row = (Vec<u8>, i64, String, Option<Vec<u8>>, Option<Vec<u8>>, String);
/// A transfer's command channel (while running), state and wake-up.
type Handles = (Option<mpsc::Sender<Command>>, State, Arc<Notify>);

fn hex(id: &TransferId) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

impl Manager {
    /// Open (or create) the outbox in `data_dir` and resume unfinished outgoing
    /// transfers once their peers' sessions are published with [`Manager::set_link`].
    pub fn open(data_dir: &Path, limits: Limits, send_policy: SendPolicy) -> rusqlite::Result<Arc<Self>> {
        let conn = Connection::open(data_dir.join("transfers.db"))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS transfer (
                id BLOB PRIMARY KEY, direction INTEGER NOT NULL, peer TEXT NOT NULL,
                manifest BLOB, files BLOB, state TEXT NOT NULL, updated INTEGER NOT NULL)",
        )?;
        let (events, _) = broadcast::channel(1024);
        let m = Arc::new(Self {
            db: Mutex::new(conn),
            entries: Mutex::new(HashMap::new()),
            links: Mutex::new(HashMap::new()),
            links_changed: Notify::new(),
            limits,
            send_policy,
            events,
            retry_delay: Duration::from_secs(2),
            pending: Mutex::new(HashMap::new()),
            destinations: Mutex::new(HashMap::new()),
            reauth: Mutex::new(HashMap::new()),
            receiving: Mutex::new(HashMap::new()),
        });
        m.restore()?;
        Ok(m)
    }

    fn restore(self: &Arc<Self>) -> rusqlite::Result<()> {
        let rows: Vec<Row> = {
            let db = self.db.lock().unwrap();
            let mut st = db.prepare("SELECT id, direction, peer, manifest, files, state FROM transfer")?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for (id, dir, peer, manifest, files, state) in rows {
            let Ok(id) = TransferId::try_from(id.as_slice()) else { continue };
            let manifest: Option<Manifest> = manifest.and_then(|b| postcard::from_bytes(&b).ok());
            let files: Option<FilesSpec> = files.and_then(|b| postcard::from_bytes(&b).ok());
            let direction = if dir == 0 { Direction::Outgoing } else { Direction::Incoming };
            let mut state = State::parse(&state);
            if direction == Direction::Incoming && !state.is_done() {
                state = State::Waiting(TransferErrorKind::TransportClosed);
            }
            let resumable = direction == Direction::Outgoing && !state.is_done() && manifest.is_some() && files.is_some();
            let summary = manifest.as_ref().map(OfferSummary::of);
            // Totals from the manifest; a completed transfer is all done (live counts aren't stored).
            let mut progress = Progress::default();
            if let Some(s) = &summary {
                progress.bytes_total = s.total_bytes;
                progress.files_total = s.files;
                if state == State::Done(Outcome::Completed) {
                    progress.bytes_done = s.total_bytes;
                    progress.files_done = s.files;
                }
            }
            self.entries.lock().unwrap().insert(id, Entry::new(
                TransferInfo { id, direction, peer, summary, state, progress, path: None },
                manifest,
                files,
                None,
            ));
            if resumable {
                tokio::spawn(self.clone().run_outgoing(id, true));
            }
        }
        Ok(())
    }

    fn persist(&self, id: &TransferId) {
        let entries = self.entries.lock().unwrap();
        let Some(e) = entries.get(id) else { return };
        let db = self.db.lock().unwrap();
        let res = db.execute(
            "INSERT INTO transfer (id, direction, peer, manifest, files, state, updated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, strftime('%s','now'))
             ON CONFLICT(id) DO UPDATE SET peer = ?3, manifest = ?4, state = ?6, updated = strftime('%s','now')",
            params![
                &e.info.id[..],
                (e.info.direction == Direction::Incoming) as i64,
                e.info.peer,
                e.manifest.as_ref().map(|m| postcard::to_allocvec(m).unwrap()),
                e.files.as_ref().map(|f| postcard::to_allocvec(f).unwrap()),
                e.info.state.code(),
            ],
        );
        if let Err(err) = res {
            tracing::warn!(error = %err, transfer = %hex(id), "transfer outbox write failed");
        }
    }

    fn set_state(&self, id: &TransferId, state: State) {
        if let Some(e) = self.entries.lock().unwrap().get_mut(id) {
            e.info.state = state;
        }
        self.persist(id);
    }

    /// Signalled when one of `peer`'s transfers stopped because its
    /// authorization ended: the agent should re-authorize (new session).
    pub fn reauth_needed(&self, peer: &str) -> Arc<Notify> {
        self.reauth.lock().unwrap().entry(peer.to_string()).or_default().clone()
    }

    fn note_auth_stop(&self, peer: &str, outcome: &Outcome) {
        if let Outcome::Interrupted(TransferErrorKind::AuthorizationExpired | TransferErrorKind::Unauthorized) = outcome {
            self.reauth_needed(peer).notify_one();
        }
    }

    /// Send `cmd` to every running transfer with `peer` (e.g. `AuthExpired`).
    pub async fn interrupt(&self, peer: &str, cmd: Command) {
        let senders: Vec<_> = self
            .entries
            .lock()
            .unwrap()
            .values()
            .filter(|e| e.info.peer == peer)
            .filter_map(|e| e.cmds.clone())
            .collect();
        for s in senders {
            let _ = s.send(cmd).await;
        }
    }

    /// Publish (or replace) the session watcher for `peer`.
    pub fn set_link(&self, peer: &str, rx: LinkRx) {
        self.links.lock().unwrap().insert(peer.to_string(), rx);
        self.links_changed.notify_waiters();
    }

    /// Peers with a bound session now, and how it reaches them, by name.
    pub fn peers(&self) -> Vec<(String, Option<idr_protocol::webrtc_ice::IcePath>)> {
        let mut v: Vec<_> = self
            .links
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(peer, rx)| rx.borrow().as_ref().map(|l| (peer.clone(), l.peer().path)))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    /// Live events for every transfer (CLI `status --follow`, GUI).
    pub fn subscribe(&self) -> broadcast::Receiver<(TransferId, TransferEvent)> {
        self.events.subscribe()
    }

    pub fn list(&self) -> Vec<TransferInfo> {
        let mut v: Vec<_> = self.entries.lock().unwrap().values().map(|e| e.info.clone()).collect();
        v.sort_by_key(|i| i.id);
        v
    }

    pub fn status(&self, id: &TransferId) -> Option<TransferInfo> {
        self.entries.lock().unwrap().get(id).map(|e| e.info.clone())
    }

    /// Queue an outgoing transfer. It starts once `peer`'s session is up.
    pub fn send(self: &Arc<Self>, peer: &str, transfer_id: TransferId, manifest: Manifest, files: FilesSpec) -> TransferId {
        let info = TransferInfo {
            id: transfer_id,
            direction: Direction::Outgoing,
            peer: peer.to_string(),
            summary: Some(OfferSummary::of(&manifest)),
            state: State::Queued,
            progress: Progress::default(),
            path: None,
        };
        self.entries.lock().unwrap().insert(transfer_id, Entry::new(info, Some(manifest), Some(files), None));
        self.persist(&transfer_id);
        tokio::spawn(self.clone().run_outgoing(transfer_id, false));
        transfer_id
    }

    fn cmd(&self, id: &TransferId) -> Result<Handles, TransferErrorKind> {
        let entries = self.entries.lock().unwrap();
        let e = entries.get(id).ok_or(TransferErrorKind::Rejected)?;
        Ok((e.cmds.clone(), e.info.state.clone(), e.wake.clone()))
    }

    pub async fn pause(&self, id: &TransferId) -> Result<(), TransferErrorKind> {
        let (cmds, state, _) = self.cmd(id)?;
        if state.is_done() {
            return Ok(());
        }
        if let Some(c) = cmds {
            let _ = c.send(Command::Pause).await;
        }
        self.set_state(id, State::Paused);
        Ok(())
    }

    pub async fn resume(&self, id: &TransferId) -> Result<(), TransferErrorKind> {
        let (cmds, state, wake) = self.cmd(id)?;
        if state != State::Paused {
            return Ok(());
        }
        self.set_state(id, State::Queued);
        if let Some(c) = cmds {
            let _ = c.send(Command::Resume).await;
            self.set_state(id, State::Running);
        }
        wake.notify_waiters();
        Ok(())
    }

    /// Cancel: the receiver removes partial data; the record stays as history.
    pub async fn cancel(&self, id: &TransferId) -> Result<(), TransferErrorKind> {
        let (cmds, state, wake) = self.cmd(id)?;
        if state.is_done() {
            return Ok(());
        }
        match cmds {
            Some(c) => {
                let _ = c.send(Command::Cancel).await;
            }
            None => self.set_state(id, State::Done(Outcome::Cancelled)),
        }
        wake.notify_waiters();
        Ok(())
    }

    /// Re-run failed or interrupted entries of a finished outgoing transfer.
    pub fn retry(self: &Arc<Self>, id: &TransferId) -> Result<(), TransferErrorKind> {
        let state = self.cmd(id)?.1;
        if !matches!(state, State::Done(Outcome::CompletedWithErrors { .. }) | State::Done(Outcome::Failed(_))) {
            return Err(TransferErrorKind::Rejected);
        }
        self.set_state(id, State::Queued);
        tokio::spawn(self.clone().run_outgoing(*id, true));
        Ok(())
    }

    async fn link_for(&self, peer: &str, newer_than: Option<u64>) -> Arc<dyn Link> {
        loop {
            let notified = self.links_changed.notified();
            let rx = self.links.lock().unwrap().get(peer).cloned();
            if let Some(mut rx) = rx {
                let got = rx
                    .wait_for(|l| l.as_ref().is_some_and(|l| newer_than.map_or(true, |g| l.generation() > g)))
                    .await
                    .ok()
                    .and_then(|l| l.clone());
                if let Some(link) = got {
                    return link;
                }
            }
            notified.await;
        }
    }

    async fn run_outgoing(self: Arc<Self>, id: TransferId, mut resume: bool) {
        let mut last_gen: Option<u64> = None;
        let mut limit_backoff = Duration::ZERO;
        loop {
            let (state, wake, peer, manifest, spec) = {
                let entries = self.entries.lock().unwrap();
                let Some(e) = entries.get(&id) else { return };
                (e.info.state.clone(), e.wake.clone(), e.info.peer.clone(), e.manifest.clone(), e.files.clone())
            };
            if state.is_done() {
                return;
            }
            if state == State::Paused {
                let w = wake.notified();
                if self.cmd(&id).map(|c| c.1 == State::Paused).unwrap_or(false) {
                    w.await;
                }
                continue;
            }
            let (Some(manifest), Some(spec)) = (manifest, spec) else { return };
            // A retry on the same session waits a little; a new session goes at once.
            let link = tokio::select! {
                l = self.link_for(&peer, last_gen) => l,
                _ = tokio::time::sleep(self.retry_delay), if last_gen.is_some() => self.link_for(&peer, None).await,
            };
            let summary = OfferSummary::of(&manifest);
            if let Err(k) = self.send_policy.check(Some(link.peer()), &summary) {
                self.set_state(&id, State::Done(Outcome::Rejected(k)));
                return;
            }
            let files = match spec.open() {
                Ok(f) => f,
                Err(_) => {
                    self.set_state(&id, State::Done(Outcome::Failed(TransferErrorKind::SourceReadFailed)));
                    return;
                }
            };
            let (cmd_tx, cmd_rx) = mpsc::channel(8);
            if let Some(e) = self.entries.lock().unwrap().get_mut(&id) {
                e.cmds = Some(cmd_tx);
                e.info.state = State::Running;
                e.info.path = link.peer().path;
            }
            let (ev_tx, ev_rx) = mpsc::unbounded_channel();
            let resumed = resume;
            let req = Outgoing { transfer_id: id, manifest, files, resume };
            let mut opener = link.opener();
            let (outcome, ()) = tokio::join!(
                send(&mut *opener, req, &self.limits, ev_tx, cmd_rx),
                self.track(id, ev_rx),
            );
            resume = true;
            if let Some(e) = self.entries.lock().unwrap().get_mut(&id) {
                e.cmds = None;
            }
            let paused = self.cmd(&id).map(|c| c.1 == State::Paused).unwrap_or(false);
            self.note_auth_stop(&peer, &outcome);
            match outcome {
                Outcome::Interrupted(k) => {
                    last_gen = Some(link.generation());
                    limit_backoff = Duration::ZERO;
                    if !paused {
                        self.set_state(&id, State::Waiting(k));
                    }
                }
                // A resume over the peer's rate or concurrency limit: those clear
                // on their own, so wait and try again rather than give up. 15 s,
                // 30 s, 60 s… keeps refusals per rate window under the cool-off count.
                Outcome::Rejected(TransferErrorKind::LimitExceeded) if resumed => {
                    self.set_state(&id, State::Waiting(TransferErrorKind::LimitExceeded));
                    limit_backoff = (limit_backoff * 2).clamp(Duration::from_secs(15), Duration::from_secs(60));
                    tokio::time::sleep(limit_backoff).await;
                    last_gen = None;
                }
                done => {
                    self.set_state(&id, State::Done(done));
                    return;
                }
            }
        }
    }

    /// Record progress and failures from a transfer's events.
    async fn track(&self, id: TransferId, mut rx: mpsc::UnboundedReceiver<TransferEvent>) {
        while let Some(ev) = rx.recv().await {
            if let Some(e) = self.entries.lock().unwrap().get_mut(&id) {
                match &ev {
                    TransferEvent::Progress(p) => e.info.progress = *p,
                    TransferEvent::Offered(s) => e.info.summary = Some(s.clone()),
                    TransferEvent::EntryFailed { entry, code } => {
                        e.failed.insert(*entry, *code);
                    }
                    TransferEvent::Renamed { entry, to } => {
                        e.renamed.insert(*entry, to.clone());
                    }
                    _ => {}
                }
            }
            let _ = self.events.send((id, ev));
        }
    }

    /// Receive an incoming transfer (from a [`Router`]-classified control stream)
    /// and track it. `sink` is closed before this returns.
    #[allow(clippy::too_many_arguments)]
    pub async fn receive<S: Sink, C: Consent>(
        &self,
        peer: &str,
        path: Option<idr_protocol::webrtc_ice::IcePath>,
        router: &Router,
        header: StreamHeader,
        control: Framed,
        mut sink: S,
        consent: &mut C,
    ) -> Outcome {
        let id = header.transfer_id;
        // The peer reconnected while an older attempt still runs on a session that
        // hasn't noticed it left; that attempt holds the transfer's files. Stop it
        // (and its consent prompt) and wait until its storage is closed.
        let older = self.entries.lock().unwrap().get(&id).and_then(|e| e.cmds.clone());
        if let Some(older) = older {
            let _ = older.try_send(Command::Supersede);
            self.pending.lock().unwrap().remove(&id);
        }
        let turn = self.receiving.lock().unwrap().entry(id).or_default().clone();
        let _turn = turn.lock_owned().await;
        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        {
            let mut entries = self.entries.lock().unwrap();
            match entries.get_mut(&id) {
                // The same peer resuming: keep what was accepted (manifest) and done so far.
                Some(e) if e.info.direction == Direction::Incoming && e.info.peer == peer => {
                    e.info.state = State::Running;
                    e.info.path = path;
                    e.cmds = Some(cmd_tx);
                }
                _ => {
                    let info = TransferInfo {
                        id,
                        direction: Direction::Incoming,
                        peer: peer.to_string(),
                        summary: None,
                        state: State::Running,
                        progress: Progress::default(),
                        path,
                    };
                    entries.insert(id, Entry::new(info, None, None, Some(cmd_tx)));
                }
            }
        }
        self.persist(&id);
        let (ev_tx, ev_rx) = mpsc::unbounded_channel();
        let (outcome, ()) = tokio::join!(
            receive(router, header, control, &mut sink, consent, &self.limits, ev_tx, cmd_rx),
            self.track(id, ev_rx),
        );
        drop(sink);
        if let Some(e) = self.entries.lock().unwrap().get_mut(&id) {
            e.cmds = None;
        }
        let state = match &outcome {
            Outcome::Interrupted(k) => State::Waiting(*k),
            o => State::Done(o.clone()),
        };
        self.set_state(&id, state);
        self.note_auth_stop(peer, &outcome);
        outcome
    }

    /// A [`Prompt`] that parks an offer as `Pending` until [`Manager::accept`] or
    /// [`Manager::reject`], or refuses it after `expiry`.
    pub fn prompt(self: &Arc<Self>, expiry: Duration) -> Box<dyn Prompt> {
        Box::new(ManagerPrompt { manager: self.clone(), expiry })
    }

    /// Accept a pending offer, optionally into `out` (which must be within `permitted`).
    pub fn accept(&self, id: &TransferId, out: Option<PathBuf>, permitted: &[PathBuf]) -> Result<(), TransferErrorKind> {
        if let Some(dir) = &out {
            let dest = super::resolve_destination(permitted, dir)?;
            self.destinations.lock().unwrap().insert(*id, dest);
        }
        let tx = self.pending.lock().unwrap().remove(id).ok_or(TransferErrorKind::Rejected)?;
        let _ = tx.send(true);
        Ok(())
    }

    pub fn reject(&self, id: &TransferId) -> Result<(), TransferErrorKind> {
        let tx = self.pending.lock().unwrap().remove(id).ok_or(TransferErrorKind::Rejected)?;
        let _ = tx.send(false);
        Ok(())
    }

    /// Up to `max` (≤ [`MAX_ENTRY_BATCH`]) entries from `first`, with per-entry
    /// failures and stored names; relative paths only. `None`: unknown transfer.
    pub fn entries_json(&self, id: &TransferId, first: u32, max: u32) -> Option<serde_json::Value> {
        let entries = self.entries.lock().unwrap();
        let e = entries.get(id)?;
        let all = e.manifest.as_ref().map(|m| m.entries.as_slice()).unwrap_or(&[]);
        let batch: Vec<_> = all
            .iter()
            .skip(first as usize)
            .take(max.min(MAX_ENTRY_BATCH) as usize)
            .map(|m| {
                serde_json::json!({
                    "entry": m.id,
                    "path": m.path.join("/"),
                    "kind": match m.kind { idr_protocol::transfer::EntryKind::File => "file", idr_protocol::transfer::EntryKind::Dir => "dir" },
                    "size": m.size,
                    "failed": e.failed.get(&m.id).map(|k| k.as_str()),
                    "stored_as": e.renamed.get(&m.id),
                })
            })
            .collect();
        Some(serde_json::json!({ "total": all.len(), "first": first, "entries": batch }))
    }

    /// Where an accepted incoming transfer goes, if chosen at accept time.
    pub fn destination(&self, id: &TransferId) -> Option<super::Destination> {
        self.destinations.lock().unwrap().get(id).cloned()
    }
}

struct ManagerPrompt {
    manager: Arc<Manager>,
    expiry: Duration,
}

#[async_trait::async_trait]
impl Prompt for ManagerPrompt {
    async fn ask(&mut self, _peer: &VerifiedPeer, offer: &OfferInfo<'_>) -> bool {
        let id = *offer.transfer_id;
        // Already accepted from this peer ([`Manager::receive`] keeps the entry only
        // for the same peer) with this exact manifest: resuming needs no new consent.
        if offer.resume {
            let entries = self.manager.entries.lock().unwrap();
            if entries.get(&id).and_then(|e| e.manifest.as_ref()).is_some_and(|m| Manifest::digest_of(&m.encode()) == *offer.digest) {
                return true;
            }
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.manager.pending.lock().unwrap().insert(id, tx);
        if let Some(e) = self.manager.entries.lock().unwrap().get_mut(&id) {
            e.info.state = State::Pending;
            e.info.summary = Some(offer.summary.clone());
        }
        let _ = self.manager.events.send((id, TransferEvent::AwaitingDecision));
        let yes = matches!(tokio::time::timeout(self.expiry, rx).await, Ok(Ok(true)));
        self.manager.pending.lock().unwrap().remove(&id);
        if let Some(e) = self.manager.entries.lock().unwrap().get_mut(&id) {
            e.info.state = State::Running;
        }
        yes
    }
}

/// Receiver storage created only once the destination is decided: the one
/// chosen at accept time, else `default`.
pub struct DeferredSink {
    manager: Arc<Manager>,
    default: PathBuf,
    inner: Option<NativeSink>,
}

impl DeferredSink {
    pub fn new(manager: Arc<Manager>, default: PathBuf) -> Self {
        Self { manager, default, inner: None }
    }

    fn inner(&mut self) -> crate::storage::Result<&mut NativeSink> {
        self.inner.as_mut().ok_or(TransferErrorKind::StorageFailed)
    }
}

#[async_trait::async_trait]
impl Sink for DeferredSink {
    async fn prepare(&mut self, id: &TransferId, digest: &idr_protocol::transfer::Sha256Digest, manifest: &Manifest) -> crate::storage::Result<Vec<idr_protocol::transfer::ResumePoint>> {
        if let Some(e) = self.manager.entries.lock().unwrap().get_mut(id) {
            e.manifest.get_or_insert_with(|| manifest.clone());
        }
        // Accepted: keep the manifest across restarts (a resume needs no new consent).
        self.manager.persist(id);
        let sink = match self.manager.destination(id) {
            Some(d) => NativeSink::open_in(&d.root, &d.rel),
            None => NativeSink::new(&self.default),
        }
        .map_err(|e| {
            tracing::warn!(id = %hex(id), error = %e, "receive destination unavailable");
            TransferErrorKind::StorageFailed
        })?;
        self.inner.insert(sink).prepare(id, digest, manifest).await
    }
    async fn create_dir(&mut self, entry: u32) -> crate::storage::Result<()> {
        self.inner()?.create_dir(entry).await
    }
    async fn read_partial(&mut self, entry: u32, offset: u64, buf: &mut [u8]) -> crate::storage::Result<usize> {
        self.inner()?.read_partial(entry, offset, buf).await
    }
    async fn write(&mut self, entry: u32, offset: u64, bytes: &[u8]) -> crate::storage::Result<()> {
        self.inner()?.write(entry, offset, bytes).await
    }
    async fn checkpoint(&mut self, entry: u32, len: u64) -> crate::storage::Result<()> {
        self.inner()?.checkpoint(entry, len).await
    }
    async fn commit(&mut self, entry: u32) -> crate::storage::Result<()> {
        self.inner()?.commit(entry).await
    }
    async fn fail(&mut self, entry: u32) -> crate::storage::Result<()> {
        self.inner()?.fail(entry).await
    }
    async fn finish(&mut self) -> crate::storage::Result<()> {
        self.inner()?.finish().await
    }
    async fn discard(&mut self) -> crate::storage::Result<()> {
        match self.inner.as_mut() {
            Some(s) => s.discard().await,
            None => Ok(()),
        }
    }
    fn take_renamed(&mut self) -> Vec<(u32, String)> {
        self.inner.as_mut().map(|s| s.take_renamed()).unwrap_or_default()
    }
}

/// A transfer as the CLI and IPC show it (no filesystem paths).
pub fn info_json(i: &TransferInfo) -> serde_json::Value {
    let state = match &i.state {
        State::Queued => "queued".to_string(),
        State::Running => "running".into(),
        State::Paused => "paused".into(),
        State::Pending => "pending".into(),
        State::Waiting(k) => format!("waiting:{}", k.as_str()),
        State::Done(o) => match o.code() {
            None => "completed".into(),
            Some(k) => k.as_str().into(),
        },
    };
    let p = &i.progress;
    serde_json::json!({
        "id": hex(&i.id),
        "direction": match i.direction { Direction::Outgoing => "outgoing", Direction::Incoming => "incoming" },
        "peer": i.peer,
        "state": state,
        "path": i.path.map(|p| p.as_str()),
        "relayed": i.path.map(|p| p.is_relayed()),
        "connection": idr_protocol::webrtc_ice::IcePath::connection(i.path),
        "summary": i.summary.as_ref().map(|s| serde_json::json!({
            "files": s.files, "dirs": s.dirs, "total_bytes": s.total_bytes,
            "top_level": s.top_level, "more_top_level": s.more_top_level,
        })),
        "progress": {
            "bytes_done": p.bytes_done, "bytes_total": p.bytes_total,
            "files_done": p.files_done, "files_total": p.files_total,
            "files_failed": p.files_failed, "bytes_per_sec": p.bytes_per_sec,
        },
    })
}

/// Parse a hex transfer id as printed by [`info_json`].
pub fn parse_id(s: &str) -> Option<TransferId> {
    if s.len() != 32 {
        return None;
    }
    let mut id = [0u8; 16];
    for (i, b) in id.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(id)
}
