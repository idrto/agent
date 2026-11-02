//! Transfer events and local commands.

use idr_protocol::transfer::TransferErrorKind;
use tokio::sync::mpsc;

use crate::manifest::OfferSummary;
use crate::storage::Approval;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Every entry verified and committed.
    Completed,
    /// Some entries failed; verified ones are kept (folders stay staged).
    CompletedWithErrors { failed: u32 },
    /// Unrecoverable for this attempt (e.g. protocol violation).
    Failed(TransferErrorKind),
    Cancelled,
    Rejected(TransferErrorKind),
    /// Disconnected or stalled; resumable with the same transfer id.
    Interrupted(TransferErrorKind),
}

impl Outcome {
    /// Stable code for C / Dart / CLI.
    pub fn code(&self) -> Option<TransferErrorKind> {
        match self {
            Self::Completed => None,
            Self::CompletedWithErrors { .. } => Some(TransferErrorKind::CompletedWithErrors),
            Self::Cancelled => Some(TransferErrorKind::Cancelled),
            Self::Failed(k) | Self::Rejected(k) | Self::Interrupted(k) => Some(*k),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Progress {
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub files_done: u32,
    pub files_total: u32,
    pub files_failed: u32,
    pub bytes_per_sec: u64,
}

/// Coalesced: progress at most every `progress_interval`, at most
/// `max_failure_events` entry failures; never one event per file or chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferEvent {
    Offered(OfferSummary),
    /// `approval` is known on the receiving side only.
    Accepted { approval: Option<Approval> },
    Progress(Progress),
    EntryFailed { entry: u32, code: TransferErrorKind },
    /// Stored under another name (`to` is the stored relative path).
    Renamed { entry: u32, to: String },
    /// The authorization lease ends soon; renewal is being attempted.
    LeaseExpiring { secs_left: u64 },
    /// An incoming offer waits for the local user (`accept` / `reject`).
    AwaitingDecision,
    Paused { by_peer: bool },
    Resumed { by_peer: bool },
    Finished(Outcome),
}

pub type EventTx = mpsc::UnboundedSender<TransferEvent>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Pause,
    Resume,
    Cancel,
    /// The authorization lease ended without renewal: checkpoint and stop,
    /// keeping verified data (`Interrupted(AuthorizationExpired)`).
    AuthExpired,
    /// The peer was revoked: stop now, keeping verified data (`Interrupted(Unauthorized)`).
    Revoked,
    /// A newer attempt of this transfer took over (its peer reconnected): stop
    /// now, keeping verified data, without telling the old session.
    Supersede,
}

impl Command {
    /// Stop-and-keep reason for authorization commands.
    pub(crate) fn auth_stop(self) -> Option<TransferErrorKind> {
        match self {
            Self::AuthExpired => Some(TransferErrorKind::AuthorizationExpired),
            Self::Revoked => Some(TransferErrorKind::Unauthorized),
            _ => None,
        }
    }
}

/// A peer `Cancel` with one of these codes means "stop, keep the data".
pub(crate) fn keeps_data(code: TransferErrorKind) -> bool {
    matches!(
        code,
        TransferErrorKind::AuthorizationExpired | TransferErrorKind::Unauthorized
    )
}

pub(crate) struct Meter {
    events: EventTx,
    every: std::time::Duration,
    last: Option<tokio::time::Instant>,
    started: tokio::time::Instant,
    start_bytes: u64,
    failure_events: u32,
    max_failure_events: u32,
    pub p: Progress,
}

impl Meter {
    pub fn new(events: EventTx, limits: &crate::Limits, p: Progress) -> Self {
        Self {
            events,
            every: limits.progress_interval,
            last: None,
            started: tokio::time::Instant::now(),
            start_bytes: p.bytes_done,
            failure_events: 0,
            max_failure_events: limits.max_failure_events,
            p,
        }
    }

    pub fn emit(&self, ev: TransferEvent) {
        let _ = self.events.send(ev);
    }

    /// Progress, if the interval has passed (or `force`).
    pub fn tick(&mut self, force: bool) {
        let now = tokio::time::Instant::now();
        if !force && self.last.is_some_and(|l| now - l < self.every) {
            return;
        }
        self.last = Some(now);
        let secs = (now - self.started).as_secs_f64();
        if secs > 0.0 {
            self.p.bytes_per_sec = ((self.p.bytes_done - self.start_bytes) as f64 / secs) as u64;
        }
        self.emit(TransferEvent::Progress(self.p));
    }

    pub fn renamed(&mut self, list: Vec<(u32, String)>) {
        for (entry, to) in list {
            if self.failure_events < self.max_failure_events {
                self.failure_events += 1;
                self.emit(TransferEvent::Renamed { entry, to });
            }
        }
    }

    pub fn entry_failed(&mut self, entry: u32, code: TransferErrorKind) {
        self.p.files_failed += 1;
        if self.failure_events < self.max_failure_events {
            self.failure_events += 1;
            self.emit(TransferEvent::EntryFailed { entry, code });
        }
    }
}
