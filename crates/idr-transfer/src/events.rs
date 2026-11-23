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

/// Transfer id as the hyphenated UUID text used in every log record (docs/observability/02).
pub fn transfer_id_text(id: &idr_protocol::transfer::TransferId) -> String {
    uuid::Uuid::from_bytes(*id).hyphenated().to_string()
}

/// The one record of how an attempt ended: the registered event for each outcome.
/// `Interrupted` (disconnected or stalled, resumable) is the stall evidence.
pub(crate) fn log_outcome(
    direction: &'static str,
    id: &idr_protocol::transfer::TransferId,
    outcome: &Outcome,
) {
    let transfer_id = transfer_id_text(id);
    match outcome {
        Outcome::Completed => {
            tracing::info!(event = "transfer.completed", %transfer_id, direction)
        }
        Outcome::CompletedWithErrors { failed } => tracing::warn!(
            event = "transfer.completed_with_errors",
            %transfer_id,
            direction,
            entries.failed = u64::from(*failed),
            error.type = "completed_with_errors"
        ),
        Outcome::Failed(k) => tracing::error!(
            event = "transfer.failed",
            %transfer_id,
            direction,
            error.type = k.as_str()
        ),
        Outcome::Cancelled => {
            tracing::info!(event = "transfer.cancelled", %transfer_id, direction)
        }
        Outcome::Rejected(k) => tracing::info!(
            event = "transfer.rejected",
            %transfer_id,
            direction,
            reason = k.as_str()
        ),
        Outcome::Interrupted(k) => tracing::warn!(
            event = "transfer.interrupted",
            %transfer_id,
            direction,
            error.type = k.as_str()
        ),
    }
}

#[cfg(test)]
mod outcome_log_tests {
    use super::*;
    use idr_protocol::transfer::TransferErrorKind as K;

    #[test]
    fn each_outcome_is_one_registered_event_with_a_uuid_transfer_id() {
        let root = std::env::temp_dir().join(format!("idr-transfer-log-{}", idr_telemetry::new_id()));
        let mut cfg = idr_telemetry::Config::new("idr-transfer-test", "0");
        cfg.log_root = Some(root.clone());
        cfg.stdout = idr_telemetry::StdoutFormat::Off;
        cfg.install_panic_hook = false;
        let (guard, subscriber) = idr_telemetry::build(cfg, &[]).unwrap();
        let id = [7u8; 16];
        tracing::subscriber::with_default(subscriber, || {
            log_outcome("send", &id, &Outcome::Completed);
            log_outcome("send", &id, &Outcome::CompletedWithErrors { failed: 2 });
            log_outcome("receive", &id, &Outcome::Failed(K::HashMismatch));
            log_outcome("receive", &id, &Outcome::Cancelled);
            log_outcome("send", &id, &Outcome::Rejected(K::Rejected));
            log_outcome("send", &id, &Outcome::Interrupted(K::Stalled));
        });
        drop(guard);
        let dir = root.join("idr-transfer-test");
        let file = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .find(|e| e.file_name().to_string_lossy().ends_with(".jsonl"))
            .unwrap();
        let records: Vec<serde_json::Value> = std::fs::read_to_string(file.path())
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let events: Vec<&str> = records.iter().map(|r| r["event"].as_str().unwrap()).collect();
        for want in [
            "transfer.completed",
            "transfer.completed_with_errors",
            "transfer.failed",
            "transfer.cancelled",
            "transfer.rejected",
            "transfer.interrupted",
        ] {
            assert!(events.contains(&want), "{want} missing in {events:?}");
        }
        let stalled = records.iter().find(|r| r["event"] == "transfer.interrupted").unwrap();
        assert_eq!(stalled["error"]["type"], "stalled");
        assert_eq!(stalled["level"], "WARN");
        assert_eq!(stalled["transfer_id"], "07070707-0707-0707-0707-070707070707");
        let failed = records.iter().find(|r| r["event"] == "transfer.failed").unwrap();
        assert_eq!((failed["level"].as_str(), failed["error"]["type"].as_str()), (Some("ERROR"), Some("hash_mismatch")));
        let _ = std::fs::remove_dir_all(&root);
    }
}
