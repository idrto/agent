use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use tokio::sync::mpsc;
use tokio::time::{sleep, Instant};
use tracing::{debug, error};

use crate::storage::models::{
    PresenceDiscoveryCacheRow, ProcessedCommandRow, RelayConnectionHistoryRow,
};
use crate::storage::Storage;
use crate::telemetry::Metrics;

const BATCH_MAX: usize = 64;
const FLUSH_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug)]
pub enum StorageCommand {
    UpsertRelayHistory(RelayConnectionHistoryRow),
    UpsertDiscoveryCache(PresenceDiscoveryCacheRow),
    UpsertProcessedCommand(ProcessedCommandRow),
    PruneExpiredCommands { not_after: DateTime<Utc> },
    Flush,
    Shutdown,
}

pub struct StorageWriter {
    tx: mpsc::Sender<StorageCommand>,
}

impl Clone for StorageWriter {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

impl StorageWriter {
    pub fn spawn(storage: Storage, metrics: Metrics) -> Self {
        let (tx, mut rx) = mpsc::channel(256);
        tokio::spawn(async move {
            let mut batch: Vec<StorageCommand> = Vec::with_capacity(BATCH_MAX);
            let mut next_flush = Instant::now() + FLUSH_INTERVAL;
            loop {
                tokio::select! {
                    cmd = rx.recv() => {
                        match cmd {
                            Some(StorageCommand::Shutdown) => {
                                if !batch.is_empty() {
                                    if let Err(e) = flush_batch(&storage, &mut batch) {
                                        error!(error = %e, "sqlite final flush failed");
                                    }
                                }
                                break;
                            }
                            Some(cmd) => {
                                batch.push(cmd);
                                if batch.len() >= BATCH_MAX {
                                    if let Err(e) = flush_batch(&storage, &mut batch) {
                                        error!(error = %e, "sqlite batch flush failed");
                                    }
                                    metrics.sqlite_batch_size.set(batch.len() as f64);
                                    next_flush = Instant::now() + FLUSH_INTERVAL;
                                }
                            }
                            None => break,
                        }
                    }
                    _ = sleep_until_deadline(next_flush) => {
                        if !batch.is_empty() {
                            if let Err(e) = flush_batch(&storage, &mut batch) {
                                error!(error = %e, "sqlite timed flush failed");
                            }
                            metrics.sqlite_batch_size.set(batch.len() as f64);
                        }
                        next_flush = Instant::now() + FLUSH_INTERVAL;
                    }
                }
            }
        });
        Self { tx }
    }

    pub async fn send(&self, cmd: StorageCommand) -> Result<()> {
        self.tx
            .send(cmd)
            .await
            .map_err(|e| anyhow::anyhow!("storage writer closed: {e}"))
    }

    pub async fn shutdown(self) -> Result<()> {
        self.send(StorageCommand::Shutdown).await
    }
}

async fn sleep_until_deadline(deadline: Instant) {
    let now = Instant::now();
    if deadline > now {
        sleep(deadline - now).await;
    }
}

fn flush_batch(storage: &Storage, batch: &mut Vec<StorageCommand>) -> Result<()> {
    let count = batch.len();
    for cmd in batch.drain(..) {
        match cmd {
            StorageCommand::UpsertRelayHistory(row) => storage.upsert_relay_history(&row)?,
            StorageCommand::UpsertDiscoveryCache(row) => storage.upsert_discovery_cache(&row)?,
            StorageCommand::UpsertProcessedCommand(row) => storage.upsert_processed_command(&row)?,
            StorageCommand::PruneExpiredCommands { not_after } => {
                let n = storage.prune_expired_commands(not_after)?;
                debug!(pruned = n, "pruned expired processed commands");
            }
            StorageCommand::Flush => {}
            StorageCommand::Shutdown => {}
        }
    }
    debug!(count, "sqlite batch flushed");
    Ok(())
}
