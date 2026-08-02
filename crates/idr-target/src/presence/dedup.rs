use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use ed25519_dalek::VerifyingKey;
use parking_lot::Mutex;
use tokio::sync::{Notify, RwLock};
use tracing::{debug, warn};
use uuid::Uuid;

use crate::storage::models::ProcessedCommandRow;
use crate::storage::writer::{StorageCommand, StorageWriter};
use crate::storage::Storage;
use idr_protocol::crypto::content_digest;
use idr_protocol::errors::ProtocolError;
use idr_protocol::signaling::{CommandResultCode, EnsureRelayConnectionCommand};

#[derive(Debug, Clone)]
pub struct CachedCommandResult {
    pub result: CommandResultCode,
    pub detail: Option<String>,
}

#[derive(Debug)]
pub struct InFlight {
    notify: Notify,
    result: Mutex<Option<Result<CachedCommandResult, String>>>,
}

#[derive(Debug)]
struct DedupEntry {
    digest: [u8; 32],
    result: CachedCommandResult,
    expires_at: chrono::DateTime<Utc>,
    in_flight: Option<Arc<InFlight>>,
}

pub struct CommandDedup {
    ttl: Duration,
    max_entries: usize,
    entries: RwLock<std::collections::HashMap<Uuid, DedupEntry>>,
    storage: Storage,
    writer: StorageWriter,
}

impl CommandDedup {
    pub fn new(ttl: Duration, max_entries: usize, storage: Storage, writer: StorageWriter) -> Self {
        Self {
            ttl,
            max_entries,
            entries: RwLock::new(std::collections::HashMap::new()),
            storage,
            writer,
        }
    }

    pub async fn check_or_register(
        &self,
        cmd: &EnsureRelayConnectionCommand,
    ) -> Result<DedupAction, ProtocolError> {
        let digest = content_digest(
            &serde_json::to_value(cmd).map_err(|e| ProtocolError::Serialization(e.to_string()))?,
        );
        let now = Utc::now();

        {
            let mut map = self.entries.write().await;
            self.prune_locked(&mut map, now);
            if let Some(entry) = map.get(&cmd.command_id) {
                if entry.digest != digest {
                    return Err(ProtocolError::ConflictingCommand);
                }
                if let Some(in_flight) = &entry.in_flight {
                    return Ok(DedupAction::Wait(in_flight.clone()));
                }
                return Ok(DedupAction::Cached(entry.result.clone()));
            }
            let in_flight = Arc::new(InFlight {
                notify: Notify::new(),
                result: Mutex::new(None),
            });
            map.insert(
                cmd.command_id,
                DedupEntry {
                    digest,
                    result: CachedCommandResult {
                        result: CommandResultCode::Received,
                        detail: None,
                    },
                    expires_at: now
                        + chrono::Duration::from_std(self.ttl)
                            .unwrap_or(chrono::Duration::minutes(5)),
                    in_flight: Some(in_flight.clone()),
                },
            );
            return Ok(DedupAction::Process(in_flight));
        }
    }

    pub async fn complete(&self, command_id: Uuid, digest: [u8; 32], result: CachedCommandResult) {
        let expires_at = Utc::now()
            + chrono::Duration::from_std(self.ttl).unwrap_or(chrono::Duration::minutes(5));
        {
            let mut map = self.entries.write().await;
            if let Some(entry) = map.get_mut(&command_id) {
                entry.result = result.clone();
                entry.expires_at = expires_at;
                if let Some(in_flight) = entry.in_flight.take() {
                    *in_flight.result.lock() = Some(Ok(result.clone()));
                    in_flight.notify.notify_waiters();
                }
            }
        }
        let _ = self
            .writer
            .send(StorageCommand::UpsertProcessedCommand(
                ProcessedCommandRow {
                    command_id,
                    content_digest: digest,
                    result_code: result.result as i32,
                    expires_at,
                },
            ))
            .await;
    }

    pub async fn fail(&self, command_id: Uuid, error: String) {
        let mut map = self.entries.write().await;
        if let Some(entry) = map.get_mut(&command_id) {
            if let Some(in_flight) = entry.in_flight.take() {
                *in_flight.result.lock() = Some(Err(error));
                in_flight.notify.notify_waiters();
            }
        }
    }

    pub fn load_persisted(&self) {
        // Best-effort warm cache from SQLite on startup is optional for v1.
        debug!("command dedup initialized");
    }

    fn prune_locked(
        &self,
        map: &mut std::collections::HashMap<Uuid, DedupEntry>,
        now: chrono::DateTime<Utc>,
    ) {
        map.retain(|_, v| v.expires_at > now);
        if map.len() > self.max_entries {
            let excess = map.len() - self.max_entries;
            let keys: Vec<_> = map.keys().take(excess).copied().collect();
            for k in keys {
                map.remove(&k);
            }
            warn!(excess, "command dedup cache pruned");
        }
    }
}

#[derive(Debug)]
pub enum DedupAction {
    Process(Arc<InFlight>),
    Wait(Arc<InFlight>),
    Cached(CachedCommandResult),
}

impl InFlight {
    pub async fn wait(&self) -> Result<CachedCommandResult, String> {
        loop {
            if let Some(result) = self.result.lock().clone() {
                return result;
            }
            self.notify.notified().await;
        }
    }
}

pub fn verify_command_signature(
    cmd: &EnsureRelayConnectionCommand,
    relay_key: &VerifyingKey,
) -> Result<(), ProtocolError> {
    cmd.verify(relay_key)
}
