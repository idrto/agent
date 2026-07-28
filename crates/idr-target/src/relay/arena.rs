use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use tokio::sync::Notify;
use tracing::warn;

use crate::quic::RelayQuicConnection;
use crate::relay::descriptor::{ConnectionAuthorization, GenerationalHandle, RelayId, StableRelayDescriptor};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayConnectionStateKind {
    Connecting,
    Active,
    Draining,
    Failed,
}

#[derive(Debug)]
pub enum RelayConnectionState {
    Connecting {
        attempt: SharedConnectionAttempt,
        started_at: Instant,
    },
    Active,
    Draining,
    Failed {
        retry_after: Instant,
        failure_count: u32,
    },
}

pub struct RelayConnectionEntry {
    pub relay_id: RelayId,
    pub generation: u32,
    pub descriptor: StableRelayDescriptor,
    pub endpoint: Option<SocketAddr>,
    pub state: RelayConnectionState,
    pub last_activity_at: Instant,
    pub idle_deadline: Option<Instant>,
    pub connection_epoch: u64,
    pub authorization: Option<ConnectionAuthorization>,
    pub quic: Option<Arc<RelayQuicConnection>>,
    pub open_streams: u32,
}

struct SharedConnectionAttemptInner {
    notify: Notify,
    done: parking_lot::Mutex<Option<Result<Arc<RelayConnection>, AttemptError>>>,
}

#[derive(Clone)]
pub struct SharedConnectionAttempt(Arc<SharedConnectionAttemptInner>);

#[derive(Debug, Clone)]
pub struct AttemptError {
    pub message: String,
}

pub struct RelayConnection {
    pub handle: GenerationalHandle,
    pub entry: RwLock<RelayConnectionEntry>,
}

impl std::fmt::Debug for SharedConnectionAttempt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedConnectionAttempt").finish_non_exhaustive()
    }
}

impl SharedConnectionAttempt {
    pub fn new() -> Self {
        Self(Arc::new(SharedConnectionAttemptInner {
            notify: Notify::new(),
            done: parking_lot::Mutex::new(None),
        }))
    }

    pub async fn wait(&self) -> Result<Arc<RelayConnection>, AttemptError> {
        loop {
            if let Some(result) = self.0.done.lock().clone() {
                return result;
            }
            self.0.notify.notified().await;
        }
    }

    pub fn complete(&self, result: Result<Arc<RelayConnection>, AttemptError>) {
        *self.0.done.lock() = Some(result);
        self.0.notify.notify_waiters();
    }
}

impl Default for SharedConnectionAttempt {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayConnection {
    pub fn state_kind(&self) -> RelayConnectionStateKind {
        match &self.entry.read().state {
            RelayConnectionState::Connecting { .. } => RelayConnectionStateKind::Connecting,
            RelayConnectionState::Active => RelayConnectionStateKind::Active,
            RelayConnectionState::Draining => RelayConnectionStateKind::Draining,
            RelayConnectionState::Failed { .. } => RelayConnectionStateKind::Failed,
        }
    }

    pub fn refresh_activity(&self) {
        let mut entry = self.entry.write();
        entry.last_activity_at = Instant::now();
        entry.idle_deadline = None;
    }

    pub fn stream_opened(&self) {
        let mut entry = self.entry.write();
        entry.open_streams = entry.open_streams.saturating_add(1);
        entry.last_activity_at = Instant::now();
        entry.idle_deadline = None;
    }

    pub fn stream_closed(&self) {
        let mut entry = self.entry.write();
        entry.open_streams = entry.open_streams.saturating_sub(1);
        entry.last_activity_at = Instant::now();
    }

    pub fn open_stream_count(&self) -> u32 {
        self.entry.read().open_streams
    }
}

/// Generational arena backing the open-addressing connection table.
pub struct ConnectionArena {
    entries: Vec<Option<Arc<RelayConnection>>>,
    generations: Vec<u32>,
    free_list: Vec<u32>,
    next_index: u32,
}

impl ConnectionArena {
    pub fn new(initial: usize) -> Self {
        Self {
            entries: vec![None; initial.max(16)],
            generations: vec![2; initial.max(16)],
            free_list: Vec::new(),
            next_index: 0,
        }
    }

    pub fn allocate(
        &mut self,
        relay_id: RelayId,
        entry: RelayConnectionEntry,
    ) -> (GenerationalHandle, Arc<RelayConnection>) {
        let index = if let Some(idx) = self.free_list.pop() {
            idx
        } else {
            let idx = self.next_index;
            self.next_index += 1;
            if idx as usize >= self.entries.len() {
                self.grow();
            }
            idx
        };
        let generation = self.generations[index as usize];
        let handle = GenerationalHandle::encode(index, generation);
        let conn = Arc::new(RelayConnection {
            handle,
            entry: RwLock::new(entry),
        });
        self.entries[index as usize] = Some(conn.clone());
        let _ = relay_id;
        (handle, conn)
    }

    pub fn get(&self, handle: GenerationalHandle) -> Option<Arc<RelayConnection>> {
        let (index, generation) = handle.decode();
        if index as usize >= self.entries.len() {
            return None;
        }
        if self.generations[index as usize] != generation {
            return None;
        }
        self.entries[index as usize].clone()
    }

    pub fn free(&mut self, handle: GenerationalHandle) -> bool {
        let (index, generation) = handle.decode();
        let idx = index as usize;
        if idx >= self.entries.len() || self.generations[idx] != generation {
            return false;
        }
        self.entries[idx] = None;
        self.generations[idx] = self.generations[idx].wrapping_add(1).max(2);
        self.free_list.push(index);
        true
    }

    fn grow(&mut self) {
        let new_len = self.entries.len().max(16) * 2;
        self.entries.resize(new_len, None);
        self.generations.resize(new_len, 2);
    }
}

pub struct RelayConnectionStore {
    pub table: crate::relay::table::RelayConnectionTable,
    pub arena: ConnectionArena,
    pub by_relay_id: HashMap<RelayId, GenerationalHandle>,
}

impl RelayConnectionStore {
    pub fn new(table_capacity: usize) -> Self {
        Self {
            table: crate::relay::table::RelayConnectionTable::with_capacity(table_capacity),
            arena: ConnectionArena::new(table_capacity),
            by_relay_id: HashMap::new(),
        }
    }

    pub fn lookup(&self, relay_id: &str) -> Option<(GenerationalHandle, Arc<RelayConnection>)> {
        let (found, _probes) = self.table.lookup_probes(relay_id);
        let (_slot, handle) = found?;
        let conn = self.arena.get(handle)?;
        if conn.entry.read().relay_id != relay_id {
            warn!(relay_id, "relay table hash collision mismatch");
            return None;
        }
        Some((handle, conn))
    }

    pub fn insert(
        &mut self,
        relay_id: RelayId,
        entry: RelayConnectionEntry,
    ) -> (GenerationalHandle, Arc<RelayConnection>) {
        let (handle, conn) = self.arena.allocate(relay_id.clone(), entry);
        self.table.insert_slot(relay_id.clone(), handle);
        self.by_relay_id.insert(relay_id, handle);
        (handle, conn)
    }

    pub fn remove(&mut self, relay_id: &str) -> bool {
        let Some((handle, _)) = self.lookup(relay_id) else {
            return false;
        };
        self.table.remove_slot(relay_id);
        self.by_relay_id.remove(relay_id);
        self.arena.free(handle)
    }
}
