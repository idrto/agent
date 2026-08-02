use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use chrono::Utc;
use parking_lot::Mutex;
use tracing::{debug, info, warn};

use crate::config::{NginxConfig, RelayConnectionsConfig};
use crate::relay::arena::{
    AttemptError, RelayConnection, RelayConnectionEntry, RelayConnectionState,
    RelayConnectionStateKind, RelayConnectionStore, SharedConnectionAttempt,
};
use crate::relay::connector::RelayConnector;
use crate::relay::descriptor::{
    ConnectionAuthorization, GenerationalHandle, StableRelayDescriptor,
};
use crate::relay::idle::IdleScheduler;
use crate::relay::readiness::RelayReadiness;
use crate::relay::retry::retry_after_from_now;
use crate::storage::models::RelayConnectionHistoryRow;
use crate::storage::writer::{StorageCommand, StorageWriter};
use crate::telemetry::Metrics;

#[derive(Clone)]
struct CachedRelayAuth {
    descriptor: StableRelayDescriptor,
    auth: ConnectionAuthorization,
    expires_at: chrono::DateTime<Utc>,
}

pub struct RelayConnectionManager {
    store: Arc<tokio::sync::Mutex<RelayConnectionStore>>,
    connector: RelayConnector,
    cfg: RelayConnectionsConfig,
    metrics: Metrics,
    idle: Arc<IdleScheduler>,
    writer: StorageWriter,
    nginx: Option<Arc<NginxConfig>>,
    readiness: Arc<RelayReadiness>,
    expected_fqhn: String,
    warm_auth: Mutex<Option<CachedRelayAuth>>,
}

impl RelayConnectionManager {
    pub fn new(
        cfg: RelayConnectionsConfig,
        connector: RelayConnector,
        metrics: Metrics,
        idle: Arc<IdleScheduler>,
        writer: StorageWriter,
        nginx: Option<Arc<NginxConfig>>,
        readiness: Arc<RelayReadiness>,
        expected_fqhn: String,
    ) -> Self {
        metrics
            .relay_table_capacity
            .set(cfg.initial_table_capacity as i64);
        Self {
            store: Arc::new(tokio::sync::Mutex::new(RelayConnectionStore::new(
                cfg.initial_table_capacity,
            ))),
            connector,
            cfg,
            metrics,
            idle,
            writer,
            nginx,
            readiness,
            expected_fqhn,
            warm_auth: Mutex::new(None),
        }
    }

    pub fn refresh_network_caps(self: &Arc<Self>, caps: crate::network::NetworkCapabilities) {
        let changed = self.connector.update_network_caps(caps);
        if !changed || !self.readiness.is_ready() {
            return;
        }
        let mgr = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(err) = mgr.connector.rebind_for_network_change() {
                warn!(error = %err, "relay QUIC rebind after network change failed");
                return;
            }
            mgr.nudge_active_relay_connections().await;
        });
    }

    async fn nudge_active_relay_connections(&self) {
        let store = self.store.lock().await;
        let active: Vec<_> = store
            .table
            .iter_active_relay_ids()
            .filter_map(|relay_id| {
                store
                    .lookup(relay_id)
                    .and_then(|(_, conn)| conn.entry.read().quic.clone())
            })
            .collect();
        drop(store);
        let count = active.len();
        for quic in active {
            quic.nudge_path_probe();
        }
        if count > 0 {
            debug!(
                count,
                "nudged active relay QUIC connections for path migration"
            );
        }
    }

    /// After Presence re-register, rebuild Relay QUIC using the last ensure credentials.
    pub fn spawn_warm_reconnect(self: &Arc<Self>) {
        if self.readiness.is_ready() {
            return;
        }
        let cached = self.warm_auth.lock().clone();
        let Some(cached) = cached else {
            return;
        };
        if Utc::now() >= cached.expires_at {
            debug!("skipping warm relay reconnect — cached token expired");
            return;
        }
        let mgr = Arc::clone(self);
        tokio::spawn(async move {
            debug!(relay_id = %cached.descriptor.relay_id, "mobility warm relay reconnect");
            if let Err(err) = mgr.get_or_connect(cached.descriptor, cached.auth).await {
                warn!(error = %err, "mobility warm relay reconnect failed");
            }
        });
    }

    fn cache_warm_auth(&self, descriptor: &StableRelayDescriptor, auth: &ConnectionAuthorization) {
        let Some(expires_at) = auth.expires_at else {
            return;
        };
        if Utc::now() >= expires_at {
            return;
        }
        *self.warm_auth.lock() = Some(CachedRelayAuth {
            descriptor: descriptor.clone(),
            auth: auth.clone(),
            expires_at,
        });
    }

    pub fn readiness(&self) -> Arc<RelayReadiness> {
        self.readiness.clone()
    }

    pub async fn get_or_connect(
        self: &Arc<Self>,
        descriptor: StableRelayDescriptor,
        auth: ConnectionAuthorization,
    ) -> Result<Arc<RelayConnection>> {
        let relay_id = descriptor.relay_id.clone();

        loop {
            let mut store = self.store.lock().await;
            self.sync_table_metrics(&store);

            if let Some((handle, conn)) = store.lookup(&relay_id) {
                match conn.state_kind() {
                    RelayConnectionStateKind::Active => {
                        // Dead QUIC may still be marked Active until supervisor runs —
                        // if quic handle is gone, treat as failed.
                        if conn.entry.read().quic.is_none() {
                            store.remove(&relay_id);
                        } else {
                            self.idle.cancel(handle);
                            conn.refresh_activity();
                            return Ok(conn);
                        }
                    }
                    RelayConnectionStateKind::Connecting => {
                        let attempt = match &conn.entry.read().state {
                            RelayConnectionState::Connecting { attempt, .. } => attempt.clone(),
                            _ => unreachable!(),
                        };
                        drop(store);
                        return attempt.wait().await.map_err(|e| anyhow::anyhow!(e.message));
                    }
                    RelayConnectionStateKind::Failed => {
                        let retry_after = match &conn.entry.read().state {
                            RelayConnectionState::Failed { retry_after, .. } => *retry_after,
                            _ => Instant::now(),
                        };
                        if Instant::now() < retry_after {
                            return Err(anyhow::anyhow!("relay connection in backoff"));
                        }
                        store.remove(&relay_id);
                    }
                    RelayConnectionStateKind::Draining => {
                        store.remove(&relay_id);
                    }
                }
            }

            if self.active_count(&store) >= self.cfg.max_active {
                self.evict_lru_idle(&mut store).await;
            }

            let attempt = SharedConnectionAttempt::new();
            let entry = RelayConnectionEntry {
                relay_id: relay_id.clone(),
                generation: 0,
                descriptor: descriptor.clone(),
                endpoint: None,
                state: RelayConnectionState::Connecting {
                    attempt: attempt.clone(),
                    started_at: Instant::now(),
                },
                last_activity_at: Instant::now(),
                idle_deadline: None,
                connection_epoch: auth.connection_epoch,
                authorization: Some(auth.clone()),
                quic: None,
                open_streams: 0,
            };
            let (_handle, conn) = store.insert(relay_id.clone(), entry);
            drop(store);

            let connect_result = self.connector.connect(&descriptor, &auth).await;

            let mut store = self.store.lock().await;
            let Some((handle, conn)) = store.lookup(&relay_id) else {
                return Err(anyhow::anyhow!(
                    "connection entry disappeared during connect"
                ));
            };

            match connect_result {
                Ok((quic, endpoint, family)) => {
                    {
                        let mut e = conn.entry.write();
                        e.state = RelayConnectionState::Active;
                        e.endpoint = Some(endpoint);
                        e.quic = Some(quic.clone());
                        e.last_activity_at = Instant::now();
                    }
                    self.persist_success(&descriptor, endpoint, family).await;
                    if let Some(nginx) = &self.nginx {
                        if nginx.tunnel_enabled {
                            crate::tunnel::spawn_on_connection(
                                quic.clone(),
                                nginx.clone(),
                                self.expected_fqhn.clone(),
                                conn.clone(),
                            );
                        }
                    }
                    self.spawn_connection_supervisor(relay_id.clone(), quic);
                    self.readiness.on_connected();
                    self.cache_warm_auth(&descriptor, &auth);
                    attempt.complete(Ok(conn.clone()));
                    self.idle.cancel(handle);
                    return Ok(conn);
                }
                Err(err) => {
                    let failure_count = 1;
                    let retry_after = retry_after_from_now(
                        self.cfg.failed_retry_initial(),
                        self.cfg.failed_retry_max(),
                        failure_count,
                    );
                    {
                        let mut e = conn.entry.write();
                        e.state = RelayConnectionState::Failed {
                            retry_after,
                            failure_count,
                        };
                    }
                    attempt.complete(Err(AttemptError {
                        message: err.to_string(),
                    }));
                    return Err(err);
                }
            }
        }
    }

    fn spawn_connection_supervisor(
        self: &Arc<Self>,
        relay_id: String,
        quic: Arc<crate::quic::RelayQuicConnection>,
    ) {
        let mgr = Arc::clone(self);
        tokio::spawn(async move {
            let reason = quic.connection().closed().await;
            warn!(%relay_id, ?reason, "relay QUIC closed — clearing Active entry");
            mgr.mark_connection_dead(&relay_id).await;
        });
    }

    async fn mark_connection_dead(&self, relay_id: &str) {
        let mut store = self.store.lock().await;
        if let Some((_, conn)) = store.lookup(relay_id) {
            {
                let mut e = conn.entry.write();
                if matches!(e.state, RelayConnectionState::Active) {
                    e.state = RelayConnectionState::Failed {
                        retry_after: Instant::now(),
                        failure_count: 1,
                    };
                    e.quic = None;
                    self.readiness.on_disconnected();
                }
            }
            store.remove(relay_id);
        }
        self.sync_table_metrics(&store);
    }

    pub async fn close_idle(&self, handle: GenerationalHandle) {
        let relay_id = {
            let store = self.store.lock().await;
            let Some(conn) = store.arena.get(handle) else {
                return;
            };
            let entry = conn.entry.read();
            if entry.open_streams > 0 {
                return;
            }
            entry.relay_id.clone()
        };

        if let Some(quic) = {
            let store = self.store.lock().await;
            store
                .lookup(&relay_id)
                .and_then(|(_, c)| c.entry.read().quic.clone())
        } {
            quic.close(0u32.into(), b"idle timeout");
        }

        {
            let mut store = self.store.lock().await;
            if let Some((_, conn)) = store.lookup(&relay_id) {
                if matches!(conn.state_kind(), RelayConnectionStateKind::Active) {
                    self.readiness.on_disconnected();
                }
            }
            store.remove(&relay_id);
        }
        self.idle.on_closed();
        debug!(relay_id, "closed idle relay connection");
    }

    pub fn spawn_idle_worker(self: &Arc<Self>) {
        let mgr = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                let handle = mgr.idle.next_expired().await;
                mgr.close_idle(handle).await;
            }
        });
    }

    async fn evict_lru_idle(&self, store: &mut RelayConnectionStore) {
        let mut candidates: Vec<(Instant, String)> = store
            .table
            .iter_active_relay_ids()
            .filter_map(|relay_id| {
                store.lookup(relay_id).and_then(|(_, conn)| {
                    let entry = conn.entry.read();
                    if entry.open_streams == 0
                        && matches!(entry.state, RelayConnectionState::Active)
                    {
                        Some((entry.last_activity_at, relay_id.to_string()))
                    } else {
                        None
                    }
                })
            })
            .collect();
        candidates.sort_by_key(|(t, _)| *t);
        if let Some((_, relay_id)) = candidates.first() {
            info!(relay_id, "evicting LRU idle relay connection");
            if let Some(quic) = store
                .lookup(relay_id)
                .and_then(|(_, c)| c.entry.read().quic.clone())
            {
                quic.close(0u32.into(), b"capacity eviction");
            }
            if let Some((_, conn)) = store.lookup(relay_id) {
                if matches!(conn.state_kind(), RelayConnectionStateKind::Active) {
                    self.readiness.on_disconnected();
                }
            }
            store.remove(relay_id);
        }
    }

    fn active_count(&self, store: &RelayConnectionStore) -> usize {
        store
            .by_relay_id
            .values()
            .filter_map(|handle| store.arena.get(*handle))
            .filter(|conn| {
                matches!(conn.state_kind(), RelayConnectionStateKind::Active)
                    && conn.entry.read().quic.is_some()
            })
            .count()
    }

    fn sync_table_metrics(&self, store: &RelayConnectionStore) {
        self.metrics
            .relay_table_capacity
            .set(store.table.capacity() as i64);
        self.metrics
            .relay_table_tombstones
            .set(store.table.tombstones() as i64);
    }

    async fn persist_success(
        &self,
        descriptor: &StableRelayDescriptor,
        endpoint: std::net::SocketAddr,
        family: i32,
    ) {
        let (v4, v6) = match endpoint {
            std::net::SocketAddr::V4(a) => (Some(a.ip().to_string()), None),
            std::net::SocketAddr::V6(a) => (None, Some(a.ip().to_string())),
        };
        let now = chrono::Utc::now().timestamp();
        let row = RelayConnectionHistoryRow {
            relay_id: descriptor.relay_id.clone(),
            last_ipv4: v4,
            last_ipv6: v6,
            last_port: endpoint.port(),
            last_success_family: Some(family),
            last_connected_at: Some(now),
            last_disconnected_at: None,
            consecutive_failures: 0,
            retry_after: None,
            descriptor_generation: 0,
        };
        let _ = self
            .writer
            .send(StorageCommand::UpsertRelayHistory(row))
            .await;
    }
}
