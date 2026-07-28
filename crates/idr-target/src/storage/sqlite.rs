use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use uuid::Uuid;

use crate::config::SqliteConfig;
use crate::storage::migrations;
use crate::storage::models::{
    PresenceDiscoveryCacheRow, ProcessedCommandRow, RelayConnectionHistoryRow,
};

#[derive(Clone)]
pub struct Storage {
    conn: Arc<Mutex<Connection>>,
}

impl Storage {
    pub fn open(cfg: &SqliteConfig) -> Result<Self> {
        if let Some(parent) = cfg.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create sqlite dir {}", parent.display()))?;
            }
        }
        let conn = Connection::open(&cfg.path)
            .with_context(|| format!("open sqlite {}", cfg.path.display()))?;
        apply_pragmas(&conn, cfg)?;
        migrations::run_migrations(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn in_memory(cfg: &SqliteConfig) -> Result<Self> {
        let conn = Connection::open_in_memory().context("open in-memory sqlite")?;
        apply_pragmas(&conn, cfg)?;
        migrations::run_migrations(&conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn connection(&self) -> Arc<Mutex<Connection>> {
        self.conn.clone()
    }

    pub fn load_relay_history(&self, relay_id: &str) -> Result<Option<RelayConnectionHistoryRow>> {
        let conn = self.conn.lock().expect("sqlite lock");
        let mut stmt = conn.prepare(
            "SELECT relay_id, last_ipv4, last_ipv6, last_port, last_success_family,
                    last_connected_at, last_disconnected_at, consecutive_failures,
                    retry_after, descriptor_generation
             FROM relay_connection_history WHERE relay_id = ?1",
        )?;
        let mut rows = stmt.query(params![relay_id])?;
        if let Some(row) = rows.next()? {
            return Ok(Some(RelayConnectionHistoryRow {
                relay_id: row.get(0)?,
                last_ipv4: row.get(1)?,
                last_ipv6: row.get(2)?,
                last_port: row.get(3)?,
                last_success_family: row.get(4)?,
                last_connected_at: row.get(5)?,
                last_disconnected_at: row.get(6)?,
                consecutive_failures: row.get(7)?,
                retry_after: row.get(8)?,
                descriptor_generation: row.get(9)?,
            }));
        }
        Ok(None)
    }

    pub fn upsert_relay_history(&self, row: &RelayConnectionHistoryRow) -> Result<()> {
        let conn = self.conn.lock().expect("sqlite lock");
        conn.execute(
            "INSERT INTO relay_connection_history (
                relay_id, last_ipv4, last_ipv6, last_port, last_success_family,
                last_connected_at, last_disconnected_at, consecutive_failures,
                retry_after, descriptor_generation
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            ON CONFLICT(relay_id) DO UPDATE SET
                last_ipv4 = excluded.last_ipv4,
                last_ipv6 = excluded.last_ipv6,
                last_port = excluded.last_port,
                last_success_family = excluded.last_success_family,
                last_connected_at = excluded.last_connected_at,
                last_disconnected_at = excluded.last_disconnected_at,
                consecutive_failures = excluded.consecutive_failures,
                retry_after = excluded.retry_after,
                descriptor_generation = excluded.descriptor_generation",
            params![
                row.relay_id,
                row.last_ipv4,
                row.last_ipv6,
                row.last_port,
                row.last_success_family,
                row.last_connected_at,
                row.last_disconnected_at,
                row.consecutive_failures,
                row.retry_after,
                row.descriptor_generation,
            ],
        )?;
        Ok(())
    }

    pub fn load_discovery_cache(&self) -> Result<Option<PresenceDiscoveryCacheRow>> {
        let conn = self.conn.lock().expect("sqlite lock");
        let mut stmt = conn.prepare(
            "SELECT generation, valid_until, canonical_json, signature, fetched_at
             FROM presence_discovery_cache WHERE singleton = 1",
        )?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let valid_until_ts: i64 = row.get(1)?;
            let fetched_at_ts: i64 = row.get(4)?;
            return Ok(Some(PresenceDiscoveryCacheRow {
                generation: row.get(0)?,
                valid_until: ts_to_datetime(valid_until_ts),
                canonical_json: row.get(2)?,
                signature: row.get(3)?,
                fetched_at: ts_to_datetime(fetched_at_ts),
            }));
        }
        Ok(None)
    }

    pub fn upsert_discovery_cache(&self, row: &PresenceDiscoveryCacheRow) -> Result<()> {
        let conn = self.conn.lock().expect("sqlite lock");
        conn.execute(
            "INSERT INTO presence_discovery_cache (
                singleton, generation, valid_until, canonical_json, signature, fetched_at
            ) VALUES (1, ?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(singleton) DO UPDATE SET
                generation = excluded.generation,
                valid_until = excluded.valid_until,
                canonical_json = excluded.canonical_json,
                signature = excluded.signature,
                fetched_at = excluded.fetched_at",
            params![
                row.generation as i64,
                datetime_to_ts(row.valid_until),
                row.canonical_json,
                row.signature,
                datetime_to_ts(row.fetched_at),
            ],
        )?;
        Ok(())
    }

    pub fn load_processed_command(&self, command_id: &Uuid) -> Result<Option<ProcessedCommandRow>> {
        let conn = self.conn.lock().expect("sqlite lock");
        let mut stmt = conn.prepare(
            "SELECT command_id, content_digest, result_code, expires_at
             FROM processed_commands WHERE command_id = ?1",
        )?;
        let id_bytes = command_id.as_bytes().to_vec();
        let mut rows = stmt.query(params![id_bytes])?;
        if let Some(row) = rows.next()? {
            let digest: Vec<u8> = row.get(1)?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&digest[..32.min(digest.len())]);
            let expires_at_ts: i64 = row.get(3)?;
            return Ok(Some(ProcessedCommandRow {
                command_id: *command_id,
                content_digest: arr,
                result_code: row.get(2)?,
                expires_at: ts_to_datetime(expires_at_ts),
            }));
        }
        Ok(None)
    }

    pub fn upsert_processed_command(&self, row: &ProcessedCommandRow) -> Result<()> {
        let conn = self.conn.lock().expect("sqlite lock");
        conn.execute(
            "INSERT INTO processed_commands (command_id, content_digest, result_code, expires_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(command_id) DO UPDATE SET
                content_digest = excluded.content_digest,
                result_code = excluded.result_code,
                expires_at = excluded.expires_at",
            params![
                row.command_id.as_bytes().to_vec(),
                row.content_digest.to_vec(),
                row.result_code,
                datetime_to_ts(row.expires_at),
            ],
        )?;
        Ok(())
    }

    pub fn prune_expired_commands(&self, now: DateTime<Utc>) -> Result<usize> {
        let conn = self.conn.lock().expect("sqlite lock");
        let n = conn.execute(
            "DELETE FROM processed_commands WHERE expires_at < ?1",
            params![datetime_to_ts(now)],
        )?;
        Ok(n)
    }
}

fn apply_pragmas(conn: &Connection, cfg: &SqliteConfig) -> Result<()> {
    conn.execute_batch(&format!(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA temp_store = FILE;
         PRAGMA cache_size = -{};
         PRAGMA mmap_size = 0;
         PRAGMA wal_autocheckpoint = {};
         PRAGMA journal_size_limit = {};
         PRAGMA busy_timeout = 5000;
         PRAGMA foreign_keys = ON;
         PRAGMA trusted_schema = OFF;",
        cfg.cache_kib,
        cfg.wal_autocheckpoint_pages,
        cfg.journal_size_limit_bytes,
    ))
    .context("apply sqlite pragmas")?;
    Ok(())
}

fn datetime_to_ts(dt: DateTime<Utc>) -> i64 {
    dt.timestamp()
}

fn ts_to_datetime(ts: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(ts, 0).unwrap_or_else(Utc::now)
}
