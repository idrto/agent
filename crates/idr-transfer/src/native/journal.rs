//! Per-transfer resume journal (SQLite, inside the transfer's staging directory).
//!
//! WAL with `synchronous = NORMAL`: each write is atomic and survives a process
//! crash; a power loss may drop the last few rows, which only makes the receiver
//! advertise less (resend), never more. Partial data is fsynced *before* its
//! checkpoint row is written, so a recorded checkpoint never exceeds persisted
//! data. Block hashes let `prepare` prove the bytes before advertising them.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};

pub const FILE: &str = "journal.db";

pub struct Journal {
    conn: Connection,
}

/// Per-entry row: `verified` entries are committed; others have block checkpoints.
pub struct EntryRow {
    pub id: u32,
    pub verified: bool,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

type R<T> = rusqlite::Result<T>;

impl Journal {
    fn connect(path: &Path) -> R<Connection> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS entry (
                 id INTEGER PRIMARY KEY, verified INTEGER NOT NULL DEFAULT 0,
                 checkpoint INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE IF NOT EXISTS block (
                 entry INTEGER NOT NULL, end_offset INTEGER NOT NULL, sha BLOB NOT NULL,
                 PRIMARY KEY (entry, end_offset));",
        )?;
        Ok(conn)
    }

    pub fn create(path: &Path, digest: &[u8; 32], manifest: &[u8]) -> R<Self> {
        let j = Self {
            conn: Self::connect(path)?,
        };
        j.conn.execute(
            "INSERT INTO meta (k, v) VALUES ('digest', ?1), ('manifest', ?2)",
            params![&digest[..], manifest],
        )?;
        j.touch()?;
        Ok(j)
    }

    /// An existing journal and the digest it was created for.
    pub fn open(path: &Path) -> R<(Self, Vec<u8>)> {
        let conn = Self::connect(path)?;
        let digest: Vec<u8> =
            conn.query_row("SELECT v FROM meta WHERE k = 'digest'", [], |r| r.get(0))?;
        Ok((Self { conn }, digest))
    }

    pub fn touch(&self) -> R<()> {
        self.set_meta("updated_at", &now().to_be_bytes())
    }

    pub fn set_meta(&self, k: &str, v: &[u8]) -> R<()> {
        self.conn.execute(
            "INSERT INTO meta (k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = ?2",
            params![k, v],
        )?;
        Ok(())
    }

    pub fn meta(&self, k: &str) -> R<Option<Vec<u8>>> {
        self.conn
            .query_row("SELECT v FROM meta WHERE k = ?1", [k], |r| r.get(0))
            .optional()
    }

    /// Seconds since the epoch of the last write, for retention.
    pub fn updated_at(path: &Path) -> Option<i64> {
        let conn = Connection::open(path).ok()?;
        let v: Vec<u8> = conn
            .query_row("SELECT v FROM meta WHERE k = 'updated_at'", [], |r| r.get(0))
            .ok()?;
        Some(i64::from_be_bytes(v.try_into().ok()?))
    }

    pub fn entries(&self) -> R<Vec<EntryRow>> {
        let mut st = self
            .conn
            .prepare("SELECT id, verified FROM entry ORDER BY id")?;
        let rows = st.query_map([], |r| {
            Ok(EntryRow {
                id: r.get::<_, i64>(0)? as u32,
                verified: r.get::<_, i64>(1)? != 0,
            })
        })?;
        rows.collect()
    }

    /// Block hashes of `entry`, ascending by end offset.
    pub fn blocks(&self, entry: u32) -> R<Vec<(u64, [u8; 32])>> {
        let mut st = self
            .conn
            .prepare("SELECT end_offset, sha FROM block WHERE entry = ?1 ORDER BY end_offset")?;
        let rows = st.query_map([entry], |r| {
            let sha: Vec<u8> = r.get(1)?;
            Ok((
                r.get::<_, i64>(0)? as u64,
                sha.try_into().unwrap_or([0; 32]),
            ))
        })?;
        rows.collect()
    }

    /// Record a durable checkpoint: bytes up to `end` hash (since the previous
    /// checkpoint) to `sha`. Call only after the data is fsynced.
    pub fn checkpoint(&self, entry: u32, end: u64, sha: &[u8; 32]) -> R<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT OR REPLACE INTO block (entry, end_offset, sha) VALUES (?1, ?2, ?3)",
            params![entry, end as i64, &sha[..]],
        )?;
        tx.execute(
            "INSERT INTO entry (id, checkpoint) VALUES (?1, ?2)
             ON CONFLICT(id) DO UPDATE SET checkpoint = ?2",
            params![entry, end as i64],
        )?;
        tx.commit()?;
        self.touch()
    }

    /// Forget checkpoints past `end` (unverifiable data was cut off).
    pub fn truncate(&self, entry: u32, end: u64) -> R<()> {
        self.conn.execute(
            "DELETE FROM block WHERE entry = ?1 AND end_offset > ?2",
            params![entry, end as i64],
        )?;
        self.conn.execute(
            "UPDATE entry SET checkpoint = ?2 WHERE id = ?1",
            params![entry, end as i64],
        )?;
        Ok(())
    }

    pub fn verified(&self, entry: u32) -> R<()> {
        self.conn.execute(
            "INSERT INTO entry (id, verified) VALUES (?1, 1)
             ON CONFLICT(id) DO UPDATE SET verified = 1",
            [entry],
        )?;
        self.conn.execute("DELETE FROM block WHERE entry = ?1", [entry])?;
        self.touch()
    }

    /// Start `entry` over (it failed and its data was removed).
    pub fn reset(&self, entry: u32) -> R<()> {
        self.conn.execute("DELETE FROM block WHERE entry = ?1", [entry])?;
        self.conn.execute("DELETE FROM entry WHERE id = ?1", [entry])?;
        Ok(())
    }
}
