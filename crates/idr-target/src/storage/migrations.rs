use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::Connection;

pub fn run_migrations(conn: &Connection) -> Result<()> {
    let sql = include_str!("../../migrations/001_initial.sql");
    conn.execute_batch(sql).context("apply initial migration")?;
    let sql2 = include_str!("../../migrations/002_webrtc.sql");
    conn.execute_batch(sql2).context("apply webrtc migration")?;
    Ok(())
}

pub fn migration_version(conn: &Connection) -> Result<i64> {
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='relay_connection_history'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);
    Ok(if exists > 0 { 1 } else { 0 })
}

pub fn migrations_dir() -> &'static Path {
    Path::new("migrations")
}
