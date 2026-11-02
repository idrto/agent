//! Resource limits, enforced by the engine regardless of client.

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_entries: u32,
    pub max_depth: usize,
    pub max_component_bytes: usize,
    pub max_path_bytes: usize,
    pub max_manifest_bytes: u32,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    /// Files whose `EntryEnd` may be outstanding before the sender waits for results.
    pub max_pipelined_files: usize,
    /// The receiver persists (and later advertises) progress at these boundaries.
    pub checkpoint_bytes: u64,
    /// Waiting for the receiver's decision (consent can take a while).
    pub offer_timeout: Duration,
    /// Waiting for a header, manifest piece or data stream.
    pub step_timeout: Duration,
    /// No data while not paused.
    pub stall_timeout: Duration,
    pub progress_interval: Duration,
    /// `EntryFailed` events emitted per transfer; later failures only count.
    pub max_failure_events: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_depth: 64,
            max_component_bytes: 255,
            max_path_bytes: 1024,
            max_manifest_bytes: 16 * 1024 * 1024,
            max_file_bytes: 64 * 1024 * 1024 * 1024,
            max_total_bytes: 256 * 1024 * 1024 * 1024,
            max_pipelined_files: 8,
            checkpoint_bytes: 4 * 1024 * 1024,
            offer_timeout: Duration::from_secs(300),
            step_timeout: Duration::from_secs(30),
            stall_timeout: Duration::from_secs(60),
            progress_interval: Duration::from_millis(250),
            max_failure_events: 32,
        }
    }
}
