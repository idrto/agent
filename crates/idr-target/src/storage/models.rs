use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct RelayConnectionHistoryRow {
    pub relay_id: String,
    pub last_ipv4: Option<String>,
    pub last_ipv6: Option<String>,
    pub last_port: u16,
    pub last_success_family: Option<i32>,
    pub last_connected_at: Option<i64>,
    pub last_disconnected_at: Option<i64>,
    pub consecutive_failures: i32,
    pub retry_after: Option<i64>,
    pub descriptor_generation: i64,
}

#[derive(Debug, Clone)]
pub struct PresenceDiscoveryCacheRow {
    pub generation: u64,
    pub valid_until: DateTime<Utc>,
    pub canonical_json: Vec<u8>,
    pub signature: Vec<u8>,
    pub fetched_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ProcessedCommandRow {
    pub command_id: Uuid,
    pub content_digest: [u8; 32],
    pub result_code: i32,
    pub expires_at: DateTime<Utc>,
}
