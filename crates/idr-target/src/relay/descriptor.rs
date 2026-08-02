use std::fmt;

use idr_protocol::signaling::RelayDescriptor;

pub type RelayId = String;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StableRelayDescriptor {
    pub relay_id: RelayId,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub port: u16,
    pub server_name: String,
    pub alpn: String,
    pub region: Option<String>,
}

impl From<RelayDescriptor> for StableRelayDescriptor {
    fn from(d: RelayDescriptor) -> Self {
        Self {
            relay_id: d.relay_id,
            ipv4: d.ipv4,
            ipv6: d.ipv6,
            port: d.port,
            server_name: d.server_name,
            alpn: d.alpn,
            region: d.region,
        }
    }
}

impl From<StableRelayDescriptor> for RelayDescriptor {
    fn from(d: StableRelayDescriptor) -> Self {
        Self {
            relay_id: d.relay_id,
            ipv4: d.ipv4,
            ipv6: d.ipv6,
            port: d.port,
            server_name: d.server_name,
            alpn: d.alpn,
            region: d.region,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionAuthorization {
    pub session_id: uuid::Uuid,
    pub target_fqhn: String,
    pub target_identity: String,
    pub connection_token: String,
    pub connection_epoch: u64,
    pub command_id: uuid::Uuid,
    /// Relay-issued ensure command expiry; used for mobility warm reconnect.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Encoded generational arena handle stored in table slots.
/// Sentinels 0 = EMPTY and 1 = TOMBSTONE are reserved at the table layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GenerationalHandle(u64);

impl GenerationalHandle {
    pub const EMPTY: u64 = 0;
    pub const TOMBSTONE: u64 = 1;

    pub fn encode(index: u32, generation: u32) -> Self {
        debug_assert!(
            generation >= 2,
            "generation 0/1 reserved for table sentinels"
        );
        Self((u64::from(generation) << 32) | u64::from(index))
    }

    pub fn decode(self) -> (u32, u32) {
        let index = (self.0 & 0xFFFF_FFFF) as u32;
        let generation = (self.0 >> 32) as u32;
        (index, generation)
    }

    pub fn raw(self) -> u64 {
        self.0
    }

    pub fn from_raw(raw: u64) -> Option<Self> {
        if raw <= Self::TOMBSTONE {
            None
        } else {
            Some(Self(raw))
        }
    }
}

impl fmt::Display for GenerationalHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (idx, gen) = self.decode();
        write!(f, "handle(gen={gen},idx={idx})")
    }
}

/// SplitMix64 finalizer over a stable string hash of relay_id.
pub fn hash_relay_id(relay_id: &str) -> u64 {
    let mut h = relay_id
        .as_bytes()
        .iter()
        .fold(0xcbf29ce484222325u64, |acc, &b| {
            (acc ^ u64::from(b)).wrapping_mul(0x100000001b3)
        });
    splitmix64(h)
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E3779B97F4A7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D049BB133111EB);
    x ^ (x >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(hash_relay_id("relay-a"), hash_relay_id("relay-a"));
        assert_ne!(hash_relay_id("relay-a"), hash_relay_id("relay-b"));
    }

    #[test]
    fn handle_roundtrip() {
        let h = GenerationalHandle::encode(42, 7);
        let (idx, gen) = h.decode();
        assert_eq!(idx, 42);
        assert_eq!(gen, 7);
    }
}
