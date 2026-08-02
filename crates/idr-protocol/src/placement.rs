use crate::discovery::PresenceServer;
use crate::fqhn;

/// Placement strategy trait — v1 uses dual-mod; future: rendezvous, jump consistent.
pub trait PresencePlacement {
    fn primary_secondary(
        &self,
        fqhn: &str,
        servers: &[PresenceServer],
    ) -> crate::errors::Result<(usize, Option<usize>)>;
}

/// SHA-256 dual-mod placement (v1 default).
///
/// ```text
/// primary   = hash % N
/// secondary = hash % (N - 1)
/// if primary == secondary:
///     secondary = (secondary + 1) % N
/// ```
///
/// Requires `N >= 2`. Secondary is always present.
///
/// **Append safety:** when `presence_servers` grows by one trailing entry, old and new
/// `{primary, secondary}` sets share at least one index (Source/Target discovery epoch skew).
/// Isolated behind this trait for future replacement (e.g. rendezvous) if secondary-load
/// skew at large `N` becomes an issue.
#[derive(Debug, Clone, Copy, Default)]
pub struct ModuloPlacement;

impl PresencePlacement for ModuloPlacement {
    fn primary_secondary(
        &self,
        target_fqhn: &str,
        servers: &[PresenceServer],
    ) -> crate::errors::Result<(usize, Option<usize>)> {
        if servers.len() < 2 {
            return Err(crate::errors::ProtocolError::MalformedDocument(
                "at least two Presence servers are required".into(),
            ));
        }
        let digest = fqhn::fqhn_digest(target_fqhn)?;
        let value = digest_to_u128_be(&digest);
        let n = servers.len() as u128;
        let primary = (value % n) as usize;
        let mut secondary = (value % (n - 1)) as usize;
        if primary == secondary {
            secondary = (secondary + 1) % servers.len();
        }
        Ok((primary, Some(secondary)))
    }
}

fn digest_to_u128_be(digest: &[u8; 32]) -> u128 {
    // Use lower 128 bits for modulo — sufficient for placement
    u128::from_be_bytes(digest[16..32].try_into().unwrap())
}

/// Rendezvous hashing placeholder for future implementation.
#[derive(Debug, Clone, Copy, Default)]
pub struct RendezvousPlacement;

impl PresencePlacement for RendezvousPlacement {
    fn primary_secondary(
        &self,
        _fqhn: &str,
        _servers: &[PresenceServer],
    ) -> crate::errors::Result<(usize, Option<usize>)> {
        Err(crate::errors::ProtocolError::MalformedDocument(
            "rendezvous placement not implemented in v1".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::PresenceServer;

    fn servers(n: usize) -> Vec<PresenceServer> {
        (0..n)
            .map(|i| PresenceServer {
                presence_id: format!("presence-{i:04}"),
                wss_url: format!("wss://203.0.113.{}/v1/presence", 10 + i),
                ipv4: Some(format!("203.0.113.{}", 10 + i)),
                ipv6: None,
                server_name: format!("presence-{i:04}.idr.to"),
                region: "test".into(),
                public_key: String::new(),
                quic_port: Some(4433),
                transports: vec!["quic".into(), "wss".into()],
            })
            .collect()
    }

    const FQHNS: &[&str] = &[
        "device-01.example.idr.to",
        "a.example.idr.to",
        "b.example.idr.to",
        "edge-99.customer.idr.to",
        "z.z.z.idr.to",
    ];

    #[test]
    fn deterministic_primary() {
        let p = ModuloPlacement;
        let s = servers(3);
        let (a, _) = p.primary_secondary("device-01.example.idr.to", &s).unwrap();
        let (b, _) = p.primary_secondary("device-01.example.idr.to", &s).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn requires_at_least_two_servers() {
        let p = ModuloPlacement;
        assert!(p
            .primary_secondary("a.example.idr.to", &servers(0))
            .is_err());
        assert!(p
            .primary_secondary("a.example.idr.to", &servers(1))
            .is_err());
    }

    #[test]
    fn distinct_and_in_range() {
        let p = ModuloPlacement;
        for n in 2..=8 {
            let s = servers(n);
            for fqhn in FQHNS {
                let (primary, secondary) = p.primary_secondary(fqhn, &s).unwrap();
                let secondary = secondary.expect("secondary required");
                assert!(primary < n);
                assert!(secondary < n);
                assert_ne!(primary, secondary);
            }
        }
    }

    #[test]
    fn n2_is_complement_pair() {
        let p = ModuloPlacement;
        let s = servers(2);
        for fqhn in FQHNS {
            let (primary, secondary) = p.primary_secondary(fqhn, &s).unwrap();
            assert_eq!(secondary, Some((primary + 1) % 2));
        }
    }

    #[test]
    fn primary_is_hash_mod_n() {
        let p = ModuloPlacement;
        let s = servers(5);
        for fqhn in FQHNS {
            let digest = fqhn::fqhn_digest(fqhn).unwrap();
            let value = digest_to_u128_be(&digest);
            let (primary, _) = p.primary_secondary(fqhn, &s).unwrap();
            assert_eq!(primary, (value % 5) as usize);
        }
    }

    #[test]
    fn collision_bumps_secondary_not_primary() {
        let p = ModuloPlacement;
        let s = servers(3);
        // Find an FQHN where hash%3 == hash%2 (collision before bump).
        let mut found = false;
        for i in 0..5000 {
            let fqhn = format!("probe-{i}.example.idr.to");
            let digest = fqhn::fqhn_digest(&fqhn).unwrap();
            let value = digest_to_u128_be(&digest);
            let raw_p = (value % 3) as usize;
            let raw_s = (value % 2) as usize;
            if raw_p != raw_s {
                continue;
            }
            let (primary, secondary) = p.primary_secondary(&fqhn, &s).unwrap();
            assert_eq!(primary, raw_p);
            assert_eq!(secondary, Some((raw_s + 1) % 3));
            found = true;
            break;
        }
        assert!(found, "expected a colliding FQHN in probe range");
    }

    #[test]
    fn append_preserves_one_common_node() {
        let p = ModuloPlacement;
        for n in 2..=12 {
            let sold = servers(n);
            let snew = servers(n + 1);
            for fqhn in FQHNS {
                let (p0, s0) = p.primary_secondary(fqhn, &sold).unwrap();
                let (p1, s1) = p.primary_secondary(fqhn, &snew).unwrap();
                let old = [p0, s0.unwrap()];
                let new = [p1, s1.unwrap()];
                assert!(
                    old.iter().any(|i| new.contains(i)),
                    "no overlap for {fqhn} N={n}: old={old:?} new={new:?}"
                );
            }
        }
    }
}
