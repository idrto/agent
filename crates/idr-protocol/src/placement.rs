use crate::discovery::PresenceServer;
use crate::fqhn;

/// Placement strategy trait — v1 uses modulo; future: rendezvous, jump consistent.
pub trait PresencePlacement {
    fn primary_secondary(&self, fqhn: &str, servers: &[PresenceServer]) -> crate::errors::Result<(usize, Option<usize>)>;
}

/// SHA-256 modulo placement (v1 default).
///
/// **Weakness:** when `presence_servers.len()` changes, many Targets remap.
/// Isolated behind this trait for future replacement.
#[derive(Debug, Clone, Copy, Default)]
pub struct ModuloPlacement;

impl PresencePlacement for ModuloPlacement {
    fn primary_secondary(
        &self,
        target_fqhn: &str,
        servers: &[PresenceServer],
    ) -> crate::errors::Result<(usize, Option<usize>)> {
        if servers.is_empty() {
            return Err(crate::errors::ProtocolError::MalformedDocument(
                "empty presence server list".into(),
            ));
        }
        let digest = fqhn::fqhn_digest(target_fqhn)?;
        let value = digest_to_u256_be(&digest);
        let n = servers.len() as u128;
        let primary = (value % n) as usize;
        let secondary = if servers.len() == 1 {
            None
        } else {
            Some((primary + 1) % servers.len())
        };
        Ok((primary, secondary))
    }
}

fn digest_to_u256_be(digest: &[u8; 32]) -> u128 {
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

    #[test]
    fn deterministic_primary() {
        let p = ModuloPlacement;
        let s = servers(3);
        let (a, _) = p.primary_secondary("device-01.example.idr.to", &s).unwrap();
        let (b, _) = p.primary_secondary("device-01.example.idr.to", &s).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn secondary_wraps() {
        let p = ModuloPlacement;
        let s = servers(2);
        let (primary, secondary) = p.primary_secondary("a.example.idr.to", &s).unwrap();
        assert_eq!(secondary, Some((primary + 1) % 2));
    }

    #[test]
    fn single_server_no_secondary() {
        let p = ModuloPlacement;
        let s = servers(1);
        let (_, secondary) = p.primary_secondary("a.example.idr.to", &s).unwrap();
        assert!(secondary.is_none());
    }

    #[test]
    fn remapping_on_list_change() {
        let p = ModuloPlacement;
        let fqhn = "device-01.example.idr.to";
        let s3 = servers(3);
        let s4 = servers(4);
        let (p3, _) = p.primary_secondary(fqhn, &s3).unwrap();
        let (p4, _) = p.primary_secondary(fqhn, &s4).unwrap();
        // Document remapping weakness — not guaranteed equal
        let _ = (p3, p4);
    }
}
