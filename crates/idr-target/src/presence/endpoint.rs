use std::net::SocketAddr;

use idr_protocol::discovery::PresenceServer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceTransportChoice {
    Quic(SocketAddr),
    Wss,
}

pub struct PresenceNetworkCaps {
    pub ipv4: bool,
    pub ipv6: bool,
}

impl PresenceNetworkCaps {
    pub fn from_detect(caps: &crate::network::NetworkCapabilities) -> Self {
        Self {
            ipv4: caps.ipv4,
            ipv6: caps.ipv6,
        }
    }
}

/// Build ordered transport attempts: QUIC endpoints first (when preferred), then WSS.
pub fn build_transport_attempts(
    server: &PresenceServer,
    network: &PresenceNetworkCaps,
    prefer_quic: bool,
) -> Vec<PresenceTransportChoice> {
    let mut attempts = Vec::new();
    let (v4, v6) = server.parse_quic_endpoints();

    if prefer_quic && server.supports_quic() {
        if let Some(v6) = v6 {
            if network.ipv6 {
                attempts.push(PresenceTransportChoice::Quic(v6));
            }
        }
        if let Some(v4) = v4 {
            if network.ipv4 {
                attempts.push(PresenceTransportChoice::Quic(v4));
            }
        }
    }

    if server.supports_wss() {
        attempts.push(PresenceTransportChoice::Wss);
    }

    if !prefer_quic && server.supports_quic() {
        if let Some(v4) = v4 {
            if network.ipv4 {
                attempts.push(PresenceTransportChoice::Quic(v4));
            }
        }
        if let Some(v6) = v6 {
            if network.ipv6 {
                attempts.push(PresenceTransportChoice::Quic(v6));
            }
        }
    }

    attempts
}

pub fn transport_label(choice: PresenceTransportChoice) -> &'static str {
    match choice {
        PresenceTransportChoice::Quic(_) => "quic",
        PresenceTransportChoice::Wss => "wss",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_server() -> PresenceServer {
        PresenceServer {
            presence_id: "p1".into(),
            wss_url: "ws://127.0.0.1/v1/presence".into(),
            ipv4: Some("127.0.0.1".into()),
            ipv6: None,
            server_name: "p1.idr.to".into(),
            region: "local".into(),
            public_key: "abc".into(),
            quic_port: Some(4433),
            transports: vec!["quic".into(), "wss".into()],
        }
    }

    #[test]
    fn prefers_quic_when_enabled() {
        let attempts = build_transport_attempts(
            &sample_server(),
            &PresenceNetworkCaps {
                ipv4: true,
                ipv6: false,
            },
            true,
        );
        assert_eq!(attempts.len(), 2);
        assert!(matches!(attempts[0], PresenceTransportChoice::Quic(_)));
        assert_eq!(attempts[1], PresenceTransportChoice::Wss);
    }
}
