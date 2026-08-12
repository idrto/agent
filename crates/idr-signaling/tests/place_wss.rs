//! place_wss_servers integration for browser WASM discovery path.

use chrono::{Duration, Utc};
use idr_protocol::discovery::{PresenceDiscoveryDocument, PresenceServer};
use idr_signaling::{place, place_wss_servers};

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

fn doc(n: usize) -> PresenceDiscoveryDocument {
    PresenceDiscoveryDocument {
        version: 1,
        generation: 1,
        valid_until: Utc::now() + Duration::hours(1),
        presence_servers: servers(n),
        signature: String::new(),
    }
}

#[test]
fn place_wss_primary_is_hash_mod_n() {
    let document = doc(5);
    let fqhn = "device-01.example.idr.to";
    let (primary, _) = place(&document, fqhn).unwrap();
    let ordered = place_wss_servers(&document, fqhn).unwrap();
    assert_eq!(ordered[0].presence_id, format!("presence-{primary:04}"));
}

#[test]
fn single_node_ok() {
    let ordered = place_wss_servers(&doc(1), "a.example.idr.to").unwrap();
    assert_eq!(ordered.len(), 1);
}
