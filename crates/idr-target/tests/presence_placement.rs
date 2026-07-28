use idr_target::protocol::fqhn;
use idr_target::protocol::placement::{ModuloPlacement, PresencePlacement};

#[test]
fn canonical_fqhn_and_placement() {
    let canonical = fqhn::canonicalize("Device-01.Example.IDR.to.").unwrap();
    assert_eq!(canonical, "device-01.example.idr.to");

    let servers = vec![
        idr_target::protocol::discovery::PresenceServer {
            presence_id: "presence-0001".into(),
            wss_url: "wss://203.0.113.10/v1/presence".into(),
            ipv4: Some("203.0.113.10".into()),
            ipv6: None,
            server_name: "presence-0001.idr.to".into(),
            region: "test".into(),
            public_key: String::new(),
            quic_port: Some(4433),
            transports: vec!["quic".into(), "wss".into()],
        },
        idr_target::protocol::discovery::PresenceServer {
            presence_id: "presence-0002".into(),
            wss_url: "wss://203.0.113.11/v1/presence".into(),
            ipv4: Some("203.0.113.11".into()),
            ipv6: None,
            server_name: "presence-0002.idr.to".into(),
            region: "test".into(),
            public_key: String::new(),
            quic_port: Some(4433),
            transports: vec!["quic".into(), "wss".into()],
        },
    ];

    let placement = ModuloPlacement;
    let (primary, secondary) = placement
        .primary_secondary(&canonical, &servers)
        .unwrap();
    assert!(primary < servers.len());
    assert_eq!(secondary, Some((primary + 1) % servers.len()));
}

#[test]
fn list_length_change_remapping() {
    let placement = ModuloPlacement;
    let fqhn = "device-01.example.idr.to";
    let s3: Vec<_> = (0..3)
        .map(|i| idr_target::protocol::discovery::PresenceServer {
            presence_id: format!("p{i}"),
            wss_url: format!("wss://10.0.0.{}/v1/presence", i + 1),
            ipv4: Some(format!("10.0.0.{}", i + 1)),
            ipv6: None,
            server_name: format!("p{i}.idr.to"),
            region: "t".into(),
            public_key: String::new(),
            quic_port: Some(4433),
            transports: vec!["quic".into(), "wss".into()],
        })
        .collect();
    let s4: Vec<_> = (0..4)
        .map(|i| idr_target::protocol::discovery::PresenceServer {
            presence_id: format!("p{i}"),
            wss_url: format!("wss://10.0.0.{}/v1/presence", i + 1),
            ipv4: Some(format!("10.0.0.{}", i + 1)),
            ipv6: None,
            server_name: format!("p{i}.idr.to"),
            region: "t".into(),
            public_key: String::new(),
            quic_port: Some(4433),
            transports: vec!["quic".into(), "wss".into()],
        })
        .collect();
    let (a, _) = placement.primary_secondary(fqhn, &s3).unwrap();
    let (b, _) = placement.primary_secondary(fqhn, &s4).unwrap();
    let _ = (a, b);
}
