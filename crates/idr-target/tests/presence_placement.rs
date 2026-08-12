use idr_target::protocol::fqhn;
use idr_target::protocol::placement::{ModuloPlacement, PresencePlacement};

fn server(i: usize) -> idr_target::protocol::discovery::PresenceServer {
    idr_target::protocol::discovery::PresenceServer {
        presence_id: format!("presence-{i:04}"),
        wss_url: format!("wss://203.0.113.{}/v1/presence", 10 + i),
        ipv4: Some(format!("203.0.113.{}", 10 + i)),
        ipv6: None,
        server_name: format!("presence-{i:04}.idr.to"),
        region: "test".into(),
        public_key: String::new(),
        quic_port: Some(4433),
        transports: vec!["quic".into(), "wss".into()],
    }
}

#[test]
fn canonical_fqhn_and_placement() {
    let canonical = fqhn::canonicalize("Device-01.Example.IDR.to.").unwrap();
    assert_eq!(canonical, "device-01.example.idr.to");

    let servers = vec![server(0), server(1)];
    let placement = ModuloPlacement;
    let (primary, secondary) = placement.primary_secondary(&canonical, &servers).unwrap();
    assert!(primary < servers.len());
    let secondary = secondary.expect("secondary required for N>=2");
    assert_ne!(primary, secondary);
    assert_eq!(secondary, (primary + 1) % servers.len());
}

#[test]
fn append_preserves_overlap() {
    let placement = ModuloPlacement;
    let fqhn = "device-01.example.idr.to";
    let s3: Vec<_> = (0..3).map(server).collect();
    let s4: Vec<_> = (0..4).map(server).collect();
    let (p0, s0) = placement.primary_secondary(fqhn, &s3).unwrap();
    let (p1, s1) = placement.primary_secondary(fqhn, &s4).unwrap();
    let old = [p0, s0.unwrap()];
    let new = [p1, s1.unwrap()];
    assert!(old.iter().any(|i| new.contains(i)));
}

#[test]
fn single_server_list_is_primary_only() {
    let placement = ModuloPlacement;
    let servers = vec![server(0)];
    let (primary, secondary) = placement
        .primary_secondary("device-01.example.idr.to", &servers)
        .unwrap();
    assert_eq!(primary, 0);
    assert!(secondary.is_none());
}
