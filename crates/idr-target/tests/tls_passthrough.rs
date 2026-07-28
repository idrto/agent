use idr_target::protocol::framing::decode_frame;
use idr_target::protocol::tunnel::{
    host_header_hostname, parse_http_host_and_path, TunnelOpen, TunnelStreamKind,
    ACME_WELL_KNOWN_PREFIX,
};
use idr_target::protocol::MAX_FRAME_BYTES;

#[test]
fn acme_http_host_parsing() {
    let req = b"GET /.well-known/acme-challenge/abc HTTP/1.1\r\nHost: device.idr.to\r\n\r\n";
    let (host, path) = parse_http_host_and_path(req).unwrap();
    assert_eq!(host, "device.idr.to");
    assert!(path.contains("acme-challenge"));
    assert!(path.starts_with(ACME_WELL_KNOWN_PREFIX));
}

#[test]
fn host_header_case_and_port() {
    let req = b"HEAD /x HTTP/1.1\r\nHOST: Device.IDR.to:8080\r\n\r\n";
    let (host, _) = parse_http_host_and_path(req).unwrap();
    assert_eq!(host, "device.idr.to");
}

#[test]
fn ipv6_host_header() {
    assert_eq!(
        host_header_hostname("[::1]:80").as_deref(),
        Some("::1")
    );
}

#[test]
fn tunnel_open_tls_kind_roundtrip() {
    let open = TunnelOpen::new(TunnelStreamKind::TlsPassthrough, "host.idr.to");
    let enc = open.encode().unwrap();
    let dec = TunnelOpen::decode(&enc).unwrap();
    assert_eq!(open, dec);
    assert_eq!(dec.kind, TunnelStreamKind::TlsPassthrough);
}

#[test]
fn tunnel_open_http_kind_roundtrip() {
    let open = TunnelOpen::new(TunnelStreamKind::HttpPassthrough, "host.idr.to");
    let enc = open.encode().unwrap();
    let dec = TunnelOpen::decode(&enc).unwrap();
    assert_eq!(dec.kind, TunnelStreamKind::HttpPassthrough);
}

#[test]
fn frame_rejects_oversize_length_prefix() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes());
    bytes.extend_from_slice(&[0u8; 8]);
    let err: Result<TunnelOpen, _> = decode_frame(&bytes);
    assert!(err.is_err());
}
