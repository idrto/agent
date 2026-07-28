//! Opaque byte tunnel over QUIC streams — Relay must not decrypt client TLS/HTTP payloads.
//!
//! Wire format: length-prefixed postcard [`TunnelOpen`], then raw application bytes.
//! Kind values are postcard enum indexes (TlsPassthrough=0, HttpPassthrough=1), not `#[repr(u8)]`.

use serde::{Deserialize, Serialize};

use crate::errors::{ProtocolError, Result};
use crate::framing::{decode_frame, encode_frame};
use crate::PROTOCOL_VERSION;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelStreamKind {
    /// Raw TLS records (HTTPS). Terminated only at Target nginx.
    TlsPassthrough,
    /// Plain HTTP (port 80). Used for ACME http-01 and cleartext routing.
    HttpPassthrough,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelOpen {
    pub protocol_version: u32,
    pub kind: TunnelStreamKind,
    pub target_fqhn: String,
}

impl TunnelOpen {
    pub fn new(kind: TunnelStreamKind, target_fqhn: impl Into<String>) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            kind,
            target_fqhn: target_fqhn.into(),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_frame(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let open: Self = decode_frame(bytes)?;
        if open.protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(open.protocol_version));
        }
        Ok(open)
    }
}

pub const ACME_WELL_KNOWN_PREFIX: &str = "/.well-known/acme-challenge/";

/// Extract hostname from an HTTP Host header value (supports `host:port` and IPv6 `[::1]:port`).
pub fn host_header_hostname(value: &str) -> Option<String> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }
    if let Some(rest) = v.strip_prefix('[') {
        let end = rest.find(']')?;
        return Some(rest[..end].to_ascii_lowercase());
    }
    // hostname or hostname:port (first ':' separates port for non-IPv6)
    Some(
        v.split(':')
            .next()
            .unwrap_or(v)
            .to_ascii_lowercase(),
    )
}

/// Returns `(host, path)` when the buffer contains a complete HTTP/1.x request line + Host header.
/// Accepts GET and HEAD (ACME validators use GET). Host matching is case-insensitive.
pub fn parse_http_host_and_path(buf: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(buf).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("HEAD") {
        return None;
    }
    let path = parts.next()?.to_string();
    let mut host = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("host") {
            host = host_header_hostname(value);
        }
    }
    host.map(|h| (h, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_open_roundtrip() {
        let open = TunnelOpen::new(TunnelStreamKind::TlsPassthrough, "host.idr.to");
        let enc = open.encode().unwrap();
        let dec = TunnelOpen::decode(&enc).unwrap();
        assert_eq!(open, dec);
    }

    #[test]
    fn parse_acme_http() {
        let req = b"GET /.well-known/acme-challenge/token123 HTTP/1.1\r\nHost: host.idr.to\r\n\r\n";
        let (host, path) = parse_http_host_and_path(req).unwrap();
        assert_eq!(host, "host.idr.to");
        assert!(path.starts_with(ACME_WELL_KNOWN_PREFIX));
    }

    #[test]
    fn parse_host_case_insensitive() {
        let req = b"GET / HTTP/1.1\r\nHOST: Example.IDR.to:80\r\n\r\n";
        let (host, _) = parse_http_host_and_path(req).unwrap();
        assert_eq!(host, "example.idr.to");
    }

    #[test]
    fn parse_ipv6_host() {
        assert_eq!(
            host_header_hostname("[2001:db8::1]:80").as_deref(),
            Some("2001:db8::1")
        );
    }
}
