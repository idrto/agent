//! Map friendly service names to stream kinds (named services v1).

use idr_protocol::stream_mux::StreamKind;

/// Default mapping for Source `open_stream(service)` before Target publishes a catalog.
pub fn default_service_kind(service: &str) -> Option<StreamKind> {
    match service {
        "https" | "web" | "tls" | "tls_passthrough" => Some(StreamKind::TlsPassthrough),
        "http" | "http_passthrough" => Some(StreamKind::HttpPassthrough),
        "tcp" | "tcp_connect" => Some(StreamKind::TcpConnect),
        _ => None,
    }
}
