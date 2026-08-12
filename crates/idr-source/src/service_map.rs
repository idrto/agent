//! Map friendly service names to stream kinds (named services / gateway).

use idr_protocol::stream_mux::StreamKind;

/// Default mapping for Source `open_stream(service)` before Target publishes a catalog.
///
/// Unknown names default to [`StreamKind::TcpConnect`] so Target `[[services]]`
/// entries work without hardcoding each app (ollama, huggingface, redis, …).
pub fn default_service_kind(service: &str) -> Option<StreamKind> {
    match service {
        "https" | "web" | "tls" | "tls_passthrough" => Some(StreamKind::TlsPassthrough),
        "http" | "http_passthrough" => Some(StreamKind::HttpPassthrough),
        "tcp" | "tcp_connect" => Some(StreamKind::TcpConnect),
        _ if !service.is_empty() => Some(StreamKind::TcpConnect),
        _ => None,
    }
}
