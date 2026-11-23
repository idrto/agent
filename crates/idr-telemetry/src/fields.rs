//! Well-known record keys. Use these instead of string literals (docs/observability/07 R-LOG-2).
//! Correlation keys are top-level record fields; when set on a span they are inherited by
//! every child span and event.

pub const EVENT: &str = "event";
pub const MESSAGE: &str = "message";

pub const SESSION_ID: &str = "session_id";
pub const CONNECTION_ID: &str = "connection_id";
pub const TRANSFER_ID: &str = "transfer_id";
pub const OPERATION_ID: &str = "operation_id";
pub const REPORT_ID: &str = "report_id";

/// Span field: a W3C `traceparent` to parent this span from (remote context).
pub const TRACEPARENT: &str = "traceparent";
/// Span field: a W3C `traceparent` to link to (related, not parent).
pub const LINK: &str = "link";
/// Span field: also write a `<span name>.started` record when the span opens.
pub const PERSIST_START: &str = "persist_start";
/// Span field: `"error"` marks the span outcome as failed.
pub const STATUS: &str = "status";

pub const ERROR_TYPE: &str = "error.type";
pub const ERROR_MESSAGE: &str = "error.message";
pub const ERROR_STACK: &str = "error.stack";
pub const ERROR_CODE: &str = "error.code";

pub const TARGET_FQHN: &str = "target.fqhn";
pub const DEVICE_SKI: &str = "device.ski";
pub const RETRY_ATTEMPT: &str = "retry.attempt";
pub const NETWORK_TRANSPORT: &str = "network.transport";
pub const SERVER_ADDRESS: &str = "server.address";
pub const CLIENT_ADDRESS: &str = "client.address";
pub const HTTP_STATUS: &str = "http.response.status_code";
pub const HTTP_REQUEST_ID: &str = "http.request_id";
pub const STREAM_ID: &str = "stream.id";
pub const FFI_HANDLE: &str = "ffi.handle";
pub const REASON: &str = "reason";
pub const DURATION_MS: &str = "duration_ms";
