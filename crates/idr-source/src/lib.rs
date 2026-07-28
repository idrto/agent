//! Minimal Source Agent — WebRTC data plane only (no Relay dependency).
//!
//! Public surface is intentionally small for mobile embeds:
//! `SourceRuntime::connect` → `SourceSession::open_stream` → read/write/half_close/reset.

mod mux_session;
mod runtime;
mod service_map;

pub use mux_session::{DemuxEvent, MuxLogicalStream};
pub use runtime::{SourceRuntime, SourceSession};
pub use service_map::default_service_kind;
