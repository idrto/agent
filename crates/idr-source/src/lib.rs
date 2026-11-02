//! Minimal Source Agent — WebRTC data plane only (no Relay dependency).
//!
//! Public surface is intentionally small for mobile embeds:
//! `SourceRuntime::connect` → `SourceSession::open_stream` → read/write/half_close/reset.

#[cfg(feature = "transfer")]
pub mod agent;
mod mux_session;
mod runtime;
mod service_map;
mod time;

pub use mux_session::{DemuxEvent, IncomingStream, MuxLogicalStream};
pub use runtime::{SessionOpener, SourceRuntime, SourceSession};
pub use service_map::default_service_kind;
