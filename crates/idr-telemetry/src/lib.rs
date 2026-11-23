//! IDR unified logging, tracing and diagnostics (`idr.log/1`).
//!
//! Design: `docs/observability/`. Rules for contributors: `docs/observability/07-rules-and-enforcement.md`.
//!
//! - Feature `types` (default): IDs, trace context, `ctx_json`, [`Secret`], [`redact`], field names.
//!   Library crates may depend on this; it pulls no subscriber code.
//! - Feature `subscriber`: [`init`] and everything behind it. Composition points only
//!   (binaries, the FFI entry); libraries never install subscribers.

// R-LIB-1: no print macros in library code (stdout is written through the sink only).
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

mod ctx;
pub mod fields;
mod ids;
#[cfg(feature = "redact")]
mod redact;
mod secret;

pub use ctx::LocalContext;
pub use ids::{is_uuid, new_id, TraceContext};
#[cfg(feature = "redact")]
pub use redact::redact;
pub use secret::Secret;

/// Record schema implemented by this crate.
pub const SCHEMA: &str = "idr.log/1";

#[cfg(feature = "subscriber")]
mod subscriber;
#[cfg(feature = "subscriber")]
pub use subscriber::*;
