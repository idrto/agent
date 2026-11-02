//! Native filesystem storage (feature `native`): sandboxed `cap-std` access,
//! staging on the destination volume, no-replace commits and a durable journal.

pub mod control;
mod enumerate;
mod files;
pub mod ipc;
mod journal;
pub mod manager;
pub mod rename;
mod sink;
mod space;

pub use enumerate::{enumerate, Enumerated};
pub use files::{mtime_secs, NativeFiles};
pub use sink::{NativeSink, STAGING_PREFIX};
pub use space::{free_space, permitted_destination, resolve_destination, Destination};
