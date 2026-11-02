//! IDR file transfer engine.
//!
//! Transfers files, a complete folder, or a selection from a folder between two
//! authenticated peers over a mux [`idr_core::PeerSession`], in either
//! direction. One model for all three modes: a transfer id, an immutable
//! manifest of entries, and per-entry state. Per transfer there is one control
//! stream and one data stream whose records are tagged by entry id.
//!
//! Boundaries: [`storage::SourceFiles`] / [`storage::Sink`] (storage),
//! [`storage::Consent`] (policy), [`storage::StreamOpener`] / [`Router`] (streams).
//! The engine has no filesystem, Presence or Relay dependency and spawns no tasks.

pub mod bind;
mod events;
pub mod io;
mod limits;
pub mod manifest;
pub mod mem;
pub mod names;
pub mod policy;
#[cfg(feature = "native")]
pub mod native;
mod receiver;
mod router;
mod sender;
pub mod storage;

pub use events::{Command, EventTx, Outcome, Progress, TransferEvent};
pub use limits::Limits;
pub use receiver::receive;
pub use router::{Routed, Router};
pub use sender::{send, Outgoing};
