//! IDR Source Agent library: configuration and the transfer-owning daemon.

pub mod config;
/// The daemon lives in `idr-source` so the embedded engine (C ABI) runs the same one.
pub mod daemon {
    pub use idr_source::agent::*;
}
