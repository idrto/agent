//! Timer primitives that work on native and `wasm32-unknown-unknown`.
//!
//! `std::time::Instant` / `tokio::time` panic on browser WASM
//! (`time not implemented on this platform`). Use this module instead.

#[cfg(target_arch = "wasm32")]
pub use wasmtimer::std::Instant;
#[cfg(target_arch = "wasm32")]
pub use wasmtimer::tokio::{sleep_until, timeout};

#[cfg(not(target_arch = "wasm32"))]
pub use tokio::time::{sleep_until, timeout, Instant};
