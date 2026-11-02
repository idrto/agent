//! Timer primitives that work on native and `wasm32-unknown-unknown`.
//!
//! `std::time::Instant` / `tokio::time` panic on browser WASM
//! (`time not implemented on this platform`). Use this module instead.

#[cfg(target_arch = "wasm32")]
pub use wasmtimer::std::Instant;
#[cfg(target_arch = "wasm32")]
pub use wasmtimer::tokio::{sleep, sleep_until, timeout};

#[cfg(not(target_arch = "wasm32"))]
pub use tokio::time::{sleep, sleep_until, timeout, Instant};

/// Run a background task: tokio on native, the JS event loop on WASM.
#[cfg(not(target_arch = "wasm32"))]
pub fn spawn(fut: impl std::future::Future<Output = ()> + Send + 'static) {
    tokio::spawn(fut);
}

#[cfg(target_arch = "wasm32")]
pub fn spawn(fut: impl std::future::Future<Output = ()> + 'static) {
    wasm_bindgen_futures::spawn_local(fut);
}
