//! Stable C ABI for embedded Source Agent (Dart / mobile FFI).
//!
//! Design rules:
//! - Opaque handles only (`idr_engine_t`, …)
//! - Config structs carry `abi_version` + `struct_size`
//! - No per-packet Dart callbacks — drain a batched event queue
//! - Safe byte copies into caller buffers

#![allow(clippy::missing_safety_doc)]

mod engine;
mod error;
mod ffi;
mod mock_backend;
#[cfg(feature = "native")]
mod native_backend;

pub use engine::{
    Engine, EngineConfig, EngineEvent, ABI_VERSION, IDR_AUTH_BEARER, IDR_AUTH_DEVICE_TOKEN,
    IDR_AUTH_MTLS,
};
pub use error::{clear_last_error, last_error_code, last_error_message, set_last_error};
pub use ffi::*;
