//! Stable C ABI for embedded Source Agent (Dart / mobile FFI).
//!
//! Design rules:
//! - Opaque handles only (`idr_engine_t`, …)
//! - Config structs carry `abi_version` + `struct_size`
//! - No per-packet Dart callbacks — drain a batched event queue
//! - Safe byte copies into caller buffers

#![allow(clippy::missing_safety_doc)]

/// Runs an export body under `idr_telemetry::ffi_guard` (docs/observability/04 §3.1): no
/// panic crosses the ABI. A panic writes a crash record, poisons the engine, sets the last
/// error to `Panic` and returns `$on_panic`; once poisoned, every guarded export fails fast.
macro_rules! guarded {
    ($name:literal, $on_panic:expr, $body:block) => {{
        let mut finished = false;
        let out = ::idr_telemetry::ffi_guard($name, $on_panic, || {
            // The inner closure makes `return` in an export body return from the closure.
            #[allow(clippy::redundant_closure_call)]
            let r = (|| $body)();
            finished = true;
            r
        });
        if !finished {
            $crate::error::set_last_error_kind(
                ::idr_core::IdrErrorKind::Panic,
                concat!(
                    $name,
                    ": native engine panicked and is poisoned; restart it"
                ),
            );
        }
        out
    }};
}

/// Like `guarded!` without the fail-fast check: for exports the host needs after a panic
/// (`idr_last_error_*`, `idr_abi_version`, `idr_engine_destroy`).
macro_rules! caught {
    ($name:literal, $on_panic:expr, $body:block) => {{
        #[allow(clippy::redundant_closure_call)]
        ::idr_telemetry::ffi_catch($name, $on_panic, || (|| $body)())
    }};
}

mod engine;
mod error;
mod ffi;
mod mock_backend;
#[cfg(feature = "native")]
mod native_backend;
mod telemetry;
mod transfer;

pub use engine::{
    Engine, EngineConfig, EngineEvent, ABI_VERSION, IDR_AUTH_BEARER, IDR_AUTH_DEVICE_TOKEN,
    IDR_AUTH_MTLS,
};
pub use error::{clear_last_error, last_error_code, last_error_message, set_last_error};
pub use ffi::*;
pub use telemetry::*;
pub use transfer::*;
// Compile the `idr_dp_*` C ABI into this cdylib so Source ships one native lib.
// Included by path (not as a dep): both `idr-dp` and `idr-dp-ffi` have lib name `idr_dp`.
#[path = "../../idr-dp-ffi/src/lib.rs"]
pub mod dp_ffi;
