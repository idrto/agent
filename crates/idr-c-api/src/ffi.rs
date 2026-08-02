//! #[no_mangle] C ABI exports.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::slice;

use idr_core::IdrErrorKind;

use crate::engine::{Engine, EngineConfig, EngineEvent, ABI_VERSION};
use crate::error::{
    clear_last_error, last_error_code, last_error_message, set_last_error, set_last_error_kind,
};

/// Opaque engine handle.
pub type IdrEngine = c_void;

#[repr(C)]
pub struct IdrEngineConfig {
    pub abi_version: u32,
    pub struct_size: u32,
    pub use_mock: u32,
    pub source_id: *const c_char,
    pub source_region: *const c_char,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IdrEvent {
    pub kind: u32,
    pub session_id: u64,
    pub stream_id: u64,
    pub code: u32,
    pub len: u32,
}

pub const IDR_EVENT_NONE: u32 = 0;
pub const IDR_EVENT_CONNECTED: u32 = 1;
pub const IDR_EVENT_STREAM_OPENED: u32 = 2;
pub const IDR_EVENT_BYTES_AVAILABLE: u32 = 3;
pub const IDR_EVENT_STREAM_CLOSED: u32 = 4;
pub const IDR_EVENT_ERROR: u32 = 5;

fn map_err(err: idr_core::IdrError) -> c_int {
    set_last_error(&err);
    -(err.kind as c_int)
}

#[no_mangle]
pub extern "C" fn idr_abi_version() -> u32 {
    ABI_VERSION
}

#[no_mangle]
pub unsafe extern "C" fn idr_engine_create(config: *const IdrEngineConfig) -> *mut IdrEngine {
    clear_last_error();
    if config.is_null() {
        set_last_error_kind(IdrErrorKind::InvalidArgument, "null config");
        return ptr::null_mut();
    }
    let cfg = &*config;
    let eng_cfg = EngineConfig {
        abi_version: cfg.abi_version,
        struct_size: cfg.struct_size,
        use_mock: cfg.use_mock,
        source_id: cfg.source_id,
        source_region: cfg.source_region,
    };
    match Engine::new(&eng_cfg) {
        Ok(engine) => Box::into_raw(Box::new(engine)) as *mut IdrEngine,
        Err(e) => {
            set_last_error(&e);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn idr_engine_destroy(engine: *mut IdrEngine) {
    if engine.is_null() {
        return;
    }
    drop(Box::from_raw(engine as *mut Engine));
}

#[no_mangle]
pub unsafe extern "C" fn idr_connect(
    engine: *mut IdrEngine,
    target_fqhn: *const c_char,
    out_session: *mut u64,
) -> c_int {
    clear_last_error();
    if engine.is_null() || target_fqhn.is_null() || out_session.is_null() {
        set_last_error_kind(IdrErrorKind::InvalidArgument, "null argument");
        return -(IdrErrorKind::InvalidArgument as c_int);
    }
    let eng = &*(engine as *mut Engine);
    let fqhn = match CStr::from_ptr(target_fqhn).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error_kind(IdrErrorKind::InvalidArgument, "invalid utf8 fqhn");
            return -(IdrErrorKind::InvalidArgument as c_int);
        }
    };
    match eng.connect(fqhn) {
        Ok(id) => {
            *out_session = id;
            0
        }
        Err(e) => map_err(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn idr_disconnect(engine: *mut IdrEngine, session_id: u64) -> c_int {
    clear_last_error();
    if engine.is_null() {
        set_last_error_kind(IdrErrorKind::InvalidArgument, "null engine");
        return -(IdrErrorKind::InvalidArgument as c_int);
    }
    let eng = &*(engine as *mut Engine);
    match eng.disconnect(session_id) {
        Ok(()) => 0,
        Err(e) => map_err(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn idr_open_stream(
    engine: *mut IdrEngine,
    session_id: u64,
    service: *const c_char,
    out_stream: *mut u64,
) -> c_int {
    clear_last_error();
    if engine.is_null() || service.is_null() || out_stream.is_null() {
        set_last_error_kind(IdrErrorKind::InvalidArgument, "null argument");
        return -(IdrErrorKind::InvalidArgument as c_int);
    }
    let eng = &*(engine as *mut Engine);
    let svc = match CStr::from_ptr(service).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error_kind(IdrErrorKind::InvalidArgument, "invalid utf8 service");
            return -(IdrErrorKind::InvalidArgument as c_int);
        }
    };
    match eng.open_stream(session_id, svc) {
        Ok(id) => {
            *out_stream = id;
            0
        }
        Err(e) => map_err(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn idr_stream_write(
    engine: *mut IdrEngine,
    session_id: u64,
    stream_id: u64,
    buf: *const u8,
    len: usize,
    out_written: *mut usize,
) -> c_int {
    clear_last_error();
    if engine.is_null() || buf.is_null() || out_written.is_null() {
        set_last_error_kind(IdrErrorKind::InvalidArgument, "null argument");
        return -(IdrErrorKind::InvalidArgument as c_int);
    }
    let eng = &*(engine as *mut Engine);
    let data = slice::from_raw_parts(buf, len);
    match eng.stream_write(session_id, stream_id, data) {
        Ok(n) => {
            *out_written = n;
            0
        }
        Err(e) => map_err(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn idr_stream_read(
    engine: *mut IdrEngine,
    session_id: u64,
    stream_id: u64,
    buf: *mut u8,
    len: usize,
    out_read: *mut usize,
) -> c_int {
    clear_last_error();
    if engine.is_null() || buf.is_null() || out_read.is_null() {
        set_last_error_kind(IdrErrorKind::InvalidArgument, "null argument");
        return -(IdrErrorKind::InvalidArgument as c_int);
    }
    let eng = &*(engine as *mut Engine);
    let data = slice::from_raw_parts_mut(buf, len);
    match eng.stream_read(session_id, stream_id, data) {
        Ok(n) => {
            *out_read = n;
            0
        }
        Err(e) => map_err(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn idr_stream_half_close(
    engine: *mut IdrEngine,
    session_id: u64,
    stream_id: u64,
) -> c_int {
    clear_last_error();
    if engine.is_null() {
        set_last_error_kind(IdrErrorKind::InvalidArgument, "null engine");
        return -(IdrErrorKind::InvalidArgument as c_int);
    }
    let eng = &*(engine as *mut Engine);
    match eng.stream_half_close(session_id, stream_id) {
        Ok(()) => 0,
        Err(e) => map_err(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn idr_stream_reset(
    engine: *mut IdrEngine,
    session_id: u64,
    stream_id: u64,
    reason: u16,
) -> c_int {
    clear_last_error();
    if engine.is_null() {
        set_last_error_kind(IdrErrorKind::InvalidArgument, "null engine");
        return -(IdrErrorKind::InvalidArgument as c_int);
    }
    let eng = &*(engine as *mut Engine);
    match eng.stream_reset(session_id, stream_id, reason) {
        Ok(()) => 0,
        Err(e) => map_err(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn idr_poll_events(
    engine: *mut IdrEngine,
    out_events: *mut IdrEvent,
    max_events: usize,
    out_count: *mut usize,
) -> c_int {
    clear_last_error();
    if engine.is_null() || out_events.is_null() || out_count.is_null() {
        set_last_error_kind(IdrErrorKind::InvalidArgument, "null argument");
        return -(IdrErrorKind::InvalidArgument as c_int);
    }
    let eng = &*(engine as *mut Engine);
    let dest = slice::from_raw_parts_mut(out_events, max_events);
    let mut n = 0usize;
    while n < max_events {
        let Some(ev) = eng.poll_event() else {
            break;
        };
        dest[n] = match ev {
            EngineEvent::Connected { session_id } => IdrEvent {
                kind: IDR_EVENT_CONNECTED,
                session_id,
                stream_id: 0,
                code: 0,
                len: 0,
            },
            EngineEvent::StreamOpened {
                session_id,
                stream_id,
            } => IdrEvent {
                kind: IDR_EVENT_STREAM_OPENED,
                session_id,
                stream_id,
                code: 0,
                len: 0,
            },
            EngineEvent::BytesAvailable { stream_id, len } => IdrEvent {
                kind: IDR_EVENT_BYTES_AVAILABLE,
                session_id: 0,
                stream_id,
                code: 0,
                len: len as u32,
            },
            EngineEvent::StreamClosed { stream_id } => IdrEvent {
                kind: IDR_EVENT_STREAM_CLOSED,
                session_id: 0,
                stream_id,
                code: 0,
                len: 0,
            },
            EngineEvent::Error { code, message } => IdrEvent {
                kind: IDR_EVENT_ERROR,
                session_id: 0,
                stream_id: 0,
                code,
                len: message.len() as u32,
            },
        };
        n += 1;
    }
    *out_count = n;
    0
}

#[no_mangle]
pub unsafe extern "C" fn idr_engine_set_dp_identity(
    engine: *mut IdrEngine,
    identity_json: *const c_char,
) -> c_int {
    clear_last_error();
    if engine.is_null() || identity_json.is_null() {
        set_last_error_kind(IdrErrorKind::InvalidArgument, "null argument");
        return -(IdrErrorKind::InvalidArgument as c_int);
    }
    let eng = &*(engine as *mut Engine);
    let json = match CStr::from_ptr(identity_json).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error_kind(IdrErrorKind::InvalidArgument, "invalid utf8 identity json");
            return -(IdrErrorKind::InvalidArgument as c_int);
        }
    };
    match eng.set_dp_identity_json(json) {
        Ok(()) => 0,
        Err(e) => map_err(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn idr_last_error_code() -> u32 {
    last_error_code()
}

/// Copies last error message into `buf` (NUL-terminated when capacity allows).
/// Returns bytes written excluding NUL, or -1 on null buf.
#[no_mangle]
pub unsafe extern "C" fn idr_last_error_message(buf: *mut c_char, capacity: usize) -> c_int {
    if buf.is_null() || capacity == 0 {
        return -1;
    }
    let msg = last_error_message();
    let cstr = CString::new(msg.replace('\0', "")).unwrap_or_default();
    let bytes = cstr.as_bytes_with_nul();
    let n = bytes.len().min(capacity);
    ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, buf, n);
    if n < bytes.len() {
        *buf.add(capacity - 1) = 0;
    }
    (n.saturating_sub(1)) as c_int
}
