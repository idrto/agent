//! C ABI for Target desktop crypto (`IdrCrypto` via Dart FFI).
//!
//! Artifacts:
//! - Windows: `idr_dp.dll`
//! - macOS: `libidr_dp.dylib`
//! - Linux: `libidr_dp.so`

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uchar};
use std::ptr;
use std::slice;

use idr_dp::{build_csr, generate_ed25519_json, sign, sign_csr_with_ca_jwk_json, sign_json, ski};

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = RefCell::new(None);
}

fn set_error(msg: impl Into<String>) {
    LAST_ERROR.with(|e| *e.borrow_mut() = Some(msg.into()));
}

fn clear_error() {
    LAST_ERROR.with(|e| *e.borrow_mut() = None);
}

unsafe fn write_cstring(out: *mut *mut c_char, s: String) -> c_int {
    match CString::new(s) {
        Ok(c) => {
            *out = c.into_raw();
            0
        }
        Err(_) => {
            set_error("string contains interior NUL");
            -2
        }
    }
}

/// Free a string returned by this ABI.
#[no_mangle]
pub unsafe extern "C" fn idr_dp_string_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

/// Last error message (valid until next call). Returns null if none.
#[no_mangle]
pub unsafe extern "C" fn idr_dp_last_error() -> *const c_char {
    thread_local! {
        static BUF: RefCell<Option<CString>> = RefCell::new(None);
    }
    LAST_ERROR.with(|e| {
        let msg = e.borrow().clone();
        BUF.with(|b| {
            *b.borrow_mut() = msg.and_then(|m| CString::new(m).ok());
            b.borrow()
                .as_ref()
                .map(|c| c.as_ptr())
                .unwrap_or(ptr::null())
        })
    })
}

/// Generate Ed25519 key material JSON (private_pem, public_pem, public_b64url, public_jwk, ski).
#[no_mangle]
pub unsafe extern "C" fn idr_dp_generate_ed25519(out_json: *mut *mut c_char) -> c_int {
    clear_error();
    if out_json.is_null() {
        set_error("null out_json");
        return -1;
    }
    match generate_ed25519_json() {
        Ok(json) => write_cstring(out_json, json),
        Err(e) => {
            set_error(e.to_string());
            -3
        }
    }
}

/// Build PKCS#10 CSR PEM for an existing private key + FQHN.
#[no_mangle]
pub unsafe extern "C" fn idr_dp_build_csr(
    private_pem: *const c_char,
    fqhn: *const c_char,
    out_pem: *mut *mut c_char,
) -> c_int {
    clear_error();
    if private_pem.is_null() || fqhn.is_null() || out_pem.is_null() {
        set_error("null argument");
        return -1;
    }
    let pem = match CStr::from_ptr(private_pem).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_error("private_pem not utf8");
            return -2;
        }
    };
    let host = match CStr::from_ptr(fqhn).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_error("fqhn not utf8");
            return -2;
        }
    };
    match build_csr(pem, host) {
        Ok(csr) => write_cstring(out_pem, csr),
        Err(e) => {
            set_error(e.to_string());
            -3
        }
    }
}

/// Sign message bytes → base64url signature.
#[no_mangle]
pub unsafe extern "C" fn idr_dp_sign(
    private_pem: *const c_char,
    msg: *const c_uchar,
    msg_len: usize,
    out_b64: *mut *mut c_char,
) -> c_int {
    clear_error();
    if private_pem.is_null() || out_b64.is_null() || (msg.is_null() && msg_len > 0) {
        set_error("null argument");
        return -1;
    }
    let pem = match CStr::from_ptr(private_pem).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_error("private_pem not utf8");
            return -2;
        }
    };
    let bytes = if msg_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(msg, msg_len)
    };
    match sign(pem, bytes) {
        Ok(sig) => write_cstring(out_b64, sig),
        Err(e) => {
            set_error(e.to_string());
            -3
        }
    }
}

/// Sign JSON UTF-8 → base64url signature.
#[no_mangle]
pub unsafe extern "C" fn idr_dp_sign_json(
    private_pem: *const c_char,
    json: *const c_char,
    out_b64: *mut *mut c_char,
) -> c_int {
    clear_error();
    if private_pem.is_null() || json.is_null() || out_b64.is_null() {
        set_error("null argument");
        return -1;
    }
    let pem = match CStr::from_ptr(private_pem).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_error("private_pem not utf8");
            return -2;
        }
    };
    let body = match CStr::from_ptr(json).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_error("json not utf8");
            return -2;
        }
    };
    match sign_json(pem, body) {
        Ok(sig) => write_cstring(out_b64, sig),
        Err(e) => {
            set_error(e.to_string());
            -3
        }
    }
}

/// SKI from public key base64url (`x`).
#[no_mangle]
pub unsafe extern "C" fn idr_dp_ski(
    public_b64url: *const c_char,
    out_ski: *mut *mut c_char,
) -> c_int {
    clear_error();
    if public_b64url.is_null() || out_ski.is_null() {
        set_error("null argument");
        return -1;
    }
    let x = match CStr::from_ptr(public_b64url).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_error("public_b64url not utf8");
            return -2;
        }
    };
    write_cstring(out_ski, ski(x))
}

/// Sign device CSR with admin CA private JWK → JSON `{leaf_pem, chain_pem}`.
/// `host` may be null.
#[no_mangle]
pub unsafe extern "C" fn idr_dp_sign_csr(
    csr_pem: *const c_char,
    ca_private_jwk_json: *const c_char,
    issuer_ski: *const c_char,
    host: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    clear_error();
    if csr_pem.is_null()
        || ca_private_jwk_json.is_null()
        || issuer_ski.is_null()
        || out_json.is_null()
    {
        set_error("null argument");
        return -1;
    }
    let csr = match CStr::from_ptr(csr_pem).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_error("csr_pem not utf8");
            return -2;
        }
    };
    let jwk = match CStr::from_ptr(ca_private_jwk_json).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_error("ca_private_jwk_json not utf8");
            return -2;
        }
    };
    let issuer = match CStr::from_ptr(issuer_ski).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_error("issuer_ski not utf8");
            return -2;
        }
    };
    let host_opt = if host.is_null() {
        None
    } else {
        match CStr::from_ptr(host).to_str() {
            Ok(s) => Some(s),
            Err(_) => {
                set_error("host not utf8");
                return -2;
            }
        }
    };
    match sign_csr_with_ca_jwk_json(csr, jwk, issuer, host_opt) {
        Ok(json) => write_cstring(out_json, json),
        Err(e) => {
            set_error(e.to_string());
            -3
        }
    }
}
