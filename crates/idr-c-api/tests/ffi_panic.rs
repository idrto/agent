//! P1-12: a panic inside an export never crosses the C ABI (which would abort the Flutter
//! host). It returns IDR_ERR_PANIC, sets the last error, writes a crash record, and poisons
//! the engine so later calls fail fast — while the diagnostic exports keep working.
//! Own test binary: poisoning is process-wide.

use std::ffi::{c_char, CStr};

const IDR_ERR_PANIC: i32 = -20;

#[test]
fn panic_is_contained_reported_and_poisons_the_engine() {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = idr_telemetry::Config::new("idr-c-api", "test");
    cfg.log_root = Some(root.path().into());
    cfg.stdout = idr_telemetry::StdoutFormat::Off;
    let guard = idr_telemetry::init(cfg).unwrap();

    assert_eq!(
        idr_c_api::idr_test_panic(),
        IDR_ERR_PANIC,
        "panic mapped to IDR_ERR_PANIC"
    );
    assert_eq!(unsafe { idr_c_api::idr_last_error_code() }, 20);
    let mut buf = [0 as c_char; 256];
    let n = unsafe { idr_c_api::idr_last_error_message(buf.as_mut_ptr(), buf.len()) };
    assert!(n > 0);
    let msg = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy();
    assert!(msg.contains("poisoned"), "{msg}");

    // Poisoned: guarded exports fail fast; diagnostic exports still answer.
    let engine = unsafe { idr_c_api::idr_engine_create(std::ptr::null()) };
    assert!(engine.is_null());
    assert_eq!(unsafe { idr_c_api::idr_last_error_code() }, 20);
    assert_eq!(idr_c_api::idr_abi_version(), idr_c_api::ABI_VERSION);
    assert!(idr_telemetry::is_poisoned());

    drop(guard);
    let crash = std::fs::read_dir(root.path().join("crash"))
        .unwrap()
        .count();
    assert_eq!(crash, 1, "one crash record written");
}
