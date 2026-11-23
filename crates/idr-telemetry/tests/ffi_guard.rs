//! Own test binary: poisoning is process-wide, so the steps run in one sequential test.
#![cfg(feature = "subscriber")]

#[test]
fn panic_does_not_cross_the_abi_and_poisons_the_engine() {
    let ok: i32 = idr_telemetry::ffi_guard("idr_connect", -99, || 7);
    assert_eq!(ok, 7);
    assert!(!idr_telemetry::is_poisoned());
    let r: i32 = idr_telemetry::ffi_guard("idr_connect", -99, || panic!("boom"));
    assert_eq!(r, -99, "panic mapped to the error code");
    assert!(idr_telemetry::is_poisoned());
    let later: i32 = idr_telemetry::ffi_guard("idr_open_stream", -99, || 1);
    assert_eq!(later, -99, "poisoned engine fails fast");

    // ffi_catch keeps diagnostic exports usable after poisoning.
    let code: u32 = idr_telemetry::ffi_catch("idr_last_error_code", 0, || 20);
    assert_eq!(code, 20, "ffi_catch still runs the body when poisoned");
    let caught: u32 = idr_telemetry::ffi_catch("idr_last_error_code", 7, || panic!("again"));
    assert_eq!(caught, 7);
}
