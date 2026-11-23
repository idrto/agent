//! P1-21: the embedded engine writes the `rust.jsonl` producer of the host's run into the
//! host's directory, and `ctx_json` parents FFI work from the host's trace with its IDs.
//! Own test binary: telemetry is process-wide.

use std::ffi::CString;

use idr_c_api::*;

#[test]
fn ctx_json_parents_engine_work_in_the_hosts_run() {
    let root = tempfile::tempdir().unwrap();
    let host_id = "019372b0-11aa-7e01-8c1d-2f6a9b0c0001";
    let init = CString::new(format!(
        r#"{{"service":"idrs","log_root":{},"app_session_id":"{host_id}","filter":"debug"}}"#,
        serde_json::Value::from(root.path().to_str().unwrap())
    ))
    .unwrap();
    assert_eq!(unsafe { idr_telemetry_init(init.as_ptr()) }, 0);
    assert_eq!(unsafe { idr_telemetry_init(init.as_ptr()) }, -2, "only once");

    let (source_id, region, token) = (
        CString::new("ffi-test").unwrap(),
        CString::new("test").unwrap(),
        CString::new("test-bearer-token").unwrap(),
    );
    let cfg = IdrEngineConfig {
        abi_version: ABI_VERSION,
        struct_size: std::mem::size_of::<IdrEngineConfig>() as u32,
        use_mock: 1,
        source_id: source_id.as_ptr(),
        source_region: region.as_ptr(),
        auth_token: token.as_ptr(),
        auth_mode: IDR_AUTH_BEARER,
        discovery_url: std::ptr::null(),
        discovery_key: std::ptr::null(),
        insecure_dev: 0,
    };
    let engine = unsafe { idr_engine_create(&cfg) };
    assert!(!engine.is_null());
    let fqhn = CString::new("demo.idr.to").unwrap();
    let ctx = CString::new(
        r#"{"traceparent":"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01","session_id":"019372b4-6b1e-7cc2-9a59-0b5c9f0e2a11"}"#,
    )
    .unwrap();
    let mut session = 0u64;
    assert_eq!(unsafe { idr_connect(engine, fqhn.as_ptr(), &mut session, ctx.as_ptr()) }, 0);
    // A failing attempt: one registered event with a stable error.type, under the host's trace.
    let bad = CString::new("not a valid name!").unwrap();
    let mut none = 0u64;
    assert!(unsafe { idr_connect(engine, bad.as_ptr(), &mut none, ctx.as_ptr()) } < 0);
    unsafe { idr_engine_destroy(engine) };
    assert_eq!(idr_telemetry_flush(), 0);
    assert_eq!(idr_telemetry_shutdown(), 0);

    let dir = root.path().join("idrs");
    let file = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .find(|e| e.file_name().to_string_lossy().ends_with(".rust.jsonl"))
        .expect("rust.jsonl producer in the host's directory");
    assert!(file.file_name().to_string_lossy().contains(host_id), "host's app_session_id");
    let records: Vec<serde_json::Value> = std::fs::read_to_string(file.path())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let call = records
        .iter()
        .find(|r| r["event"] == "ffi.call" && r["kind"] == "span")
        .expect("ffi.call span");
    assert_eq!(call["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736");
    assert_eq!(call["parent_span_id"], "00f067aa0ba902b7");
    assert_eq!(call["session_id"], "019372b4-6b1e-7cc2-9a59-0b5c9f0e2a11");
    assert_eq!(call["attrs"]["ffi.fn"], "idr_connect");
    assert_eq!(call["app_session_id"], host_id);
    let failed = records
        .iter()
        .find(|r| r["event"] == "connection.attempt.failed")
        .expect("connection.attempt.failed");
    assert_eq!(failed["level"], "WARN");
    assert_eq!(failed["error"]["type"], "invalid_argument");
    assert_eq!(failed["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736");
    assert_eq!(failed["session_id"], "019372b4-6b1e-7cc2-9a59-0b5c9f0e2a11");
    assert_eq!(records.last().unwrap()["event"], "app.stopping");
}
