//! C ABI smoke tests (mock backend).

use std::ffi::CString;
use std::ptr;

use idr_c_api::{
    idr_abi_version, idr_connect, idr_disconnect, idr_engine_create, idr_engine_destroy,
    idr_open_stream, idr_poll_events, idr_stream_half_close, idr_stream_read, idr_stream_write,
    IdrEngineConfig, IdrEvent, ABI_VERSION, IDR_AUTH_BEARER, IDR_EVENT_CONNECTED,
    IDR_EVENT_STREAM_OPENED,
};

fn test_config(use_mock: u32, auth: Option<&CString>) -> (IdrEngineConfig, CString, CString) {
    let source_id = CString::new("ffi-test").unwrap();
    let region = CString::new("test").unwrap();
    let cfg = IdrEngineConfig {
        abi_version: ABI_VERSION,
        struct_size: std::mem::size_of::<IdrEngineConfig>() as u32,
        use_mock,
        source_id: source_id.as_ptr(),
        source_region: region.as_ptr(),
        auth_token: auth.map(|a| a.as_ptr()).unwrap_or(ptr::null()),
        auth_mode: IDR_AUTH_BEARER,
        discovery_url: ptr::null(),
        discovery_key: ptr::null(),
        insecure_dev: 0,
    };
    (cfg, source_id, region)
}

#[test]
fn abi_version_matches() {
    assert_eq!(idr_abi_version(), ABI_VERSION);
}

#[test]
fn mock_round_trip_bytes() {
    let token = CString::new("test-bearer-token").unwrap();
    let (cfg, _id, _region) = test_config(1, Some(&token));

    let engine = unsafe { idr_engine_create(&cfg) };
    assert!(!engine.is_null());

    let fqhn = CString::new("demo.idr.to").unwrap();
    let mut session = 0u64;
    let rc = unsafe { idr_connect(engine, fqhn.as_ptr(), &mut session) };
    assert_eq!(rc, 0, "connect failed");
    assert!(session > 0);

    let mut events = [IdrEvent {
        kind: 0,
        session_id: 0,
        stream_id: 0,
        code: 0,
        len: 0,
    }; 8];
    let mut count = 0usize;
    unsafe {
        idr_poll_events(engine, events.as_mut_ptr(), events.len(), &mut count);
    }
    assert!(count >= 1);
    assert_eq!(events[0].kind, IDR_EVENT_CONNECTED);

    let service = CString::new("http").unwrap();
    let mut stream = 0u64;
    let rc = unsafe { idr_open_stream(engine, session, service.as_ptr(), &mut stream) };
    assert_eq!(rc, 0, "open_stream failed");

    unsafe {
        idr_poll_events(engine, events.as_mut_ptr(), events.len(), &mut count);
    }
    assert!(events
        .iter()
        .take(count)
        .any(|e| e.kind == IDR_EVENT_STREAM_OPENED));

    let payload = b"hello-ffi";
    let mut written = 0usize;
    let rc = unsafe {
        idr_stream_write(
            engine,
            session,
            stream,
            payload.as_ptr(),
            payload.len(),
            &mut written,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(written, payload.len());

    let mut buf = [0u8; 64];
    let mut nread = 0usize;
    let rc = unsafe {
        idr_stream_read(
            engine,
            session,
            stream,
            buf.as_mut_ptr(),
            buf.len(),
            &mut nread,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(&buf[..nread], payload);

    assert_eq!(unsafe { idr_stream_half_close(engine, session, stream) }, 0);
    assert_eq!(unsafe { idr_disconnect(engine, session) }, 0);
    unsafe { idr_engine_destroy(engine) };
}

#[test]
fn rejects_missing_auth_token() {
    let (cfg, _id, _region) = test_config(1, None);
    let engine = unsafe { idr_engine_create(&cfg) };
    assert!(engine.is_null());
}

#[test]
fn rejects_native_without_backend() {
    let token = CString::new("tok").unwrap();
    let (cfg, _id, _region) = test_config(0, Some(&token));
    let engine = unsafe { idr_engine_create(&cfg) };
    // Without --features native this fails; with native it fails on missing discovery_url.
    assert!(engine.is_null());
}

#[test]
fn null_config_fails() {
    let engine = unsafe { idr_engine_create(ptr::null()) };
    assert!(engine.is_null());
}
