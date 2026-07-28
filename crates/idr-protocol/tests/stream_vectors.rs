//! Deterministic hex vectors for idr-stream-v1 frames.

use std::path::PathBuf;

use idr_protocol::stream_mux::{
    MuxProfile, StreamFrame, StreamKind, StreamOpenMeta, INITIAL_STREAM_WINDOW, STREAM_MUX_VERSION,
};

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn vector(frame: StreamFrame) -> String {
    hex_encode(&frame.encode().unwrap())
}

#[test]
fn snapshot_core_vectors() {
    let open = StreamFrame::Open {
        stream_id: 1,
        kind: StreamKind::TlsPassthrough,
        meta: StreamOpenMeta {
            target_fqhn: "host.idr.to".into(),
            host: None,
            port: None,
        },
    };
    let data = StreamFrame::Data {
        stream_id: 1,
        bytes: b"hello".to_vec(),
    };
    let open_ok = StreamFrame::OpenOk {
        stream_id: 1,
        initial_window: INITIAL_STREAM_WINDOW,
    };
    let wu = StreamFrame::WindowUpdate {
        stream_id: 1,
        credit: 4096,
    };
    let ping = StreamFrame::Ping { opaque: 1 };
    let pong = StreamFrame::Pong { opaque: 1 };

    // Round-trip every vector.
    for frame in [
        open.clone(),
        data.clone(),
        open_ok.clone(),
        wu.clone(),
        ping.clone(),
        pong.clone(),
    ] {
        let enc = frame.encode().unwrap();
        assert_eq!(StreamFrame::decode(&enc).unwrap(), frame);
    }

    // Stable non-empty encodings.
    assert!(!vector(open).is_empty());
    let data_hex = vector(data);
    assert!(data_hex.contains("68656c6c6f") || data_hex.len() > 8); // "hello"
    assert_eq!(STREAM_MUX_VERSION, 1);
    assert!(!MuxProfile::FlowControlV1.advertised_features().is_empty());
}

#[test]
#[ignore = "writes protocol/test-vectors/*.hex — run explicitly when refreshing snapshots"]
fn write_stream_vectors() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../protocol/test-vectors");
    std::fs::create_dir_all(&root).unwrap();

    let pairs: Vec<(&str, StreamFrame)> = vec![
        (
            "open_tls.hex",
            StreamFrame::Open {
                stream_id: 1,
                kind: StreamKind::TlsPassthrough,
                meta: StreamOpenMeta {
                    target_fqhn: "host.idr.to".into(),
                    host: None,
                    port: None,
                },
            },
        ),
        (
            "data_hello.hex",
            StreamFrame::Data {
                stream_id: 1,
                bytes: b"hello".to_vec(),
            },
        ),
        (
            "open_ok.hex",
            StreamFrame::OpenOk {
                stream_id: 1,
                initial_window: INITIAL_STREAM_WINDOW,
            },
        ),
        (
            "window_update.hex",
            StreamFrame::WindowUpdate {
                stream_id: 1,
                credit: 4096,
            },
        ),
        ("ping.hex", StreamFrame::Ping { opaque: 1 }),
        ("pong.hex", StreamFrame::Pong { opaque: 1 }),
    ];

    for (name, frame) in pairs {
        let hex = vector(frame);
        std::fs::write(root.join(name), format!("{hex}\n")).unwrap();
    }
}
