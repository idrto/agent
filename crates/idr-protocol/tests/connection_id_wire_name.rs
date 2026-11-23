//! P1-22 / R1: the Rust field is `connection_id` but the wire name is, and stays,
//! `session_id` (docs/observability/02). Every renamed field must carry the serde rename,
//! otherwise the JSON key (and every signature over it) would silently change.

#[test]
fn every_connection_id_field_keeps_the_session_id_wire_name() {
    let mut checked = 0;
    for file in ["webrtc_signaling.rs", "signaling.rs", "quic_control.rs"] {
        let path = format!("{}/src/{file}", env!("CARGO_MANIFEST_DIR"));
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replace("\r\n", "\n");
        let lines: Vec<&str> = text.lines().collect();
        for (i, l) in lines.iter().enumerate() {
            if l.trim() == "pub connection_id: Uuid," {
                assert!(
                    i > 0 && lines[i - 1].trim() == r#"#[serde(rename = "session_id")]"#,
                    "{file}:{} `connection_id` without #[serde(rename = \"session_id\")]",
                    i + 1
                );
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 14, "the 14 wire message fields");
}

#[test]
fn json_key_is_session_id_not_connection_id() {
    let hello: idr_protocol::quic_control::ClientHello = serde_json::from_str(
        r#"{"protocol_version":1,"message_id":"019372b4-6b1e-7cc2-9a59-0b5c9f0e2a11","session_id":"7f3e0c52-9a43-4b8e-8d0e-6a6f2b0f6e10","target_fqhn":"a","target_identity":"b","connection_token":"c","connection_epoch":1,"relay_id":"r"}"#,
    )
    .unwrap();
    let out = serde_json::to_string(&hello).unwrap();
    assert!(
        out.contains(r#""session_id":"7f3e0c52-9a43-4b8e-8d0e-6a6f2b0f6e10""#),
        "{out}"
    );
    assert!(!out.contains("connection_id"), "{out}");
}
