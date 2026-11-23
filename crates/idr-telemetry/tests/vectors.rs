//! Shared conformance vectors (spec/telemetry/vectors). The Dart package runs the same files.

use idr_telemetry::{is_uuid, new_id, redact, LocalContext, Secret, TraceContext};
use serde_json::Value;

fn vectors(name: &str) -> Value {
    let path = format!(
        "{}/../../spec/telemetry/vectors/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(&path).expect(&path)).expect(&path)
}

#[test]
fn traceparent_vectors() {
    let v = vectors("ids.json");
    for c in v["traceparent_valid"].as_array().unwrap() {
        let input = c["input"].as_str().unwrap();
        let t = TraceContext::parse(input).unwrap_or_else(|| panic!("should parse: {input}"));
        assert_eq!(t.trace_id_hex(), c["trace_id"].as_str().unwrap(), "{input}");
        assert_eq!(t.span_id_hex(), c["span_id"].as_str().unwrap(), "{input}");
        assert_eq!(t.sampled, c["sampled"].as_bool().unwrap(), "{input}");
    }
    for c in v["traceparent_invalid"].as_array().unwrap() {
        let input = c["input"].as_str().unwrap();
        assert!(
            TraceContext::parse(input).is_none(),
            "should reject ({}): {input}",
            c["why"]
        );
    }
    for c in v["traceparent_format"].as_array().unwrap() {
        let t = TraceContext::parse(&format!(
            "00-{}-{}-{}",
            c["trace_id"].as_str().unwrap(),
            c["span_id"].as_str().unwrap(),
            if c["sampled"].as_bool().unwrap() {
                "01"
            } else {
                "00"
            }
        ))
        .unwrap();
        assert_eq!(t.to_traceparent(), c["output"].as_str().unwrap());
    }
    let root = TraceContext::new_root();
    assert_eq!(TraceContext::parse(&root.to_traceparent()), Some(root));
}

#[test]
fn uuid_v7_vectors() {
    let v = vectors("ids.json");
    let re = regex::Regex::new(v["uuid_pattern"].as_str().unwrap()).unwrap();
    let ids: Vec<String> = (0..10_000).map(|_| new_id()).collect();
    for id in &ids {
        assert!(re.is_match(id) && is_uuid(id), "{id}");
    }
    for w in ids.windows(2) {
        assert!(w[0] < w[1], "not strictly increasing: {} {}", w[0], w[1]);
    }
}

#[test]
fn ctx_vectors() {
    let v = vectors("ctx.json");
    for c in v["cases"].as_array().unwrap() {
        let input = c["input"].as_str().unwrap();
        let (ctx, invalid) = LocalContext::parse(input);
        assert_eq!(
            ctx.trace.map(|t| t.to_traceparent()).as_deref(),
            c["traceparent"].as_str(),
            "{input}"
        );
        assert_eq!(
            ctx.session_id.as_deref(),
            c["session_id"].as_str(),
            "{input}"
        );
        assert_eq!(
            ctx.operation_id.as_deref(),
            c["operation_id"].as_str(),
            "{input}"
        );
        assert_eq!(
            ctx.transfer_id.as_deref(),
            c["transfer_id"].as_str(),
            "{input}"
        );
        let want: Vec<&str> = c["invalid"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        assert_eq!(invalid, want, "{input}");
    }
    for c in v["format"].as_array().unwrap() {
        let ctx = LocalContext {
            trace: c["traceparent"].as_str().and_then(TraceContext::parse),
            session_id: c["session_id"].as_str().map(String::from),
            operation_id: c["operation_id"].as_str().map(String::from),
            transfer_id: c["transfer_id"].as_str().map(String::from),
        };
        assert_eq!(ctx.to_json(), c["output"].as_str().unwrap());
    }
}

#[test]
fn redaction_vectors() {
    let v = vectors("redaction.json");
    for c in v["cases"].as_array().unwrap() {
        let input = c["input"].as_str().unwrap();
        assert_eq!(
            redact(input),
            c["expected"].as_str().unwrap(),
            "case {}",
            c["name"]
        );
        // Idempotent.
        assert_eq!(
            redact(&redact(input)),
            redact(input),
            "idempotent {}",
            c["name"]
        );
    }
}

#[test]
fn redaction_stays_fast_on_adversarial_input() {
    let inputs = [
        "10".repeat(3000),
        format!("{}@", "a".repeat(6000)),
        "ab1.".repeat(3000),
        "x ".repeat(6000),
        "/a".repeat(6000),
        "a:".repeat(6000),
        "1.".repeat(6000),
    ];
    for s in &inputs {
        let t = std::time::Instant::now();
        let _ = redact(s);
        assert!(
            t.elapsed() < std::time::Duration::from_millis(200),
            "{} took {:?}",
            &s[..8],
            t.elapsed()
        );
    }
}

#[test]
fn secret_is_wire_transparent_and_never_printed() {
    #[derive(serde::Serialize, serde::Deserialize, Debug)]
    struct Hello {
        connection_token: Secret<String>,
    }
    let wire = r#"{"connection_token":"tok-123"}"#;
    let h: Hello = serde_json::from_str(wire).unwrap();
    assert_eq!(
        serde_json::to_string(&h).unwrap(),
        wire,
        "wire bytes unchanged"
    );
    assert_eq!(h.connection_token.expose(), "tok-123");
    let printed = format!("{h:?} {}", h.connection_token);
    assert!(!printed.contains("tok-123"), "{printed}");
    assert!(printed.contains("[REDACTED]"));
}
