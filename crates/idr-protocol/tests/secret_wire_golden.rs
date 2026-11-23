//! P1-10 / R7: wrapping credentials in `Secret<T>` must not change a single wire byte or
//! signature. Frozen JSON literals (written in struct field order) must round-trip exactly,
//! signatures computed over the literal JSON must still verify through the structs, and the
//! postcard `ClientHello` must encode exactly like a plain-`String` mirror.

use ed25519_dalek::SigningKey;
use idr_protocol::crypto::sign_json_canonical;
use idr_protocol::quic_control::ClientHello;
use idr_protocol::signaling::EnsureRelayConnectionCommand;
use idr_protocol::webrtc_ice::IceServer;
use idr_protocol::webrtc_signaling::{ByorIceServer, SourceAgentIdentity, WebRtcSessionOffer};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

fn roundtrip<T: Serialize + DeserializeOwned + std::fmt::Debug>(literal: &str) -> T {
    let v: T = serde_json::from_str(literal).expect(literal);
    assert_eq!(
        serde_json::to_string(&v).unwrap(),
        literal,
        "wire JSON changed"
    );
    v
}

fn assert_no_leak<T: std::fmt::Debug>(v: &T, secrets: &[&str]) {
    let printed = format!("{v:?}");
    for s in secrets {
        assert!(!printed.contains(s), "Debug leaks {s}: {printed}");
    }
}

const KEY: [u8; 32] = [7; 32];

fn sign_literal(literal: &str) -> String {
    let mut v: Value = serde_json::from_str(literal).unwrap();
    v.as_object_mut().unwrap().remove("signature");
    sign_json_canonical(&v, &SigningKey::from_bytes(&KEY)).unwrap()
}

#[test]
fn ice_servers_and_source_identity() {
    let ice: IceServer = roundtrip(
        r#"{"urls":["turn:turn.idr.to:3478"],"username":"1700:s:src","credential":"turn-secret-1"}"#,
    );
    assert_no_leak(&ice, &["turn-secret-1"]);
    let byor: ByorIceServer = roundtrip(
        r#"{"urls":["turn:byor.example:3478"],"username":"u","credential":"byor-secret-2","region":"eu"}"#,
    );
    assert_no_leak(&byor, &["byor-secret-2"]);
    let src: SourceAgentIdentity = roundtrip(
        r#"{"auth_mode":"bearer","source_id":"ski","sdk_version":"1","auth_token":"bearer-secret-3"}"#,
    );
    assert_no_leak(&src, &["bearer-secret-3"]);
}

#[test]
fn webrtc_offer_bytes_and_presence_signature_unchanged() {
    let body = r#"{"version":1,"message_type":"webrtc_session_offer","message_id":"019372b4-6b1e-7cc2-9a59-0b5c9f0e2a11","session_id":"7f3e0c52-9a43-4b8e-8d0e-6a6f2b0f6e10","target_fqhn":"gpu--acme.idr.to","source":{"auth_mode":"bearer","auth_token":"bearer-secret-3"},"sdp":{"sdp_type":"offer","sdp":"v=0"},"ice":{"relay_mode":"platform","stun_policy":"google_and_idr","stun_servers":[{"urls":["stun:stun.idr.to:3478"]}],"ice_transport_policy":"all","p2p_only":false},"session_token":"tok:session-secret-4","issued_at":"2026-11-21T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","presence_generation":3,"signature":"SIG"}"#;
    let probe: Result<WebRtcSessionOffer, _> = serde_json::from_str(body);
    let literal = body.replace("SIG", &sign_literal(body));
    let offer: WebRtcSessionOffer = roundtrip(&literal);
    assert!(probe.is_ok());
    let key = SigningKey::from_bytes(&KEY).verifying_key();
    offer
        .verify_presence_signature(&key)
        .expect("signature over the old wire bytes must verify");
    assert_no_leak(&offer, &["session-secret-4", "bearer-secret-3"]);
}

#[test]
fn ensure_relay_command_bytes_and_signature_unchanged() {
    let body = r#"{"version":1,"message_type":"ensure_relay_connection","message_id":"019372b4-6b1e-7cc2-9a59-0b5c9f0e2a11","command_id":"019372b4-6b1e-7cc2-9a59-0b5c9f0e2a12","session_id":"7f3e0c52-9a43-4b8e-8d0e-6a6f2b0f6e10","target_fqhn":"gpu--acme.idr.to","relay":{"relay_id":"relay-eu-2","ipv4":"203.0.113.7","ipv6":null,"port":443,"server_name":"relay-eu-2.idr.to","alpn":"idr-relay-v1","region":"eu"},"connection_token":"conn-secret-5","connection_epoch":9,"issued_at":"2026-11-21T10:00:00Z","expires_at":"2099-01-01T00:00:00Z","presence_generation":3,"signature":"SIG"}"#;
    let literal = body.replace("SIG", &sign_literal(body));
    let cmd: EnsureRelayConnectionCommand = roundtrip(&literal);
    cmd.verify(&SigningKey::from_bytes(&KEY).verifying_key())
        .expect("signature over the old wire bytes must verify");
    assert_no_leak(&cmd, &["conn-secret-5"]);
}

#[test]
fn client_hello_postcard_bytes_unchanged() {
    #[derive(Serialize)]
    struct Mirror<'a> {
        protocol_version: u32,
        message_id: uuid::Uuid,
        session_id: uuid::Uuid,
        target_fqhn: &'a str,
        target_identity: &'a str,
        connection_token: &'a str,
        connection_epoch: u64,
        relay_id: &'a str,
    }
    let literal = r#"{"protocol_version":1,"message_id":"019372b4-6b1e-7cc2-9a59-0b5c9f0e2a11","session_id":"7f3e0c52-9a43-4b8e-8d0e-6a6f2b0f6e10","target_fqhn":"gpu--acme.idr.to","target_identity":"pub","connection_token":"conn-secret-6","connection_epoch":9,"relay_id":"relay-eu-2"}"#;
    let hello: ClientHello = roundtrip(literal);
    let mirror = Mirror {
        protocol_version: 1,
        message_id: hello.message_id,
        session_id: hello.connection_id,
        target_fqhn: "gpu--acme.idr.to",
        target_identity: "pub",
        connection_token: "conn-secret-6",
        connection_epoch: 9,
        relay_id: "relay-eu-2",
    };
    assert_eq!(
        postcard::to_allocvec(&hello).unwrap(),
        postcard::to_allocvec(&mirror).unwrap()
    );
    let back: ClientHello = postcard::from_bytes(&postcard::to_allocvec(&mirror).unwrap()).unwrap();
    assert_eq!(back, hello);
    assert_no_leak(&hello, &["conn-secret-6"]);
}
