use std::sync::{Arc, Mutex};

use idr_protocol::stream_mux::{StreamFrame, StreamKind, INITIAL_STREAM_WINDOW};
use idr_protocol::webrtc_signaling::SourceAuthMode;
use idr_signaling::mock::MockSignalingClient;
use idr_source::SourceRuntime;
use idr_webrtc::{PeerTransport, RecordingPeer};

struct SlotPeer {
    inner: RecordingPeer,
    sent_sink: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Auto-enqueue OpenOk when Open is sent (FlowControlV1 path).
    auto_open_ok: bool,
    pending_in: Vec<Vec<u8>>,
}

#[async_trait::async_trait]
impl PeerTransport for SlotPeer {
    async fn start(&mut self, request: idr_webrtc::PeerConnectRequest) -> idr_core::Result<()> {
        self.inner.start(request).await
    }
    async fn set_remote_description(&mut self, sdp_type: &str, sdp: &str) -> idr_core::Result<()> {
        self.inner.set_remote_description(sdp_type, sdp).await
    }
    async fn create_local_description(&mut self) -> idr_core::Result<()> {
        self.inner.create_local_description().await
    }
    fn add_remote_candidate(&mut self, candidate: &str, mid: &str) -> idr_core::Result<()> {
        self.inner.add_remote_candidate(candidate, mid)
    }
    fn send_binary(&mut self, message: &[u8]) -> idr_core::Result<()> {
        self.sent_sink.lock().unwrap().push(message.to_vec());
        if let Ok(StreamFrame::ServicesCatalogRequest) = StreamFrame::decode(message) {
            let catalog = StreamFrame::ServicesCatalog {
                services: vec!["http".into(), "ollama".into()],
            };
            self.pending_in.push(catalog.encode().unwrap());
            let detailed = StreamFrame::ServicesCatalogDetailed {
                entries: vec![
                    idr_protocol::stream_mux::ServiceCatalogEntry {
                        name: "http".into(),
                        kind: idr_protocol::stream_mux::ServiceTransportKind::Http,
                        credential_mode: idr_protocol::stream_mux::CredentialMode::Target,
                        require_upstream_tls: false,
                    },
                    idr_protocol::stream_mux::ServiceCatalogEntry {
                        name: "ollama".into(),
                        kind: idr_protocol::stream_mux::ServiceTransportKind::Http,
                        credential_mode: idr_protocol::stream_mux::CredentialMode::Target,
                        require_upstream_tls: false,
                    },
                ],
            };
            self.pending_in.push(detailed.encode().unwrap());
        }
        if self.auto_open_ok {
            if let Ok(StreamFrame::Open { stream_id, .. }) = StreamFrame::decode(message) {
                let ok = StreamFrame::OpenOk {
                    stream_id,
                    initial_window: INITIAL_STREAM_WINDOW,
                };
                self.pending_in.push(ok.encode().unwrap());
            }
        }
        self.inner.send_binary(message)
    }
    async fn next_event(&mut self) -> idr_core::Result<idr_webrtc::PeerEvent> {
        if let Some(bytes) = self.pending_in.pop() {
            return Ok(idr_webrtc::PeerEvent::BinaryMessage(bytes));
        }
        self.inner.next_event().await
    }
    fn close(&mut self) {
        self.inner.close();
    }
}

#[tokio::test]
async fn open_stream_emits_open_frame_on_dc() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let sent2 = sent.clone();
    let mut runtime = SourceRuntime::with_auth(
        Box::new(MockSignalingClient::default()),
        move || {
            Box::new(SlotPeer {
                inner: RecordingPeer::new(),
                sent_sink: sent2.clone(),
                auto_open_ok: true,
                pending_in: Vec::new(),
            })
        },
        "src",
        "eu",
        SourceAuthMode::Bearer,
        Some("test-token".into()),
    );
    let mut session = runtime.connect("t.idr.to").await.unwrap();
    session.open_named_stream("http").await.unwrap();
    let frames = sent.lock().unwrap().clone();
    assert!(!frames.is_empty());
    let decoded = frames
        .iter()
        .map(|f| StreamFrame::decode(f).unwrap())
        .find(|f| matches!(f, StreamFrame::Open { .. }))
        .expect("expected Open frame after catalog request");
    match decoded {
        StreamFrame::Open {
            stream_id,
            kind,
            meta,
        } => {
            assert_eq!(stream_id, 1);
            assert_eq!(stream_id % 2, 1, "source-initiated odd id");
            assert_eq!(kind, StreamKind::HttpPassthrough);
            assert_eq!(meta.target_fqhn, "t.idr.to");
            assert_eq!(meta.service_name.as_deref(), Some("http"));
        }
        other => panic!("expected Open, got {other:?}"),
    }
}

#[tokio::test]
async fn anonymous_connect_rejected() {
    let mut runtime = SourceRuntime::new(
        Box::new(MockSignalingClient::default()),
        || Box::new(RecordingPeer::new()),
        "src",
        "eu",
    );
    let err = match runtime.connect("t.idr.to").await {
        Err(e) => e,
        Ok(_) => panic!("expected authentication failure"),
    };
    assert_eq!(err.kind(), idr_core::IdrErrorKind::AuthenticationFailed);
}

#[tokio::test]
async fn unknown_service_fails() {
    let mut runtime = SourceRuntime::with_auth(
        Box::new(MockSignalingClient::default()),
        || Box::new(RecordingPeer::new()),
        "source-test-2",
        "eu-central",
        SourceAuthMode::Bearer,
        Some("test-token".into()),
    );
    let mut session = runtime.connect("host.example.idr.to").await.unwrap();
    let err = match session.open_named_stream("").await {
        Err(e) => e,
        Ok(_) => panic!("expected service_not_found"),
    };
    assert_eq!(err.kind(), idr_core::IdrErrorKind::ServiceNotFound);
}

#[tokio::test]
async fn flow_control_write_respects_window() {
    use idr_core::flow::FlowController;
    let mut fc = FlowController::new(4, 100);
    assert!(fc.consume_send(4).is_ok());
    assert_eq!(
        fc.consume_send(1).unwrap_err().kind(),
        idr_core::IdrErrorKind::Backpressure
    );
}

/// Records the session request the runtime sends, then answers like the mock.
struct RecordingSignaling {
    inner: MockSignalingClient,
    seen: Arc<Mutex<Option<idr_protocol::webrtc_signaling::WebRtcSessionRequest>>>,
}

#[async_trait::async_trait]
impl idr_signaling::ephemeral::WebRtcSignalingClient for RecordingSignaling {
    async fn begin_session(
        &mut self,
        request: idr_protocol::webrtc_signaling::WebRtcSessionRequest,
    ) -> idr_core::Result<Box<dyn idr_signaling::ephemeral::EphemeralSignaling>> {
        *self.seen.lock().unwrap() = Some(request.clone());
        self.inner.begin_session(request).await
    }
}

fn connect_runtime(
    identity: Option<idr_dp::DeviceIdentity>,
) -> (
    SourceRuntime,
    Arc<Mutex<Option<idr_protocol::webrtc_signaling::WebRtcSessionRequest>>>,
) {
    let seen = Arc::new(Mutex::new(None));
    let runtime = SourceRuntime::with_auth(
        Box::new(RecordingSignaling {
            inner: MockSignalingClient::default(),
            seen: seen.clone(),
        }),
        || {
            Box::new(SlotPeer {
                inner: RecordingPeer::new(),
                sent_sink: Arc::new(Mutex::new(Vec::new())),
                auto_open_ok: true,
                pending_in: Vec::new(),
            })
        },
        "src",
        "eu",
        SourceAuthMode::Bearer,
        Some("test-token".into()),
    );
    let runtime = match identity {
        Some(id) => runtime.with_identity(id),
        None => runtime,
    };
    (runtime, seen)
}

#[tokio::test]
async fn enrolled_source_sends_a_proof_bound_to_the_session() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let x = URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes());
    let identity = idr_dp::DeviceIdentity {
        ski: "member-ski".into(),
        private_jwk: serde_json::json!({
            "kty": "OKP", "crv": "Ed25519", "x": x, "d": URL_SAFE_NO_PAD.encode([9u8; 32]),
        }),
        credential: idr_dp::CapabilityCredential {
            version: 1,
            kind: idr_dp::CredentialKind::Machine,
            entity_id: "a@acme.test".into(),
            ski: "member-ski".into(),
            public_jwk: serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": x}),
            permissions: vec![],
            zone: Some("zone-a".into()),
            host: Some("member--a@acme.test".into()),
            issuer_ski: "zone-ski".into(),
            not_before: "2026-01-01T00:00:00.000Z".into(),
            not_after: "2027-01-01T00:00:00.000Z".into(),
            package: None,
            platform_cosign: None,
            signature: "hdr.payload.sig".into(),
        },
        cert_pem: Some("LEAF".into()),
        chain_pem: Some("LEAF\nZONE\nROOT".into()),
    };
    let (mut runtime, seen) = connect_runtime(Some(identity));
    runtime.connect("t.idr.to").await.unwrap();

    let request = seen.lock().unwrap().clone().expect("session request sent");
    let proof = request
        .source_proof
        .expect("enrolled Source attaches a proof");
    assert_eq!(proof.ski, "member-ski");
    assert_eq!(proof.chain_pem, "LEAF\nZONE\nROOT");
    let vk = key.verifying_key();
    assert!(proof
        .verify_signature(&vk, request.session_id, "t.idr.to")
        .is_ok());
    assert!(proof
        .verify_signature(&vk, uuid::Uuid::new_v4(), "t.idr.to")
        .is_err());
}

#[tokio::test]
async fn unenrolled_source_sends_no_proof() {
    let (mut runtime, seen) = connect_runtime(None);
    runtime.connect("t.idr.to").await.unwrap();
    let request = seen.lock().unwrap().clone().expect("session request sent");
    assert!(request.source_proof.is_none());
}
