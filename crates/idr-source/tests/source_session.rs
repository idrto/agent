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
