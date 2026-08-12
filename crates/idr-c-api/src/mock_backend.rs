//! Mock backend: MockSignalingClient + peer that auto-replies OpenOk and echoes DATA.
//!
//! Only for unit/FFI tests (`use_mock=1`). Product builds use the native backend.

use std::collections::VecDeque;

use async_trait::async_trait;
use idr_protocol::stream_mux::{StreamFrame, INITIAL_STREAM_WINDOW};
use idr_protocol::webrtc_signaling::SourceAuthMode;
use idr_signaling::mock::MockSignalingClient;
use idr_source::SourceRuntime;
use idr_webrtc::transport::{PeerConnectRequest, PeerEvent, PeerTransport};
use idr_webrtc::RecordingPeer;

struct AutoOkPeer {
    inner: RecordingPeer,
    pending: VecDeque<Vec<u8>>,
}

impl AutoOkPeer {
    fn new() -> Self {
        Self {
            inner: RecordingPeer::new(),
            pending: VecDeque::new(),
        }
    }
}

#[async_trait]
impl PeerTransport for AutoOkPeer {
    async fn start(&mut self, request: PeerConnectRequest) -> idr_core::Result<()> {
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
        if let Ok(StreamFrame::Open { stream_id, .. }) = StreamFrame::decode(message) {
            let ok = StreamFrame::OpenOk {
                stream_id,
                initial_window: INITIAL_STREAM_WINDOW,
            };
            self.pending.push_back(ok.encode().expect("OpenOk encode"));
        }
        if let Ok(StreamFrame::ServicesCatalogRequest) = StreamFrame::decode(message) {
            let catalog = StreamFrame::ServicesCatalog {
                services: vec!["http".into(), "ollama".into()],
            };
            self.pending
                .push_back(catalog.encode().expect("ServicesCatalog encode"));
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
            self.pending
                .push_back(detailed.encode().expect("ServicesCatalogDetailed encode"));
        }
        if let Ok(StreamFrame::Data { stream_id, bytes }) = StreamFrame::decode(message) {
            let echo = StreamFrame::Data { stream_id, bytes };
            self.pending.push_back(echo.encode().expect("Data encode"));
        }
        self.inner.send_binary(message)
    }

    async fn next_event(&mut self) -> idr_core::Result<PeerEvent> {
        if let Some(bytes) = self.pending.pop_front() {
            return Ok(PeerEvent::BinaryMessage(bytes));
        }
        self.inner.next_event().await
    }

    fn close(&mut self) {
        self.inner.close();
    }
}

pub fn mock_runtime(
    source_id: &str,
    region: &str,
    auth_mode: SourceAuthMode,
    auth_token: &str,
) -> SourceRuntime {
    SourceRuntime::with_auth(
        Box::new(MockSignalingClient::default()),
        || Box::new(AutoOkPeer::new()),
        source_id,
        region,
        auth_mode,
        Some(auth_token.to_string()),
    )
}
