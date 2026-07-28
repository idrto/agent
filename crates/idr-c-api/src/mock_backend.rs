//! Mock backend: MockSignalingClient + peer that auto-replies OpenOk and echoes DATA.

use std::collections::VecDeque;

use async_trait::async_trait;
use idr_protocol::stream_mux::{StreamFrame, INITIAL_STREAM_WINDOW};
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
        // Echo DATA for round-trip FFI tests (loopback mock).
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

pub fn mock_runtime(source_id: &str, region: &str) -> SourceRuntime {
    SourceRuntime::new(
        Box::new(MockSignalingClient::default()),
        || Box::new(AutoOkPeer::new()),
        source_id,
        region,
    )
}
