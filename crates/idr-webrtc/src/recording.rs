//! Recording PeerTransport for Source unit tests.

use std::collections::VecDeque;

use crate::transport::{PeerConnectRequest, PeerEvent, PeerRole, PeerTransport};
use async_trait::async_trait;
use idr_core::error::{IdrError, IdrErrorKind, Result};

pub struct RecordingPeer {
    role: PeerRole,
    events: VecDeque<PeerEvent>,
    pub sent: Vec<Vec<u8>>,
    dc_open: bool,
}

impl RecordingPeer {
    pub fn new() -> Self {
        Self {
            role: PeerRole::Offerer,
            events: VecDeque::new(),
            sent: Vec::new(),
            dc_open: false,
        }
    }
}

impl Default for RecordingPeer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl PeerTransport for RecordingPeer {
    async fn start(&mut self, request: PeerConnectRequest) -> Result<()> {
        self.role = request.role;
        Ok(())
    }

    async fn set_remote_description(&mut self, sdp_type: &str, _sdp: &str) -> Result<()> {
        if self.role == PeerRole::Offerer && sdp_type == "answer" {
            self.dc_open = true;
            self.events.push_back(PeerEvent::DataChannelOpen);
        }
        Ok(())
    }

    async fn create_local_description(&mut self) -> Result<()> {
        let sdp_type = match self.role {
            PeerRole::Offerer => "offer",
            PeerRole::Answerer => "answer",
        };
        self.events.push_back(PeerEvent::LocalDescription {
            sdp_type: sdp_type.into(),
            sdp: format!("recording-{sdp_type}"),
        });
        self.events.push_back(PeerEvent::GatheringComplete);
        Ok(())
    }

    fn add_remote_candidate(&mut self, _candidate: &str, _mid: &str) -> Result<()> {
        Ok(())
    }

    fn send_binary(&mut self, message: &[u8]) -> Result<()> {
        if !self.dc_open {
            return Err(IdrError::new(IdrErrorKind::TransportClosed, "dc closed"));
        }
        self.sent.push(message.to_vec());
        Ok(())
    }

    async fn next_event(&mut self) -> Result<PeerEvent> {
        if let Some(ev) = self.events.pop_front() {
            return Ok(ev);
        }
        // Idle until a later set_remote_description pushes DataChannelOpen (or test ends).
        // Returning Err here races with signaling in SourceRuntime::connect's select!.
        std::future::pending::<()>().await;
        unreachable!("pending resolved")
    }

    fn close(&mut self) {
        self.dc_open = false;
    }
}
