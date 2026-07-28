//! In-memory PeerTransport for unit tests (no native WebRTC).

use std::collections::VecDeque;

use async_trait::async_trait;
use tokio::sync::mpsc;

use idr_core::error::{IdrError, IdrErrorKind, Result};

use crate::transport::{PeerConnectRequest, PeerEvent, PeerRole, PeerTransport};

/// Pair of connected mock peers that exchange binary DC messages and SDP stubs.
pub struct MockPeerPair {
    pub offerer: MockPeer,
    pub answerer: MockPeer,
}

impl MockPeerPair {
    pub fn new() -> Self {
        let (o_to_a, a_from_o) = mpsc::channel::<Vec<u8>>(64);
        let (a_to_o, o_from_a) = mpsc::channel::<Vec<u8>>(64);
        let (o_evt_tx, o_evt_rx) = mpsc::channel(64);
        let (a_evt_tx, a_evt_rx) = mpsc::channel(64);
        Self {
            offerer: MockPeer {
                role: PeerRole::Offerer,
                peer_tx: o_to_a,
                peer_rx: o_from_a,
                events: o_evt_rx,
                event_tx: o_evt_tx,
                pending: VecDeque::new(),
                started: false,
                dc_open: false,
            },
            answerer: MockPeer {
                role: PeerRole::Answerer,
                peer_tx: a_to_o,
                peer_rx: a_from_o,
                events: a_evt_rx,
                event_tx: a_evt_tx,
                pending: VecDeque::new(),
                started: false,
                dc_open: false,
            },
        }
    }
}

impl Default for MockPeerPair {
    fn default() -> Self {
        Self::new()
    }
}

pub struct MockPeer {
    role: PeerRole,
    peer_tx: mpsc::Sender<Vec<u8>>,
    peer_rx: mpsc::Receiver<Vec<u8>>,
    events: mpsc::Receiver<PeerEvent>,
    event_tx: mpsc::Sender<PeerEvent>,
    pending: VecDeque<PeerEvent>,
    started: bool,
    dc_open: bool,
}

impl MockPeer {
    fn push_event(&mut self, ev: PeerEvent) {
        self.pending.push_back(ev);
    }
}

#[async_trait]
impl PeerTransport for MockPeer {
    async fn start(&mut self, request: PeerConnectRequest) -> Result<()> {
        self.role = request.role;
        self.started = true;
        Ok(())
    }

    async fn set_remote_description(&mut self, sdp_type: &str, _sdp: &str) -> Result<()> {
        if !self.started {
            return Err(IdrError::new(
                IdrErrorKind::NotInitialized,
                "peer not started",
            ));
        }
        if self.role == PeerRole::Answerer && sdp_type == "offer" {
            // Answerer will create answer next.
        }
        if self.role == PeerRole::Offerer && sdp_type == "answer" {
            self.dc_open = true;
            self.push_event(PeerEvent::DataChannelOpen);
            let _ = self.event_tx.try_send(PeerEvent::DataChannelOpen);
            // Notify answerer side similarly via injecting into its queue is handled by create.
        }
        Ok(())
    }

    async fn create_local_description(&mut self) -> Result<()> {
        if !self.started {
            return Err(IdrError::new(
                IdrErrorKind::NotInitialized,
                "peer not started",
            ));
        }
        let sdp_type = match self.role {
            PeerRole::Offerer => "offer",
            PeerRole::Answerer => "answer",
        };
        let sdp = format!("mock-{sdp_type}");
        self.push_event(PeerEvent::LocalDescription {
            sdp_type: sdp_type.into(),
            sdp: sdp.clone(),
        });
        if self.role == PeerRole::Answerer {
            self.dc_open = true;
            self.push_event(PeerEvent::DataChannelOpen);
        }
        self.push_event(PeerEvent::GatheringComplete);
        Ok(())
    }

    fn add_remote_candidate(&mut self, _candidate: &str, _mid: &str) -> Result<()> {
        Ok(())
    }

    fn send_binary(&mut self, message: &[u8]) -> Result<()> {
        if !self.dc_open {
            return Err(IdrError::new(
                IdrErrorKind::TransportClosed,
                "datachannel not open",
            ));
        }
        self.peer_tx
            .try_send(message.to_vec())
            .map_err(|_| IdrError::new(IdrErrorKind::Backpressure, "mock peer send queue full"))?;
        Ok(())
    }

    async fn next_event(&mut self) -> Result<PeerEvent> {
        if let Some(ev) = self.pending.pop_front() {
            return Ok(ev);
        }
        tokio::select! {
            msg = self.peer_rx.recv() => {
                match msg {
                    Some(bytes) => Ok(PeerEvent::BinaryMessage(bytes)),
                    None => Ok(PeerEvent::Closed),
                }
            }
            ev = self.events.recv() => {
                match ev {
                    Some(ev) => Ok(ev),
                    None => Ok(PeerEvent::Closed),
                }
            }
        }
    }

    fn close(&mut self) {
        self.dc_open = false;
        self.push_event(PeerEvent::Closed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_pair_exchanges_binary() {
        let mut pair = MockPeerPair::new();
        pair.offerer
            .start(PeerConnectRequest {
                role: PeerRole::Offerer,
                ice_servers_json: None,
            })
            .await
            .unwrap();
        pair.answerer
            .start(PeerConnectRequest {
                role: PeerRole::Answerer,
                ice_servers_json: None,
            })
            .await
            .unwrap();
        pair.offerer.create_local_description().await.unwrap();
        let PeerEvent::LocalDescription { sdp, .. } = pair.offerer.next_event().await.unwrap()
        else {
            panic!("expected local description");
        };
        pair.answerer
            .set_remote_description("offer", &sdp)
            .await
            .unwrap();
        pair.answerer.create_local_description().await.unwrap();
        // Drain answerer events until DC open (also feed answer SDP to offerer)
        loop {
            match pair.answerer.next_event().await.unwrap() {
                PeerEvent::DataChannelOpen => break,
                PeerEvent::LocalDescription { sdp_type, sdp } => {
                    pair.offerer
                        .set_remote_description(&sdp_type, &sdp)
                        .await
                        .unwrap();
                }
                PeerEvent::GatheringComplete | PeerEvent::LocalCandidate { .. } => {}
                other => panic!("answerer unexpected {other:?}"),
            }
        }
        // Offerer gets DC open from set_remote answer; skip leftovers
        loop {
            match pair.offerer.next_event().await.unwrap() {
                PeerEvent::DataChannelOpen => break,
                PeerEvent::GatheringComplete | PeerEvent::LocalCandidate { .. } => {}
                other => panic!("offerer unexpected {other:?}"),
            }
        }
        // Clear any remaining answerer control events before data
        loop {
            // Peek by trying with a timeout would be nicer; drain known leftovers.
            // After DC open, only GatheringComplete may remain.
            // Use try_path: if next is GatheringComplete, continue; else if we'd block, stop.
            // Simpler: just send and loop answerer until BinaryMessage.
            break;
        }
        pair.offerer.send_binary(b"hello").unwrap();
        loop {
            match pair.answerer.next_event().await.unwrap() {
                PeerEvent::BinaryMessage(b) => {
                    assert_eq!(b, b"hello");
                    break;
                }
                PeerEvent::GatheringComplete | PeerEvent::LocalCandidate { .. } => {}
                other => panic!("unexpected data event {other:?}"),
            }
        }
    }
}
