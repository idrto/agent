//! Per-stream and connection flow-control windows.

use std::sync::Arc;

use idr_protocol::stream_mux::{INITIAL_CONN_WINDOW, INITIAL_STREAM_WINDOW, MAX_SEND_CREDIT};
use tokio::sync::Semaphore;

use crate::error::{IdrError, IdrErrorKind, Result};

/// Tracks send credit and receive consumption for mux flow control.
#[derive(Debug, Clone)]
pub struct FlowController {
    pub stream_send_window: u32,
    pub conn_send_window: u32,
    pub stream_recv_consumed: u32,
    pub conn_recv_consumed: u32,
    pub stream_recv_window: u32,
    pub conn_recv_window: u32,
    /// Emit WINDOW_UPDATE after this much consumed credit.
    pub update_threshold: u32,
}

impl Default for FlowController {
    fn default() -> Self {
        Self::new(INITIAL_STREAM_WINDOW, INITIAL_CONN_WINDOW)
    }
}

impl FlowController {
    pub fn new(stream_window: u32, conn_window: u32) -> Self {
        Self {
            stream_send_window: stream_window,
            conn_send_window: conn_window,
            stream_recv_consumed: 0,
            conn_recv_consumed: 0,
            stream_recv_window: stream_window,
            conn_recv_window: conn_window,
            update_threshold: stream_window / 2,
        }
    }

    /// Bytes that may still be sent on this stream.
    pub fn send_budget(&self) -> u32 {
        self.stream_send_window.min(self.conn_send_window)
    }

    /// Reserve `n` bytes of send credit before writing DATA.
    pub fn consume_send(&mut self, n: u32) -> Result<()> {
        if n > self.send_budget() {
            return Err(IdrError::new(
                IdrErrorKind::Backpressure,
                format!(
                    "send window exhausted (need {n}, have {})",
                    self.send_budget()
                ),
            ));
        }
        self.stream_send_window -= n;
        self.conn_send_window -= n;
        Ok(())
    }

    pub fn credit_send_stream(&mut self, credit: u32) {
        self.stream_send_window = self.stream_send_window.saturating_add(credit);
    }

    pub fn credit_send_conn(&mut self, credit: u32) {
        self.conn_send_window = self.conn_send_window.saturating_add(credit);
    }

    /// Account for received DATA; returns Some(credit) when a WINDOW_UPDATE should be sent.
    pub fn on_recv_data(&mut self, n: u32) -> Option<u32> {
        self.stream_recv_consumed = self.stream_recv_consumed.saturating_add(n);
        self.conn_recv_consumed = self.conn_recv_consumed.saturating_add(n);
        if self.stream_recv_consumed >= self.update_threshold {
            let credit = self.stream_recv_consumed;
            self.stream_recv_consumed = 0;
            self.conn_recv_consumed = 0;
            Some(credit)
        } else {
            None
        }
    }

    pub fn set_peer_initial_window(&mut self, stream: u32, conn: Option<u32>) {
        self.stream_send_window = stream;
        if let Some(c) = conn {
            self.conn_send_window = c;
        }
    }
}

/// Send credit granted by the peer for one stream or the whole connection
/// (`flow_credit_v1`). Shared between the writer and the demux that applies
/// `WindowUpdate`s.
#[derive(Debug, Clone)]
pub struct SendCredit(Arc<Semaphore>);

impl SendCredit {
    pub fn new(initial: u32) -> Self {
        Self(Arc::new(Semaphore::new(initial.min(MAX_SEND_CREDIT) as usize)))
    }

    /// Apply a peer `WindowUpdate`. Credit beyond [`MAX_SEND_CREDIT`] is dropped.
    pub fn grant(&self, credit: u32) {
        let room = (MAX_SEND_CREDIT as usize).saturating_sub(self.0.available_permits());
        self.0.add_permits((credit as usize).min(room));
    }

    pub fn available(&self) -> u32 {
        self.0.available_permits() as u32
    }

    /// Take `n` credit without waiting.
    pub fn try_take(&self, n: u32) -> bool {
        match self.0.try_acquire_many(n) {
            Ok(p) => {
                p.forget();
                true
            }
            Err(_) => false,
        }
    }

    /// Wait for `n` credit. Errors once [`close`](Self::close)d.
    pub async fn take(&self, n: u32) -> Result<()> {
        self.0
            .acquire_many(n)
            .await
            .map(|p| p.forget())
            .map_err(|_| IdrError::new(IdrErrorKind::StreamReset, "stream closed"))
    }

    pub fn is_closed(&self) -> bool {
        self.0.is_closed()
    }

    /// Wake and fail every waiter (stream reset).
    pub fn close(&self) {
        self.0.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backpressure_when_window_empty() {
        let mut fc = FlowController::new(8, 100);
        fc.consume_send(8).unwrap();
        assert!(fc.consume_send(1).is_err());
        fc.credit_send_stream(4);
        fc.consume_send(4).unwrap();
    }

    #[test]
    fn send_credit_caps_grants() {
        let c = SendCredit::new(10);
        assert!(c.try_take(10));
        assert!(!c.try_take(1));
        c.grant(u32::MAX);
        c.grant(u32::MAX);
        assert_eq!(c.available(), MAX_SEND_CREDIT);
    }

    #[test]
    fn window_update_threshold() {
        let mut fc = FlowController::new(10, 100);
        fc.update_threshold = 5;
        assert!(fc.on_recv_data(3).is_none());
        assert_eq!(fc.on_recv_data(2), Some(5));
    }
}
