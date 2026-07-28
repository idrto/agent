//! Per-stream and connection flow-control windows.

use idr_protocol::stream_mux::{INITIAL_CONN_WINDOW, INITIAL_STREAM_WINDOW};

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
    fn window_update_threshold() {
        let mut fc = FlowController::new(10, 100);
        fc.update_threshold = 5;
        assert!(fc.on_recv_data(3).is_none());
        assert_eq!(fc.on_recv_data(2), Some(5));
    }
}
