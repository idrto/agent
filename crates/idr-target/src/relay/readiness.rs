//! Signals when at least one Relay QUIC session is Active (needed before ACME http-01).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;

#[derive(Debug, Default)]
pub struct RelayReadiness {
    active: AtomicUsize,
    notify: Notify,
}

impl RelayReadiness {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn on_connected(&self) {
        self.active.fetch_add(1, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub fn on_disconnected(&self) {
        let mut cur = self.active.load(Ordering::SeqCst);
        while cur > 0 {
            match self.active.compare_exchange(
                cur,
                cur - 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }

    pub fn is_ready(&self) -> bool {
        self.active.load(Ordering::SeqCst) > 0
    }

    /// Wait until at least one Relay QUIC is Active, or `timeout` elapses.
    pub async fn wait_ready(&self, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.is_ready() {
                return true;
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return false;
            }
            tokio::select! {
                _ = self.notify.notified() => {}
                _ = tokio::time::sleep(remaining) => {
                    return self.is_ready();
                }
            }
        }
    }
}
