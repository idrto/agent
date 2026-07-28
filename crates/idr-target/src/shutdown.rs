use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{broadcast, Notify};
use tokio::time::{sleep, Instant};

#[derive(Clone)]
pub struct ShutdownCoordinator {
    inner: Arc<Inner>,
}

struct Inner {
    draining: AtomicBool,
    shutdown: AtomicBool,
    notify: Notify,
    broadcast: broadcast::Sender<()>,
}

impl ShutdownCoordinator {
    pub fn new() -> Self {
        let (broadcast, _) = broadcast::channel(1);
        Self {
            inner: Arc::new(Inner {
                draining: AtomicBool::new(false),
                shutdown: AtomicBool::new(false),
                notify: Notify::new(),
                broadcast,
            }),
        }
    }

    pub fn begin_drain(&self) {
        self.inner.draining.store(true, Ordering::SeqCst);
        let _ = self.inner.broadcast.send(());
        self.inner.notify.notify_waiters();
    }

    pub fn shutdown_now(&self) {
        self.inner.shutdown.store(true, Ordering::SeqCst);
        self.begin_drain();
    }

    pub fn is_draining(&self) -> bool {
        self.inner.draining.load(Ordering::SeqCst)
    }

    pub fn is_shutdown(&self) -> bool {
        self.inner.shutdown.load(Ordering::SeqCst)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.inner.broadcast.subscribe()
    }

    pub async fn wait_for_drain(&self) {
        if self.is_draining() {
            return;
        }
        self.inner.notify.notified().await;
    }

    pub async fn wait_grace_period(&self, grace: Duration) {
        let deadline = Instant::now() + grace;
        while Instant::now() < deadline {
            if self.is_shutdown() {
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
    }
}

impl Default for ShutdownCoordinator {
    fn default() -> Self {
        Self::new()
    }
}
