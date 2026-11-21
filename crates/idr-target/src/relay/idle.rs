use std::collections::HashMap;
use std::time::Duration;

use futures::StreamExt;
use tokio::sync::{broadcast, mpsc};
use tokio_util::time::{delay_queue::Key, DelayQueue};

use crate::relay::descriptor::GenerationalHandle;
use crate::telemetry::Metrics;

const JITTER_MAX_MS: u64 = 500;

enum IdleCommand {
    Schedule {
        handle: GenerationalHandle,
        timeout: Duration,
    },
    Cancel(GenerationalHandle),
}

pub struct IdleScheduler {
    cmd_tx: mpsc::UnboundedSender<IdleCommand>,
    expired_tx: broadcast::Sender<GenerationalHandle>,
    metrics: Metrics,
}

impl IdleScheduler {
    pub fn new(metrics: Metrics) -> Self {
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
        let (expired_tx, _) = broadcast::channel(1024);
        let worker_expired = expired_tx.clone();
        let metrics_worker = metrics.clone();

        tokio::spawn(async move {
            let mut queue = DelayQueue::new();
            let mut keys: HashMap<u64, Key> = HashMap::new();

            loop {
                tokio::select! {
                    cmd = cmd_rx.recv() => {
                        let Some(cmd) = cmd else { break };
                        match cmd {
                            IdleCommand::Schedule { handle, timeout } => {
                                let jitter = Duration::from_millis(fastrand_u64() % JITTER_MAX_MS);
                                if let Some(key) = keys.remove(&handle.raw()) {
                                    queue.remove(&key);
                                }
                                let key = queue.insert(handle, timeout + jitter);
                                keys.insert(handle.raw(), key);
                            }
                            IdleCommand::Cancel(handle) => {
                                if let Some(key) = keys.remove(&handle.raw()) {
                                    queue.remove(&key);
                                }
                            }
                        }
                    }
                    // An empty DelayQueue returns Ready(None), not Pending.
                    // Polling it unconditionally spins and monopolizes a worker.
                    expired = queue.next(), if !queue.is_empty() => {
                        if let Some(entry) = expired {
                            let handle = entry.into_inner();
                            keys.remove(&handle.raw());
                            metrics_worker.idle_connections_closed_total.inc();
                            let _ = worker_expired.send(handle);
                        }
                    }
                }
            }
        });

        Self {
            cmd_tx,
            expired_tx,
            metrics,
        }
    }

    pub fn schedule(&self, handle: GenerationalHandle, idle_timeout: Duration) {
        let _ = self.cmd_tx.send(IdleCommand::Schedule {
            handle,
            timeout: idle_timeout,
        });
    }

    pub fn cancel(&self, handle: GenerationalHandle) {
        let _ = self.cmd_tx.send(IdleCommand::Cancel(handle));
    }

    pub async fn next_expired(&self) -> GenerationalHandle {
        let mut rx = self.expired_tx.subscribe();
        loop {
            match rx.recv().await {
                Ok(handle) => return handle,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    rx = self.expired_tx.subscribe();
                }
            }
        }
    }

    pub fn on_closed(&self) {
        self.metrics.idle_connections_closed_total.inc();
    }
}

fn fastrand_u64() -> u64 {
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u64> = const { Cell::new(0x853c49e6748fea9b) };
    }
    STATE.with(|s| {
        let mut x = s.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.set(x);
        x
    })
}

pub fn idle_deadline_from(
    last_activity: std::time::Instant,
    idle_timeout: Duration,
) -> std::time::Instant {
    last_activity + idle_timeout
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc as std_mpsc;

    fn assert_empty_queue_yields(cancel_scheduled: bool) {
        let (scheduler_tx, scheduler_rx) = std_mpsc::channel();
        let (heartbeat_tx, heartbeat_rx) = std_mpsc::channel();
        let worker = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap()
                .block_on(async move {
                    let scheduler = IdleScheduler::new(Metrics::new());
                    if cancel_scheduled {
                        let handle = GenerationalHandle::encode(1, 1);
                        scheduler.schedule(handle, Duration::from_secs(30));
                        scheduler.cancel(handle);
                    }
                    scheduler_tx.send(scheduler).unwrap();
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    let _ = heartbeat_tx.send(());
                });
        });
        let scheduler = scheduler_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let progress = heartbeat_rx.recv_timeout(Duration::from_secs(2));
        // Closing the command channel releases even a regressed spinning worker,
        // so the regression test itself does not hang the test runner.
        drop(scheduler);
        worker.join().unwrap();
        assert!(
            progress.is_ok(),
            "empty idle queue starved the runtime timer"
        );
    }

    #[test]
    fn empty_queue_does_not_starve_other_tasks() {
        assert_empty_queue_yields(false);
    }

    #[test]
    fn canceling_last_timer_does_not_starve_other_tasks() {
        assert_empty_queue_yields(true);
    }

    #[tokio::test]
    async fn scheduled_timer_still_expires() {
        let scheduler = IdleScheduler::new(Metrics::new());
        let handle = GenerationalHandle::encode(1, 1);
        let mut expired = scheduler.expired_tx.subscribe();
        scheduler.schedule(handle, Duration::from_millis(1));
        let actual = tokio::time::timeout(Duration::from_secs(2), expired.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(actual, handle);
    }
}
