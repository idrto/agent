//! Outbound mux frames with strict priority: control > interactive > bulk.
//!
//! The session driver is the only reader. It sends control frames (credit,
//! opens, resets, pings) first, then interactive stream data, and bulk data only
//! while the transport's send buffer is below its low-water mark, so bulk can't
//! bury the other classes in the DataChannel buffer.

use tokio::sync::mpsc;

/// Scheduling class of a stream's DATA (and its in-order `HalfClose`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StreamPriority {
    #[default]
    Interactive,
    Bulk,
}

/// Bytes the transport may hold before bulk sends pause.
pub const BULK_LOW_WATER: usize = 256 * 1024;

/// Sender half; cheap to clone into every stream.
#[derive(Debug, Clone)]
pub struct MuxOut {
    control: mpsc::Sender<Vec<u8>>,
    interactive: mpsc::Sender<Vec<u8>>,
    bulk: mpsc::Sender<Vec<u8>>,
}

/// Receiver half, owned by the session driver.
#[derive(Debug)]
pub struct MuxOutRx {
    control: mpsc::Receiver<Vec<u8>>,
    interactive: mpsc::Receiver<Vec<u8>>,
    bulk: mpsc::Receiver<Vec<u8>>,
}

/// Each class queue holds up to `capacity` encoded frames.
pub fn mux_out(capacity: usize) -> (MuxOut, MuxOutRx) {
    let (c, cr) = mpsc::channel(capacity);
    let (i, ir) = mpsc::channel(capacity);
    let (b, br) = mpsc::channel(capacity);
    (
        MuxOut {
            control: c,
            interactive: i,
            bulk: b,
        },
        MuxOutRx {
            control: cr,
            interactive: ir,
            bulk: br,
        },
    )
}

impl MuxOut {
    /// Queue a control frame. False once the session is gone.
    pub async fn control(&self, frame: Vec<u8>) -> bool {
        self.control.send(frame).await.is_ok()
    }

    /// Queue stream data (or a `HalfClose`, which must follow its data in order).
    pub async fn data(&self, priority: StreamPriority, frame: Vec<u8>) -> bool {
        match priority {
            StreamPriority::Interactive => self.interactive.send(frame).await,
            StreamPriority::Bulk => self.bulk.send(frame).await,
        }
        .is_ok()
    }
}

impl MuxOutRx {
    /// Next frame to send; bulk only when `bulk_open`. Cancel-safe.
    /// None when every sender is gone.
    pub async fn next(&mut self, bulk_open: bool) -> Option<Vec<u8>> {
        tokio::select! {
            biased;
            Some(f) = self.control.recv() => Some(f),
            Some(f) = self.interactive.recv() => Some(f),
            Some(f) = self.bulk.recv(), if bulk_open => Some(f),
            else => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn control_then_interactive_then_bulk() {
        let (out, mut rx) = mux_out(8);
        out.data(StreamPriority::Bulk, vec![3]).await;
        out.data(StreamPriority::Interactive, vec![2]).await;
        out.control(vec![1]).await;
        assert_eq!(rx.next(true).await, Some(vec![1]));
        assert_eq!(rx.next(true).await, Some(vec![2]));
        assert_eq!(rx.next(true).await, Some(vec![3]));
    }

    #[tokio::test]
    async fn bulk_waits_while_transport_is_full() {
        let (out, mut rx) = mux_out(8);
        out.data(StreamPriority::Bulk, vec![3]).await;
        let gated = tokio::time::timeout(std::time::Duration::from_millis(50), rx.next(false));
        assert!(gated.await.is_err(), "bulk sent past the low-water mark");
        out.control(vec![1]).await;
        assert_eq!(rx.next(false).await, Some(vec![1]));
        assert_eq!(rx.next(true).await, Some(vec![3]));
    }
}
