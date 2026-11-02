//! Classifies incoming transfer streams by their header.
//!
//! A control stream goes back to the caller (it becomes a new offer to decide
//! on). A data stream is delivered only to a receiver that has accepted that
//! transfer id; anything else is reset before any data is read, so a peer
//! can't push bulk data without an accepted offer.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use idr_core::LogicalStream;
use idr_protocol::transfer::{StreamHeader, StreamRole, TransferId, STREAM_MAGIC};
use tokio::sync::oneshot;

use crate::io::Framed;

const HEADER_MAX: usize = 64;

pub enum Routed {
    /// A new control stream: hand it to [`crate::receive`].
    Control { header: StreamHeader, stream: Framed },
    /// A data stream, delivered to the receiver waiting for it.
    Data,
    /// Bad header, timeout, or a data stream nobody accepted; already reset.
    Refused,
}

#[derive(Clone, Default)]
pub struct Router {
    waiting: Arc<Mutex<HashMap<TransferId, oneshot::Sender<Framed>>>>,
}

impl Router {
    pub async fn route(&self, stream: Box<dyn LogicalStream>, timeout: Duration) -> Routed {
        let mut framed = Framed::new(stream);
        let header = match tokio::time::timeout(timeout, framed.next::<StreamHeader>(HEADER_MAX))
            .await
        {
            Ok(Ok(Some(h))) if h.magic == STREAM_MAGIC => h,
            _ => {
                let _ = framed.stream.reset(0).await;
                return Routed::Refused;
            }
        };
        match header.role {
            StreamRole::Control => Routed::Control {
                header,
                stream: framed,
            },
            StreamRole::Data => {
                let waiter = self.waiting.lock().unwrap().remove(&header.transfer_id);
                match waiter {
                    Some(tx) => match tx.send(framed) {
                        Ok(()) => Routed::Data,
                        Err(mut framed) => {
                            let _ = framed.stream.reset(0).await;
                            Routed::Refused
                        }
                    },
                    None => {
                        tracing::warn!("transfer data stream without an accepted offer; reset");
                        let _ = framed.stream.reset(0).await;
                        Routed::Refused
                    }
                }
            }
        }
    }

    /// Accept one data stream for `id`. Dropping the waiter withdraws it.
    pub(crate) fn expect_data(&self, id: TransferId) -> DataWaiter {
        let (tx, rx) = oneshot::channel();
        self.waiting.lock().unwrap().insert(id, tx);
        DataWaiter {
            rx,
            id,
            waiting: self.waiting.clone(),
        }
    }
}

pub(crate) struct DataWaiter {
    pub rx: oneshot::Receiver<Framed>,
    id: TransferId,
    waiting: Arc<Mutex<HashMap<TransferId, oneshot::Sender<Framed>>>>,
}

impl Drop for DataWaiter {
    fn drop(&mut self) {
        self.waiting.lock().unwrap().remove(&self.id);
    }
}
