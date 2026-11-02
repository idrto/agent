//! Length-prefixed records over a [`LogicalStream`].

use idr_core::LogicalStream;
use idr_protocol::transfer::{encode_record, ControlFrame, ControlMsg, TransferErrorKind};
use serde::de::DeserializeOwned;
use serde::Serialize;

use TransferErrorKind::{ProtocolViolation, TransportClosed};

/// A transfer stream plus the bytes read past the last record.
pub struct Framed {
    pub stream: Box<dyn LogicalStream>,
    buf: Vec<u8>,
}

impl Framed {
    pub fn new(stream: Box<dyn LogicalStream>) -> Self {
        Self {
            stream,
            buf: Vec::new(),
        }
    }

    /// Next record body, `None` on clean EOF. Cancel-safe: the only await is the
    /// stream read, and its bytes are buffered before the next one.
    pub async fn next_raw(&mut self, max: usize) -> Result<Option<Vec<u8>>, TransferErrorKind> {
        loop {
            if self.buf.len() >= 4 {
                let len = u32::from_be_bytes(self.buf[..4].try_into().unwrap()) as usize;
                if len > max {
                    return Err(ProtocolViolation);
                }
                if self.buf.len() >= 4 + len {
                    let body = self.buf[4..4 + len].to_vec();
                    self.buf.drain(..4 + len);
                    return Ok(Some(body));
                }
            }
            let mut tmp = [0u8; 16 * 1024];
            let n = self.stream.read(&mut tmp).await.map_err(|_| TransportClosed)?;
            if n == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(TransportClosed)
                };
            }
            self.buf.extend_from_slice(&tmp[..n]);
        }
    }

    pub async fn next<T: DeserializeOwned>(
        &mut self,
        max: usize,
    ) -> Result<Option<T>, TransferErrorKind> {
        match self.next_raw(max).await? {
            Some(body) => postcard::from_bytes(&body).map(Some).map_err(|_| ProtocolViolation),
            None => Ok(None),
        }
    }

    /// Next control message. Unknown optional types are skipped.
    pub async fn next_control(&mut self) -> Result<Option<ControlMsg>, TransferErrorKind> {
        loop {
            let Some(frame) = self
                .next::<ControlFrame>(idr_protocol::transfer::MAX_RECORD_BYTES)
                .await?
            else {
                return Ok(None);
            };
            if let Some(msg) = ControlMsg::from_frame(&frame)? {
                return Ok(Some(msg));
            }
        }
    }

    pub async fn send<T: Serialize>(&mut self, value: &T) -> Result<(), TransferErrorKind> {
        let bytes = encode_record(value);
        let mut sent = 0;
        while sent < bytes.len() {
            let n = self
                .stream
                .write(&bytes[sent..])
                .await
                .map_err(|_| TransportClosed)?;
            if n == 0 {
                return Err(TransportClosed);
            }
            sent += n;
        }
        Ok(())
    }

    pub async fn send_control(&mut self, msg: &ControlMsg) -> Result<(), TransferErrorKind> {
        self.send(&msg.to_frame()).await
    }
}
