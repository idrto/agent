//! Logical stream identifiers and async byte-stream trait.

use async_trait::async_trait;

use crate::error::Result;

/// Multiplexed logical stream id (Source-initiated streams use odd ids).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId(pub u32);

impl StreamId {
    pub fn is_source_initiated(self) -> bool {
        self.0 % 2 == 1
    }
}

/// Byte-oriented logical stream over a Target session.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg(not(target_arch = "wasm32"))]
pub trait LogicalStream: Send {
    fn id(&self) -> StreamId;

    /// Write bytes; returns accepted count (may be less under backpressure).
    async fn write(&mut self, buf: &[u8]) -> Result<usize>;

    /// Read into `buf`; returns 0 on clean EOF after half-close.
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    async fn half_close(&mut self) -> Result<()>;

    async fn reset(&mut self, reason: u16) -> Result<()>;
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg(target_arch = "wasm32")]
pub trait LogicalStream {
    fn id(&self) -> StreamId;

    async fn write(&mut self, buf: &[u8]) -> Result<usize>;

    async fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    async fn half_close(&mut self) -> Result<()>;

    async fn reset(&mut self, reason: u16) -> Result<()>;
}
