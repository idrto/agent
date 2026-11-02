//! Boundaries to storage and policy. The engine never touches a filesystem.

use async_trait::async_trait;
use idr_protocol::transfer::{
    Manifest, ManifestEntry, ResumePoint, Sha256Digest, TransferErrorKind, TransferId,
};

use crate::manifest::OfferSummary;

/// `Send` on native, nothing on WASM.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send> MaybeSend for T {}
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T> MaybeSend for T {}

pub type Result<T> = std::result::Result<T, TransferErrorKind>;

/// Sender-side file contents.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait SourceFiles: MaybeSend {
    /// Open a manifest file entry from its start.
    async fn open(&mut self, entry: &ManifestEntry) -> Result<Box<dyn EntryReader>>;
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait EntryReader: MaybeSend {
    /// 0 at end of file.
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
    /// After EOF: `ChangedDuringTransfer` if size or mtime no longer match the manifest.
    async fn verify_unchanged(&mut self) -> Result<()>;
}

/// Receiver-side storage for one transfer. Implementations write to private
/// partial files, persist checkpoints durably, and expose nothing as complete
/// until [`commit`](Sink::commit) / [`finish`](Sink::finish).
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Sink: MaybeSend {
    /// Start or resume `id`. Returns what is already verified. Partial data beyond
    /// the last checkpoint is dropped. `ConflictingManifest` when `id` is held for
    /// a different digest.
    async fn prepare(
        &mut self,
        id: &TransferId,
        digest: &Sha256Digest,
        manifest: &Manifest,
    ) -> Result<Vec<ResumePoint>>;
    async fn create_dir(&mut self, entry: u32) -> Result<()>;
    /// Persisted bytes of a partial entry (to resume its hash).
    async fn read_partial(&mut self, entry: u32, offset: u64, buf: &mut [u8]) -> Result<usize>;
    /// Append at `offset` (always the current partial length).
    async fn write(&mut self, entry: u32, offset: u64, bytes: &[u8]) -> Result<()>;
    /// Durably persist `len` bytes of `entry`; only then may they be advertised.
    async fn checkpoint(&mut self, entry: u32, len: u64) -> Result<()>;
    /// Verified: finalize the file (loose files become visible here).
    async fn commit(&mut self, entry: u32) -> Result<()>;
    /// Drop the entry's partial data.
    async fn fail(&mut self, entry: u32) -> Result<()>;
    /// Every entry verified: commit the transfer (folders become visible here).
    async fn finish(&mut self) -> Result<()>;
    /// Cancelled: remove partial data, staging and metadata.
    async fn discard(&mut self) -> Result<()>;
    /// Entries stored under a different name than offered (platform-incompatible
    /// names, taken top-level names), with the stored path. Drained by the engine.
    fn take_renamed(&mut self) -> Vec<(u32, String)> {
        Vec::new()
    }
}

/// How an offer was approved; logged and reported separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Approval {
    User,
    Auto,
}

pub struct OfferInfo<'a> {
    pub transfer_id: &'a TransferId,
    /// Digest of the offered manifest (a resume must offer the accepted one).
    pub digest: &'a idr_protocol::transfer::Sha256Digest,
    pub summary: &'a OfferSummary,
    pub resume: bool,
}

/// Receive-side decision (consent and local policy; Phase 2 adds identity,
/// quota and destination rules behind the same call).
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Consent: MaybeSend {
    async fn decide(&mut self, offer: &OfferInfo<'_>) -> Result<Approval>;
    /// The receive attempt ended (release reservations, count failures).
    async fn finished(&mut self, _outcome: &crate::Outcome) {}
}

/// Opens a fresh mux stream to the peer for [`TRANSFER_SERVICE`](idr_protocol::transfer::TRANSFER_SERVICE).
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait StreamOpener: MaybeSend {
    async fn open(&mut self) -> idr_core::Result<Box<dyn idr_core::LogicalStream>>;
}
