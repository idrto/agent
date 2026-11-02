//! File transfer wire types (`idr.transfer/1`).
//!
//! Carried only on mux streams opened for [`TRANSFER_SERVICE`]; never on Presence
//! or Relay. Every transfer stream starts with a [`StreamHeader`] followed by
//! length-prefixed postcard records (`[u32 BE len][postcard]`):
//!
//! - the **control** stream carries [`ControlFrame`]s, an envelope whose `msg_type`
//!   is marked mandatory or optional so newer messages can be skipped;
//! - the **data** stream carries [`DataRecord`]s tagged by entry id.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Mux service name both peers use to open transfer streams.
pub const TRANSFER_SERVICE: &str = "idr.transfer";
pub const TRANSFER_VERSION: u16 = 1;
pub const STREAM_MAGIC: [u8; 4] = *b"IDRT";

/// Largest data payload in one [`DataRecord::Chunk`].
pub const MAX_CHUNK_BYTES: usize = 48 * 1024;
/// Largest encoded record on either stream (chunk plus framing slack).
pub const MAX_RECORD_BYTES: usize = MAX_CHUNK_BYTES + 256;
/// Largest manifest piece in one [`ControlMsg::ManifestChunk`].
pub const MANIFEST_CHUNK_BYTES: usize = 32 * 1024;

pub type TransferId = [u8; 16];

/// Random, unguessable transfer id.
pub fn new_transfer_id() -> TransferId {
    uuid::Uuid::new_v4().into_bytes()
}
pub type Sha256Digest = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamRole {
    Control,
    Data,
}

/// First record on every transfer stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamHeader {
    pub magic: [u8; 4],
    pub version: u16,
    pub transfer_id: TransferId,
    pub role: StreamRole,
}

/// Stable transfer error / outcome categories, shared by Rust, C, Dart and CLI.
/// Discriminants are ABI: append only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum TransferErrorKind {
    ProtocolViolation = 1,
    IncompatibleVersion = 2,
    ManifestInvalid = 3,
    LimitExceeded = 4,
    Rejected = 5,
    Cancelled = 6,
    HashMismatch = 7,
    SizeMismatch = 8,
    ChangedDuringTransfer = 9,
    NameIncompatible = 10,
    StorageFailed = 11,
    Stalled = 12,
    TransportClosed = 13,
    AuthorizationExpired = 14,
    ConflictingManifest = 15,
    SourceReadFailed = 16,
    Unauthorized = 17,
    CompletedWithErrors = 18,
    Timeout = 19,
}

impl TransferErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolViolation => "protocol_violation",
            Self::IncompatibleVersion => "incompatible_version",
            Self::ManifestInvalid => "manifest_invalid",
            Self::LimitExceeded => "limit_exceeded",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
            Self::HashMismatch => "hash_mismatch",
            Self::SizeMismatch => "size_mismatch",
            Self::ChangedDuringTransfer => "changed_during_transfer",
            Self::NameIncompatible => "name_incompatible",
            Self::StorageFailed => "storage_failed",
            Self::Stalled => "stalled",
            Self::TransportClosed => "transport_closed",
            Self::AuthorizationExpired => "authorization_expired",
            Self::ConflictingManifest => "conflicting_manifest",
            Self::SourceReadFailed => "source_read_failed",
            Self::Unauthorized => "unauthorized",
            Self::CompletedWithErrors => "completed_with_errors",
            Self::Timeout => "timeout",
        }
    }

    pub fn from_u32(v: u32) -> Option<Self> {
        use TransferErrorKind::*;
        [
            ProtocolViolation,
            IncompatibleVersion,
            ManifestInvalid,
            LimitExceeded,
            Rejected,
            Cancelled,
            HashMismatch,
            SizeMismatch,
            ChangedDuringTransfer,
            NameIncompatible,
            StorageFailed,
            Stalled,
            TransportClosed,
            AuthorizationExpired,
            ConflictingManifest,
            SourceReadFailed,
            Unauthorized,
            CompletedWithErrors,
            Timeout,
        ]
        .into_iter()
        .find(|k| *k as u32 == v)
    }
}

// ---- Manifest --------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManifestKind {
    /// One or more loose files; each commits as it verifies.
    Files,
    /// One folder (complete or a selection of it); every entry sits under one root
    /// component and the folder commits all-or-nothing.
    Folder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryKind {
    Dir,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub id: u32,
    pub kind: EntryKind,
    /// Relative path as components, never a joined string.
    pub path: Vec<String>,
    /// File size in bytes (0 for directories).
    pub size: u64,
    /// Seconds since the Unix epoch.
    pub mtime: Option<i64>,
    /// Untrusted, descriptive only.
    pub mime: Option<String>,
}

/// Immutable once offered. No hashes: each file's SHA-256 travels in its
/// [`DataRecord::EntryEnd`] trailer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub kind: ManifestKind,
    pub entries: Vec<ManifestEntry>,
}

impl Manifest {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("manifest encodes")
    }

    /// Binds the journal, resume state and authorization to this exact manifest.
    pub fn digest_of(encoded: &[u8]) -> Sha256Digest {
        Sha256::digest(encoded).into()
    }
}

// ---- Control stream --------------------------------------------------------

/// Per-entry resume state the receiver reports in `Accept`/`Resume`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumePoint {
    pub entry: u32,
    /// Bytes already persisted and verified; the sender continues from here.
    pub verified: u64,
    /// The entry is finished; the sender skips it.
    pub complete: bool,
}

/// Wire envelope for control messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlFrame {
    pub msg_type: u16,
    /// An unknown mandatory message fails the transfer; an unknown optional one is skipped.
    pub mandatory: bool,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMsg {
    /// Sender → receiver. `manifest_len` bytes of manifest follow in chunks.
    Offer {
        digest: Sha256Digest,
        manifest_len: u32,
        entry_count: u32,
        /// Continuing a transfer id the receiver may already hold state for.
        resume: bool,
    },
    ManifestChunk { bytes: Vec<u8> },
    Accept { resume: Vec<ResumePoint> },
    Reject { code: TransferErrorKind },
    Pause,
    Resume,
    Cancel { code: TransferErrorKind },
    /// Receiver → sender: an entry was verified and committed (`code` None) or failed.
    EntryResult {
        entry: u32,
        code: Option<TransferErrorKind>,
    },
    /// Receiver → sender: every entry is resolved. `code` None means Completed.
    Done { code: Option<TransferErrorKind> },
}

impl ControlMsg {
    pub fn msg_type(&self) -> u16 {
        match self {
            Self::Offer { .. } => 1,
            Self::ManifestChunk { .. } => 2,
            Self::Accept { .. } => 3,
            Self::Reject { .. } => 4,
            Self::Pause => 5,
            Self::Resume => 6,
            Self::Cancel { .. } => 7,
            Self::EntryResult { .. } => 8,
            Self::Done { .. } => 9,
        }
    }

    pub fn to_frame(&self) -> ControlFrame {
        ControlFrame {
            msg_type: self.msg_type(),
            mandatory: true,
            body: postcard::to_allocvec(self).expect("control message encodes"),
        }
    }

    /// `Ok(None)`: unknown optional message, skip it. `Err`: malformed, or an
    /// unknown mandatory message.
    pub fn from_frame(frame: &ControlFrame) -> Result<Option<Self>, TransferErrorKind> {
        if !(1..=9).contains(&frame.msg_type) {
            return if frame.mandatory {
                Err(TransferErrorKind::ProtocolViolation)
            } else {
                Ok(None)
            };
        }
        let msg: Self = postcard::from_bytes(&frame.body)
            .map_err(|_| TransferErrorKind::ProtocolViolation)?;
        if msg.msg_type() != frame.msg_type {
            return Err(TransferErrorKind::ProtocolViolation);
        }
        Ok(Some(msg))
    }
}

// ---- Data stream -----------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataRecord {
    /// File bytes at `offset`; offsets of one entry are strictly sequential.
    Chunk {
        entry: u32,
        offset: u64,
        bytes: Vec<u8>,
    },
    /// Trailer: the file's full size and SHA-256. The receiver finalizes only on match.
    EntryEnd {
        entry: u32,
        size: u64,
        sha256: Sha256Digest,
    },
    /// The sender gave up on one entry (e.g. it changed during transfer).
    EntryAbort { entry: u32, code: TransferErrorKind },
}

/// `[u32 BE len][postcard(value)]`.
pub fn encode_record<T: Serialize>(value: &T) -> Vec<u8> {
    let body = postcard::to_allocvec(value).expect("record encodes");
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_roundtrip_and_unknown_types() {
        let msg = ControlMsg::EntryResult {
            entry: 7,
            code: Some(TransferErrorKind::HashMismatch),
        };
        assert_eq!(ControlMsg::from_frame(&msg.to_frame()), Ok(Some(msg)));

        let optional = ControlFrame {
            msg_type: 4000,
            mandatory: false,
            body: vec![1, 2, 3],
        };
        assert_eq!(ControlMsg::from_frame(&optional), Ok(None));
        let mandatory = ControlFrame {
            mandatory: true,
            ..optional
        };
        assert_eq!(
            ControlMsg::from_frame(&mandatory),
            Err(TransferErrorKind::ProtocolViolation)
        );
    }

    #[test]
    fn mislabeled_or_garbage_frames_are_violations() {
        let mut frame = ControlMsg::Pause.to_frame();
        frame.msg_type = ControlMsg::Resume.msg_type();
        assert!(ControlMsg::from_frame(&frame).is_err());
        frame.body = vec![0xff; 5];
        assert!(ControlMsg::from_frame(&frame).is_err());
    }

    #[test]
    fn max_chunk_record_fits_record_limit() {
        let rec = encode_record(&DataRecord::Chunk {
            entry: u32::MAX,
            offset: u64::MAX,
            bytes: vec![0; MAX_CHUNK_BYTES],
        });
        assert!(rec.len() - 4 <= MAX_RECORD_BYTES);
    }

    #[test]
    fn error_kinds_roundtrip_and_stay_stable() {
        for v in 1..=19 {
            let k = TransferErrorKind::from_u32(v).unwrap();
            assert_eq!(k as u32, v);
        }
        assert_eq!(TransferErrorKind::from_u32(0), None);
        assert_eq!(
            TransferErrorKind::ChangedDuringTransfer.as_str(),
            "changed_during_transfer"
        );
        assert_eq!(TransferErrorKind::NameIncompatible as u32, 10);
    }
}
