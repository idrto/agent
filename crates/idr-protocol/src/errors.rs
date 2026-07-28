use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u32),
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(usize),
    #[error("invalid frame")]
    InvalidFrame,
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("document expired")]
    DocumentExpired,
    #[error("malformed document: {0}")]
    MalformedDocument(String),
    #[error("invalid FQHN: {0}")]
    InvalidFqhn(String),
    #[error("conflicting command_id")]
    ConflictingCommand,
    #[error("command expired")]
    CommandExpired,
    #[error("authentication failed: {0}")]
    Authentication(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, ProtocolError>;
