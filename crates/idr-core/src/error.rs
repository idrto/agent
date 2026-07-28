//! Stable public error categories shared across Rust, future C ABI, and Dart.

use std::fmt;

use thiserror::Error;

use idr_protocol::errors::ProtocolError;

/// Stable error category for public APIs and ABI mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum IdrErrorKind {
    InvalidArgument = 1,
    NotInitialized = 2,
    AuthenticationFailed = 3,
    AuthorizationDenied = 4,
    TargetNotFound = 5,
    TargetOffline = 6,
    ServiceNotFound = 7,
    ConnectionRefused = 8,
    SignalingFailed = 9,
    IceFailed = 10,
    TurnFailed = 11,
    TransportClosed = 12,
    StreamReset = 13,
    Timeout = 14,
    Backpressure = 15,
    ResourceExhausted = 16,
    ProtocolError = 17,
    IncompatibleVersion = 18,
    InternalError = 19,
}

impl IdrErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid_argument",
            Self::NotInitialized => "not_initialized",
            Self::AuthenticationFailed => "authentication_failed",
            Self::AuthorizationDenied => "authorization_denied",
            Self::TargetNotFound => "target_not_found",
            Self::TargetOffline => "target_offline",
            Self::ServiceNotFound => "service_not_found",
            Self::ConnectionRefused => "connection_refused",
            Self::SignalingFailed => "signaling_failed",
            Self::IceFailed => "ice_failed",
            Self::TurnFailed => "turn_failed",
            Self::TransportClosed => "transport_closed",
            Self::StreamReset => "stream_reset",
            Self::Timeout => "timeout",
            Self::Backpressure => "backpressure",
            Self::ResourceExhausted => "resource_exhausted",
            Self::ProtocolError => "protocol_error",
            Self::IncompatibleVersion => "incompatible_version",
            Self::InternalError => "internal_error",
        }
    }
}

impl fmt::Display for IdrErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Error)]
#[error("{kind}: {message}")]
pub struct IdrError {
    pub kind: IdrErrorKind,
    pub message: String,
}

impl IdrError {
    pub fn new(kind: IdrErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> IdrErrorKind {
        self.kind
    }
}

pub type Result<T> = std::result::Result<T, IdrError>;

impl From<ProtocolError> for IdrError {
    fn from(value: ProtocolError) -> Self {
        let kind = match &value {
            ProtocolError::UnsupportedVersion(_) => IdrErrorKind::IncompatibleVersion,
            ProtocolError::FrameTooLarge(_)
            | ProtocolError::InvalidFrame
            | ProtocolError::MalformedDocument(_)
            | ProtocolError::InvalidFqhn(_)
            | ProtocolError::Serialization(_) => IdrErrorKind::ProtocolError,
            ProtocolError::InvalidSignature | ProtocolError::Authentication(_) => {
                IdrErrorKind::AuthenticationFailed
            }
            ProtocolError::DocumentExpired | ProtocolError::CommandExpired => IdrErrorKind::Timeout,
            ProtocolError::ConflictingCommand => IdrErrorKind::ResourceExhausted,
        };
        Self::new(kind, value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_strings_are_stable() {
        assert_eq!(IdrErrorKind::Backpressure.as_str(), "backpressure");
        assert_eq!(IdrErrorKind::TargetOffline.as_str(), "target_offline");
    }
}
