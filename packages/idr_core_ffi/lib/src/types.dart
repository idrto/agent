/// Shared ABI constants and event kinds (mirrors `idr.h`).
library;

const int idrAbiVersion = 3;

const int idrAuthBearer = 0;
const int idrAuthDeviceToken = 1;
const int idrAuthMtls = 2;

const int idrEventNone = 0;
const int idrEventConnected = 1;
const int idrEventStreamOpened = 2;
const int idrEventBytesAvailable = 3;
const int idrEventStreamClosed = 4;
const int idrEventError = 5;

/// Stable error kinds from `idr_core::IdrErrorKind` (`repr(u32)`).
class IdrErrorCode {
  static const int invalidArgument = 1;
  static const int notInitialized = 2;
  static const int authenticationFailed = 3;
  static const int authorizationDenied = 4;
  static const int targetNotFound = 5;
  static const int targetOffline = 6;
  static const int serviceNotFound = 7;
  static const int connectionRefused = 8;
  static const int signalingFailed = 9;
  static const int iceFailed = 10;
  static const int turnFailed = 11;
  static const int transportClosed = 12;
  static const int streamReset = 13;
  static const int timeout = 14;
  static const int backpressure = 15;
  static const int resourceExhausted = 16;
  static const int protocolError = 17;
  static const int incompatibleVersion = 18;
  static const int internalError = 19;
}

/// `-(idrTransferErrorBase + kind)` when the transfer layer refuses a call.
const int idrTransferErrorBase = 100;

// Transfer event kinds (`IDR_TEV_*`).
const int idrTevOffered = 1;
const int idrTevAwaitingDecision = 2;
const int idrTevAccepted = 3;
const int idrTevProgress = 4;
const int idrTevEntryFailed = 5;
const int idrTevRenamed = 6;
const int idrTevLeaseExpiring = 7;
const int idrTevPaused = 8;
const int idrTevResumed = 9;
const int idrTevFinished = 10;
const int idrTevInterrupted = 11;
const int idrTevResync = 12;

// Outcomes of IDR_TEV_FINISHED (`IDR_OUTCOME_*`).
const int idrOutcomeCompleted = 0;
const int idrOutcomeCompletedWithErrors = 1;
const int idrOutcomeFailed = 2;
const int idrOutcomeCancelled = 3;
const int idrOutcomeRejected = 4;

/// Stable transfer error names by code (`IDR_TERR_*`), as the CLI prints them.
const List<String> idrTransferErrorNames = [
  '',
  'protocol_violation',
  'incompatible_version',
  'manifest_invalid',
  'limit_exceeded',
  'rejected',
  'cancelled',
  'hash_mismatch',
  'size_mismatch',
  'changed_during_transfer',
  'name_incompatible',
  'storage_failed',
  'stalled',
  'transport_closed',
  'authorization_expired',
  'conflicting_manifest',
  'source_read_failed',
  'unauthorized',
  'completed_with_errors',
  'timeout',
];
