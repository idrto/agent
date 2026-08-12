/// Shared ABI constants and event kinds (mirrors `idr.h`).
library;

const int idrAbiVersion = 2;

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
