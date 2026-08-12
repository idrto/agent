import 'package:idr_core_ffi/idr_core_ffi.dart';

class IdrException implements Exception {
  IdrException(this.code, this.message);

  final int code;
  final String message;

  String get codeName => describeErrorCode(code);

  @override
  String toString() => 'IdrException($code/$codeName): $message';
}

String describeErrorCode(int code) {
  switch (code) {
    case IdrErrorCode.invalidArgument:
      return 'invalid_argument';
    case IdrErrorCode.notInitialized:
      return 'not_initialized';
    case IdrErrorCode.authenticationFailed:
      return 'authentication_failed';
    case IdrErrorCode.authorizationDenied:
      return 'authorization_denied';
    case IdrErrorCode.targetNotFound:
      return 'target_not_found';
    case IdrErrorCode.targetOffline:
      return 'target_offline';
    case IdrErrorCode.serviceNotFound:
      return 'service_not_found';
    case IdrErrorCode.connectionRefused:
      return 'connection_refused';
    case IdrErrorCode.signalingFailed:
      return 'signaling_failed';
    case IdrErrorCode.iceFailed:
      return 'ice_failed';
    case IdrErrorCode.turnFailed:
      return 'turn_failed';
    case IdrErrorCode.transportClosed:
      return 'transport_closed';
    case IdrErrorCode.streamReset:
      return 'stream_reset';
    case IdrErrorCode.timeout:
      return 'timeout';
    case IdrErrorCode.backpressure:
      return 'backpressure';
    case IdrErrorCode.resourceExhausted:
      return 'resource_exhausted';
    case IdrErrorCode.protocolError:
      return 'protocol_error';
    case IdrErrorCode.incompatibleVersion:
      return 'incompatible_version';
    case IdrErrorCode.internalError:
      return 'internal_error';
    default:
      return 'error_$code';
  }
}
