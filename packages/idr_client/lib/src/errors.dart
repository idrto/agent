import 'package:idr_core_ffi/idr_core_ffi.dart';

class IdrException implements Exception {
  IdrException(this.code, this.message);

  final int code;
  final String message;

  @override
  String toString() => 'IdrException($code): $message';
}

String describeErrorCode(int code) {
  switch (code) {
    case IdrErrorCode.invalidArgument:
      return 'invalid_argument';
    case IdrErrorCode.notInitialized:
      return 'not_initialized';
    case IdrErrorCode.serviceNotFound:
      return 'service_not_found';
    case IdrErrorCode.signalingFailed:
      return 'signaling_failed';
    case IdrErrorCode.iceFailed:
      return 'ice_failed';
    case IdrErrorCode.transportClosed:
      return 'transport_closed';
    case IdrErrorCode.backpressure:
      return 'backpressure';
    case IdrErrorCode.incompatibleVersion:
      return 'incompatible_version';
    default:
      return 'error_$code';
  }
}
