import 'dart:developer' as developer;
import 'dart:typed_data';

import 'package:idr_core_ffi/idr_core_ffi.dart';

import 'errors.dart';
import 'events.dart';
import 'ffi_isolate.dart';
import 'session.dart';
import 'catalog.dart';

void _idrLog(String message) {
  developer.log(message, name: 'idr_client');
}

/// Embedded Source runtime (owns the native engine on a background isolate).
class IdrRuntime {
  IdrRuntime._(this._ffi);

  final IdrFfiIsolate _ffi;
  bool _disposed = false;

  /// Create a runtime. Product path: [authToken] required, [useMock]=false.
  ///
  /// Engine create and later [connect] run on a background isolate so the
  /// Flutter UI thread does not freeze during Discovery/WebRTC signaling.
  static Future<IdrRuntime> create({
    String? libraryPath,
    String sourceId = 'dart',
    String sourceRegion = 'unknown',
    required String authToken,
    int authMode = idrAuthBearer,
    bool useMock = false,
    String? discoveryUrl,
    String? discoveryKey,
    bool insecureDev = false,
  }) async {
    _idrLog(
      'create: lib=${libraryPath ?? "(auto)"} mock=$useMock '
      'sourceId=$sourceId region=$sourceRegion '
      'discovery=${discoveryUrl ?? "(none)"} insecureDev=$insecureDev '
      'tokenLen=${authToken.length}',
    );
    if (authToken.isEmpty) {
      throw IdrException(
        IdrErrorCode.authenticationFailed,
        'authToken is required',
      );
    }
    final ffi = await IdrFfiIsolate.spawn();
    try {
      await ffi.engineCreate({
        'libraryPath': libraryPath,
        'sourceId': sourceId,
        'sourceRegion': sourceRegion,
        'authToken': authToken,
        'authMode': authMode,
        'useMock': useMock,
        'discoveryUrl': discoveryUrl,
        'discoveryKey': discoveryKey,
        'insecureDev': insecureDev,
      });
    } catch (e) {
      await ffi.dispose();
      rethrow;
    }
    _idrLog('engineCreate OK (background isolate)');
    return IdrRuntime._(ffi);
  }

  Future<IdrSession> connect(String targetFqhn) async {
    _ensureOpen();
    _idrLog('connect: fqhn=$targetFqhn');
    try {
      final sessionId = await _ffi.connect(targetFqhn);
      _idrLog('connect OK sessionId=$sessionId');
      return IdrSession(this, sessionId);
    } on IdrException catch (e) {
      _idrLog(
        'connect FAILED code=${e.code}/${describeErrorCode(e.code)} msg=${e.message}',
      );
      rethrow;
    }
  }

  /// Install the DP device identity (`idr_dp::DeviceIdentityJson`) used for
  /// mTLS / PoP. Call before [connect] when `authMode == idrAuthMtls`.
  Future<void> setDpIdentity(String identityJson) async {
    _ensureOpen();
    await _ffi.setDpIdentity(identityJson);
  }

  /// Events are not yet proxied across the FFI isolate; returns empty.
  List<IdrEvent> pollEvents({int max = 32}) {
    _ensureOpen();
    return const [];
  }

  Future<void> dispose() async {
    if (_disposed) return;
    _disposed = true;
    await _ffi.dispose();
  }

  void _ensureOpen() {
    if (_disposed) {
      throw IdrException(IdrErrorCode.notInitialized, 'runtime disposed');
    }
  }

  IdrFfiIsolate get ffi => _ffi;
}

/// Internal helpers used by session/stream.
extension IdrRuntimeInternal on IdrRuntime {
  Future<void> disconnectSession(int sessionId) async {
    _ensureOpen();
    await ffi.disconnect(sessionId);
  }

  Future<List<String>> listNamedServices(int sessionId) async {
    _ensureOpen();
    return ffi.sessionNamedServices(sessionId);
  }

  Future<List<NamedServiceInfo>> listNamedServiceCatalog(int sessionId) async {
    _ensureOpen();
    return ffi.sessionNamedServiceCatalog(sessionId);
  }

  Future<int> openNamedStream(int sessionId, String service) async {
    _ensureOpen();
    return ffi.openStream(sessionId, service);
  }

  Future<int> writeBytes(int sessionId, int streamId, Uint8List data) async {
    _ensureOpen();
    return ffi.streamWrite(sessionId, streamId, data);
  }

  Future<Uint8List> readBytes(int sessionId, int streamId, int maxLen) async {
    _ensureOpen();
    return ffi.streamRead(sessionId, streamId, maxLen);
  }

  Future<void> halfCloseStream(int sessionId, int streamId) async {
    _ensureOpen();
    await ffi.streamHalfClose(sessionId, streamId);
  }

  Future<void> resetStream(int sessionId, int streamId, int reason) async {
    _ensureOpen();
    await ffi.streamReset(sessionId, streamId, reason);
  }
}
