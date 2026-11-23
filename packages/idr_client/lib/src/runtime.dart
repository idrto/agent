import 'dart:convert';
import 'dart:typed_data';

import 'package:idr_core_ffi/idr_core_ffi.dart';
import 'package:idr_telemetry/idr_telemetry.dart';

import 'errors.dart';
import 'events.dart';
import 'ffi_isolate.dart';
import 'session.dart';
import 'catalog.dart';
import 'transfer.dart';

const _log = IdrLog('idr_client.runtime');

/// Config for `idr_telemetry_init`: the engine writes the same run (host `app_session_id`)
/// into the host's directory (docs/observability/01 §3). Null without host telemetry.
String? _engineTelemetry() {
  final t = Telemetry.instance;
  if (t == null) return null;
  return jsonEncode({
    'service': t.config.service,
    'log_root': t.logRoot,
    'app_session_id': t.appSessionId,
    'filter': t.config.filter,
  });
}

/// Embedded Source runtime (owns the native engine on a background isolate).
class IdrRuntime {
  IdrRuntime._(this._ffi) : transfers = IdrTransfers(_ffi);

  final IdrFfiIsolate _ffi;
  bool _disposed = false;

  /// File transfer (call `transfers.enable` after [setDpIdentity]).
  final IdrTransfers transfers;

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
        'telemetry': _engineTelemetry(),
      });
    } catch (e) {
      await ffi.dispose();
      rethrow;
    }
    return IdrRuntime._(ffi);
  }

  /// One connection attempt, as the span `source.connect.attempt` (child of the caller's
  /// `source.connect`); the engine's `ffi.call` and its work nest under it.
  Future<IdrSession> connect(String targetFqhn) async {
    _ensureOpen();
    return _log.span('source.connect.attempt', (s) async {
      try {
        return IdrSession(this, await _ffi.connect(targetFqhn));
      } on IdrException catch (e) {
        s.fail(describeErrorCode(e.code), message: e.message);
        rethrow;
      }
    }, attrs: {'target.fqhn': targetFqhn}, persistStart: true);
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
