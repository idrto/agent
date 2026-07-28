import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:idr_core_ffi/idr_core_ffi.dart';

import 'errors.dart';
import 'events.dart';
import 'session.dart';

/// Embedded Source runtime (owns the native engine).
class IdrRuntime {
  IdrRuntime._(this._bindings, this._engine);

  final IdrBindings _bindings;
  final Pointer<Void> _engine;
  bool _disposed = false;

  /// Create a runtime. Pass [useMock]=true for CI / local tests without libdatachannel.
  factory IdrRuntime.create({
    String? libraryPath,
    String sourceId = 'dart',
    String sourceRegion = 'unknown',
    bool useMock = true,
  }) {
    final bindings = openIdrBindings(libraryPath: libraryPath);
    bindings.ensureAbiCompatible();

    final idPtr = sourceId.toNativeUtf8();
    final regionPtr = sourceRegion.toNativeUtf8();
    final cfg = calloc<IdrEngineConfigNative>();
    cfg.ref
      ..abiVersion = idrAbiVersion
      ..structSize = sizeOf<IdrEngineConfigNative>()
      ..useMock = useMock ? 1 : 0
      ..sourceId = idPtr
      ..sourceRegion = regionPtr;

    final engine = bindings.engineCreate(cfg);
    calloc.free(cfg);
    malloc.free(idPtr);
    malloc.free(regionPtr);

    if (engine == nullptr) {
      throw IdrException(
        bindings.lastErrorCode(),
        _readLastError(bindings),
      );
    }
    return IdrRuntime._(bindings, engine);
  }

  Future<IdrSession> connect(String targetFqhn) async {
    _ensureOpen();
    final fqhn = targetFqhn.toNativeUtf8();
    final out = calloc<Uint64>();
    final rc = _bindings.connect(_engine, fqhn, out);
    malloc.free(fqhn);
    final sessionId = out.value;
    calloc.free(out);
    if (rc != 0) {
      throw IdrException(_bindings.lastErrorCode(), _readLastError(_bindings));
    }
    return IdrSession(this, sessionId);
  }

  /// Drain up to [max] batched events (no per-packet callbacks).
  List<IdrEvent> pollEvents({int max = 32}) {
    _ensureOpen();
    final buf = calloc<IdrEventNative>(max);
    final outCount = calloc<IntPtr>();
    final rc = _bindings.pollEvents(_engine, buf, max, outCount);
    if (rc != 0) {
      calloc.free(buf);
      calloc.free(outCount);
      throw IdrException(_bindings.lastErrorCode(), _readLastError(_bindings));
    }
    final n = outCount.value;
    final events = <IdrEvent>[];
    for (var i = 0; i < n; i++) {
      final e = buf[i];
      final mapped = mapNativeEvent(e.kind, e.sessionId, e.streamId, e.code, e.len);
      if (mapped != null) {
        events.add(mapped);
      }
    }
    calloc.free(buf);
    calloc.free(outCount);
    return events;
  }

  void dispose() {
    if (_disposed) {
      return;
    }
    _disposed = true;
    _bindings.engineDestroy(_engine);
  }

  void _ensureOpen() {
    if (_disposed) {
      throw IdrException(IdrErrorCode.notInitialized, 'runtime disposed');
    }
  }

  IdrBindings get bindings => _bindings;
  Pointer<Void> get engine => _engine;

  static String _readLastError(IdrBindings bindings) {
    final buf = calloc<Uint8>(512);
    final n = bindings.lastErrorMessage(buf.cast<Utf8>(), 512);
    if (n <= 0) {
      calloc.free(buf);
      return describeErrorCode(bindings.lastErrorCode());
    }
    final msg = buf.cast<Utf8>().toDartString();
    calloc.free(buf);
    return msg;
  }

  void checkRc(int rc) {
    if (rc != 0) {
      throw IdrException(_bindings.lastErrorCode(), _readLastError(_bindings));
    }
  }
}

/// Internal helpers used by session/stream.
extension IdrRuntimeInternal on IdrRuntime {
  void disconnectSession(int sessionId) {
    _ensureOpen();
    checkRc(bindings.disconnect(engine, sessionId));
  }

  int openNamedStream(int sessionId, String service) {
    _ensureOpen();
    final svc = service.toNativeUtf8();
    final out = calloc<Uint64>();
    final rc = bindings.openStream(engine, sessionId, svc, out);
    malloc.free(svc);
    final id = out.value;
    calloc.free(out);
    checkRc(rc);
    return id;
  }

  int writeBytes(int sessionId, int streamId, Uint8List data) {
    _ensureOpen();
    final ptr = calloc<Uint8>(data.length);
    ptr.asTypedList(data.length).setAll(0, data);
    final out = calloc<IntPtr>();
    final rc = bindings.streamWrite(engine, sessionId, streamId, ptr, data.length, out);
    final n = out.value;
    calloc.free(ptr);
    calloc.free(out);
    checkRc(rc);
    return n;
  }

  Uint8List readBytes(int sessionId, int streamId, int maxLen) {
    _ensureOpen();
    final ptr = calloc<Uint8>(maxLen);
    final out = calloc<IntPtr>();
    final rc = bindings.streamRead(engine, sessionId, streamId, ptr, maxLen, out);
    final n = out.value;
    final bytes = Uint8List.fromList(ptr.asTypedList(n));
    calloc.free(ptr);
    calloc.free(out);
    checkRc(rc);
    return bytes;
  }

  void halfCloseStream(int sessionId, int streamId) {
    _ensureOpen();
    checkRc(bindings.streamHalfClose(engine, sessionId, streamId));
  }

  void resetStream(int sessionId, int streamId, int reason) {
    _ensureOpen();
    checkRc(bindings.streamReset(engine, sessionId, streamId, reason));
  }
}
