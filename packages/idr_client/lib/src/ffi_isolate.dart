import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:idr_core_ffi/idr_core_ffi.dart';

import 'errors.dart';
import 'catalog.dart';

/// Owns all `idr_c_api` FFI calls on a background isolate so the UI never
/// blocks on Rust `block_on` (connect / engine create).
class IdrFfiIsolate {
  IdrFfiIsolate._(this._commands, this._responses) {
    _sub = _responses.listen(_onResponse);
  }

  final SendPort _commands;
  final ReceivePort _responses;
  late final StreamSubscription<dynamic> _sub;
  final Map<int, Completer<Object?>> _pending = {};
  int _nextId = 1;
  bool _closed = false;

  static Future<IdrFfiIsolate> spawn() async {
    final ready = ReceivePort();
    await Isolate.spawn(_main, ready.sendPort, debugName: 'idr_ffi');
    final ports = await ready.first as List<dynamic>;
    ready.close();
    final commands = ports[0] as SendPort;
    final attach = ports[1] as SendPort;
    final responses = ReceivePort();
    attach.send(responses.sendPort);
    return IdrFfiIsolate._(commands, responses);
  }

  Future<void> engineCreate(Map<String, Object?> cfg) =>
      _request({'op': 'create', ...cfg});

  Future<int> connect(String fqhn) async {
    final v = await _request({'op': 'connect', 'fqhn': fqhn});
    return v! as int;
  }

  Future<void> disconnect(int sessionId) =>
      _request({'op': 'disconnect', 'sessionId': sessionId});

  Future<void> setDpIdentity(String identityJson) =>
      _request({'op': 'setDpIdentity', 'json': identityJson});

  Future<List<String>> sessionNamedServices(int sessionId) async {
    final v = await _request({
      'op': 'namedServices',
      'sessionId': sessionId,
    });
    return (v! as List).cast<String>();
  }

  Future<List<NamedServiceInfo>> sessionNamedServiceCatalog(int sessionId) async {
    final v = await _request({
      'op': 'namedServiceCatalog',
      'sessionId': sessionId,
    });
    final list = v! as List;
    return list
        .map((e) {
          if (e is Map) {
            return NamedServiceInfo.fromJson(Map<String, dynamic>.from(e));
          }
          return null;
        })
        .whereType<NamedServiceInfo>()
        .where((e) => e.name.isNotEmpty)
        .toList();
  }

  Future<int> openStream(int sessionId, String service) async {
    final v = await _request({
      'op': 'openStream',
      'sessionId': sessionId,
      'service': service,
    });
    return v! as int;
  }

  Future<Uint8List> streamRead(int sessionId, int streamId, int maxLen) async {
    final v = await _request({
      'op': 'read',
      'sessionId': sessionId,
      'streamId': streamId,
      'maxLen': maxLen,
    });
    return v! as Uint8List;
  }

  Future<int> streamWrite(int sessionId, int streamId, Uint8List data) async {
    final v = await _request({
      'op': 'write',
      'sessionId': sessionId,
      'streamId': streamId,
      'data': data,
    });
    return v! as int;
  }

  Future<void> streamHalfClose(int sessionId, int streamId) => _request({
        'op': 'halfClose',
        'sessionId': sessionId,
        'streamId': streamId,
      });

  Future<void> streamReset(int sessionId, int streamId, int reason) =>
      _request({
        'op': 'reset',
        'sessionId': sessionId,
        'streamId': streamId,
        'reason': reason,
      });

  Future<void> dispose() async {
    if (_closed) return;
    _closed = true;
    try {
      await _request({'op': 'dispose'});
    } catch (_) {}
    await _sub.cancel();
    _responses.close();
    for (final c in _pending.values) {
      if (!c.isCompleted) {
        c.completeError(
          IdrException(IdrErrorCode.notInitialized, 'runtime disposed'),
        );
      }
    }
    _pending.clear();
  }

  Future<Object?> _request(Map<String, Object?> payload) {
    if (_closed) {
      return Future.error(
        IdrException(IdrErrorCode.notInitialized, 'runtime disposed'),
      );
    }
    final id = _nextId++;
    final c = Completer<Object?>();
    _pending[id] = c;
    _commands.send({'id': id, ...payload});
    return c.future;
  }

  void _onResponse(dynamic msg) {
    if (msg is! Map) return;
    final id = msg['id'] as int?;
    if (id == null) return;
    final c = _pending.remove(id);
    if (c == null || c.isCompleted) return;
    if (msg['ok'] == true) {
      c.complete(msg['value']);
    } else {
      c.completeError(
        IdrException(
          msg['code'] as int? ?? IdrErrorCode.internalError,
          msg['error'] as String? ?? 'native error',
        ),
      );
    }
  }
}

void _main(SendPort ready) {
  final commands = ReceivePort();
  final attach = ReceivePort();
  ready.send([commands.sendPort, attach.sendPort]);

  SendPort? replies;
  IdrBindings? bindings;
  Pointer<Void>? engine;

  attach.listen((msg) {
    replies = msg as SendPort;
    attach.close();
  });

  commands.listen((raw) {
    final msg = Map<String, Object?>.from(raw as Map);
    final id = msg['id'] as int;
    void ok([Object? value]) =>
        replies?.send({'id': id, 'ok': true, 'value': value});
    void err(int code, String error) =>
        replies?.send({'id': id, 'ok': false, 'code': code, 'error': error});

    try {
      switch (msg['op'] as String) {
        case 'create':
          if (engine != null) {
            err(IdrErrorCode.invalidArgument, 'engine already created');
            return;
          }
          bindings = openIdrBindings(
            libraryPath: msg['libraryPath'] as String?,
          );
          bindings!.ensureAbiCompatible();
          engine = _createEngine(bindings!, msg);
          ok();
          return;
        case 'connect':
          ok(_connect(bindings!, engine!, msg['fqhn'] as String));
          return;
        case 'disconnect':
          _rc(bindings!, bindings!.disconnect(engine!, msg['sessionId'] as int));
          ok();
          return;
        case 'setDpIdentity':
          final json = (msg['json'] as String).toNativeUtf8();
          try {
            _rc(bindings!, bindings!.setDpIdentity(engine!, json));
          } finally {
            malloc.free(json);
          }
          ok();
          return;
        case 'namedServices':
          ok(_namedServices(bindings!, engine!, msg['sessionId'] as int));
          return;
        case 'namedServiceCatalog':
          ok(_namedServiceCatalog(bindings!, engine!, msg['sessionId'] as int));
          return;
        case 'openStream':
          ok(
            _openStream(
              bindings!,
              engine!,
              msg['sessionId'] as int,
              msg['service'] as String,
            ),
          );
          return;
        case 'read':
          ok(
            _read(
              bindings!,
              engine!,
              msg['sessionId'] as int,
              msg['streamId'] as int,
              msg['maxLen'] as int,
            ),
          );
          return;
        case 'write':
          ok(
            _write(
              bindings!,
              engine!,
              msg['sessionId'] as int,
              msg['streamId'] as int,
              msg['data'] as Uint8List,
            ),
          );
          return;
        case 'halfClose':
          _rc(
            bindings!,
            bindings!.streamHalfClose(
              engine!,
              msg['sessionId'] as int,
              msg['streamId'] as int,
            ),
          );
          ok();
          return;
        case 'reset':
          _rc(
            bindings!,
            bindings!.streamReset(
              engine!,
              msg['sessionId'] as int,
              msg['streamId'] as int,
              msg['reason'] as int,
            ),
          );
          ok();
          return;
        case 'dispose':
          if (engine != null && bindings != null) {
            bindings!.engineDestroy(engine!);
          }
          engine = null;
          bindings = null;
          ok();
          commands.close();
          return;
        default:
          err(IdrErrorCode.invalidArgument, 'unknown op');
      }
    } on IdrException catch (e) {
      err(e.code, e.message);
    } catch (e) {
      err(IdrErrorCode.internalError, e.toString());
    }
  });
}

Pointer<Void> _createEngine(IdrBindings bindings, Map<String, Object?> msg) {
  final sourceId = msg['sourceId'] as String;
  final sourceRegion = msg['sourceRegion'] as String;
  final authToken = msg['authToken'] as String;
  final idPtr = sourceId.toNativeUtf8();
  final regionPtr = sourceRegion.toNativeUtf8();
  final tokenPtr = authToken.toNativeUtf8();
  final discoveryPtr = (msg['discoveryUrl'] as String?)?.toNativeUtf8();
  final keyPtr = (msg['discoveryKey'] as String?)?.toNativeUtf8();
  final cfg = calloc<IdrEngineConfigNative>();
  cfg.ref
    ..abiVersion = idrAbiVersion
    ..structSize = sizeOf<IdrEngineConfigNative>()
    ..useMock = (msg['useMock'] as bool) ? 1 : 0
    ..sourceId = idPtr
    ..sourceRegion = regionPtr
    ..authToken = tokenPtr
    ..authMode = msg['authMode'] as int
    ..discoveryUrl = discoveryPtr ?? nullptr
    ..discoveryKey = keyPtr ?? nullptr
    ..insecureDev = (msg['insecureDev'] as bool) ? 1 : 0;

  final engine = bindings.engineCreate(cfg);
  calloc.free(cfg);
  malloc.free(idPtr);
  malloc.free(regionPtr);
  malloc.free(tokenPtr);
  if (discoveryPtr != null) malloc.free(discoveryPtr);
  if (keyPtr != null) malloc.free(keyPtr);

  if (engine == nullptr) {
    throw IdrException(bindings.lastErrorCode(), _lastError(bindings));
  }
  return engine;
}

int _connect(IdrBindings bindings, Pointer<Void> engine, String fqhn) {
  final fqhnPtr = fqhn.toNativeUtf8();
  final out = calloc<Uint64>();
  final rc = bindings.connect(engine, fqhnPtr, out);
  malloc.free(fqhnPtr);
  final sessionId = out.value;
  calloc.free(out);
  if (rc != 0) {
    throw IdrException(bindings.lastErrorCode(), _lastError(bindings));
  }
  return sessionId;
}

List<String> _namedServices(
  IdrBindings bindings,
  Pointer<Void> engine,
  int sessionId,
) {
  final buf = calloc<Uint8>(8192);
  try {
    final rc = bindings.sessionNamedServices(
      engine,
      sessionId,
      buf.cast<Utf8>(),
      8192,
    );
    if (rc < 0) {
      throw IdrException(bindings.lastErrorCode(), _lastError(bindings));
    }
    final json = buf.cast<Utf8>().toDartString(length: rc);
    final decoded = jsonDecode(json);
    if (decoded is! List) return const [];
    return decoded.map((e) => e.toString()).where((s) => s.isNotEmpty).toList();
  } finally {
    calloc.free(buf);
  }
}

/// Returns raw maps so they can cross the isolate boundary (no custom types).
List<Map<String, dynamic>> _namedServiceCatalog(
  IdrBindings bindings,
  Pointer<Void> engine,
  int sessionId,
) {
  final buf = calloc<Uint8>(16384);
  try {
    final rc = bindings.sessionNamedServiceCatalog(
      engine,
      sessionId,
      buf.cast<Utf8>(),
      16384,
    );
    if (rc < 0) {
      throw IdrException(bindings.lastErrorCode(), _lastError(bindings));
    }
    final json = buf.cast<Utf8>().toDartString(length: rc);
    final decoded = jsonDecode(json);
    if (decoded is! List) return const [];
    return decoded
        .whereType<Map>()
        .map((e) => Map<String, dynamic>.from(e))
        .toList();
  } finally {
    calloc.free(buf);
  }
}

int _openStream(
  IdrBindings bindings,
  Pointer<Void> engine,
  int sessionId,
  String service,
) {
  final svc = service.toNativeUtf8();
  final out = calloc<Uint64>();
  final rc = bindings.openStream(engine, sessionId, svc, out);
  malloc.free(svc);
  final id = out.value;
  calloc.free(out);
  _rc(bindings, rc);
  return id;
}

Uint8List _read(
  IdrBindings bindings,
  Pointer<Void> engine,
  int sessionId,
  int streamId,
  int maxLen,
) {
  final ptr = calloc<Uint8>(maxLen);
  final out = calloc<IntPtr>();
  final rc = bindings.streamRead(engine, sessionId, streamId, ptr, maxLen, out);
  final n = out.value;
  final bytes = Uint8List.fromList(ptr.asTypedList(n));
  calloc.free(ptr);
  calloc.free(out);
  _rc(bindings, rc);
  return bytes;
}

int _write(
  IdrBindings bindings,
  Pointer<Void> engine,
  int sessionId,
  int streamId,
  Uint8List data,
) {
  final ptr = calloc<Uint8>(data.length);
  ptr.asTypedList(data.length).setAll(0, data);
  final out = calloc<IntPtr>();
  final rc =
      bindings.streamWrite(engine, sessionId, streamId, ptr, data.length, out);
  final n = out.value;
  calloc.free(ptr);
  calloc.free(out);
  _rc(bindings, rc);
  return n;
}

void _rc(IdrBindings bindings, int rc) {
  if (rc != 0) {
    throw IdrException(bindings.lastErrorCode(), _lastError(bindings));
  }
}

String _lastError(IdrBindings bindings) {
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
