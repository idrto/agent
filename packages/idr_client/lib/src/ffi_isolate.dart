import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:idr_core_ffi/idr_core_ffi.dart';

import 'errors.dart';
import 'catalog.dart';
import 'transfer.dart' show IdrTransferException;

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
  final StreamController<Map<dynamic, dynamic>> _tev = StreamController.broadcast();
  int _nextId = 1;
  bool _closed = false;

  /// Transfer events drained on the FFI isolate (see `IdrTransfers.events`).
  Stream<Map<dynamic, dynamic>> get transferEvents => _tev.stream;

  /// One `idr_transfer_*` operation on the FFI isolate. `id` is the request id; name a transfer `tid`.
  Future<Object?> transfer(String op, Map<String, Object?> args) {
    assert(!args.containsKey('id') && !args.containsKey('op'));
    return _request({...args, 'op': op});
  }

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
    await _tev.close();
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
    final tev = msg['tev'];
    if (tev is List) {
      for (final e in tev) {
        _tev.add(e as Map);
      }
      return;
    }
    final id = msg['id'] as int?;
    if (id == null) return;
    final c = _pending.remove(id);
    if (c == null || c.isCompleted) return;
    if (msg['ok'] == true) {
      c.complete(msg['value']);
    } else {
      final code = msg['code'] as int? ?? IdrErrorCode.internalError;
      final error = msg['error'] as String? ?? 'native error';
      c.completeError(
        code >= idrTransferErrorBase
            ? IdrTransferException(code - idrTransferErrorBase, error)
            : IdrException(code, error),
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
  IdrTransferBindings? tb;
  Timer? poller;
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
          final lib = loadIdrLibrary(path: msg['libraryPath'] as String?);
          bindings = IdrBindings(lib);
          bindings!.ensureAbiCompatible();
          tb = IdrTransferBindings(lib);
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
        case 'transferEnable':
          _transferEnable(bindings!, tb!, engine!, msg);
          // Drain on this isolate; the UI isolate only receives batches.
          poller ??= Timer.periodic(const Duration(milliseconds: 200), (_) {
            final e = engine;
            if (e == null) return;
            final batch = _transferPoll(tb!, e);
            if (batch.isNotEmpty) replies?.send({'tev': batch});
          });
          ok();
          return;
        case 'transferSend':
          ok(_transferSend(bindings!, tb!, engine!, msg['target'] as String,
              (msg['paths'] as List).cast<String>()));
          return;
        case 'transferSendSelection':
          ok(_transferSendSelection(bindings!, tb!, engine!, msg['target'] as String,
              msg['folder'] as String, (msg['selected'] as List).cast<String>()));
          return;
        case 'transferCmd':
          _transferCmd(bindings!, tb!, engine!, msg['cmd'] as String, msg['tid'] as String,
              msg['outDir'] as String?);
          ok();
          return;
        case 'transferList':
          ok(_json(bindings!, (b, n) => tb!.list(engine!, b, n)));
          return;
        case 'transferStatus':
          ok(_withId(msg['tid'] as String,
              (id) => _json(bindings!, (b, n) => tb!.status(engine!, id, b, n))));
          return;
        case 'transferEntries':
          ok(_withId(
              msg['tid'] as String,
              (id) => _json(bindings!,
                  (b, n) => tb!.entries(engine!, id, msg['first'] as int, msg['max'] as int, b, n))));
          return;
        case 'dispose':
          poller?.cancel();
          poller = null;
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

// ---- File transfer (runs on the FFI isolate) ---------------------------------

void _trc(IdrBindings bindings, int rc) {
  if (rc == 0) return;
  if (rc <= -idrTransferErrorBase) {
    // Transfer refusal: carry the code so the UI side maps it to IdrTransferException.
    throw IdrException(-rc, _lastError(bindings));
  }
  throw IdrException(bindings.lastErrorCode(), _lastError(bindings));
}

void _transferEnable(
    IdrBindings bindings, IdrTransferBindings tb, Pointer<Void> engine, Map<String, Object?> msg) {
  using((arena) {
    final cfg = arena<IdrTransferConfigNative>();
    final pem = msg['entityRootPem'] as String?;
    cfg.ref
      ..abiVersion = idrAbiVersion
      ..structSize = sizeOf<IdrTransferConfigNative>()
      ..dataDir = (msg['dataDir'] as String).toNativeUtf8(allocator: arena)
      ..receiveDir = (msg['receiveDir'] as String).toNativeUtf8(allocator: arena)
      ..entityRootPem = pem == null ? nullptr : pem.toNativeUtf8(allocator: arena)
      ..interactive = (msg['interactive'] as bool) ? 1 : 0
      ..anyDestination = (msg['anyDestination'] as bool) ? 1 : 0
      ..leaseMinutes = msg['leaseMinutes'] as int
      ..offerExpirySeconds = msg['offerExpirySeconds'] as int;
    _trc(bindings, tb.enable(engine, cfg));
  });
}

Pointer<Pointer<Utf8>> _strings(Arena arena, List<String> items) {
  final p = arena<Pointer<Utf8>>(items.isEmpty ? 1 : items.length);
  for (var i = 0; i < items.length; i++) {
    p[i] = items[i].toNativeUtf8(allocator: arena);
  }
  return p;
}

String _hex(Pointer<Uint8> id) =>
    List.generate(16, (i) => id[i].toRadixString(16).padLeft(2, '0')).join();

Pointer<Uint8> _idBuf(Arena arena, String hex) {
  if (hex.length != 32) {
    throw IdrException(IdrErrorCode.invalidArgument, 'transfer id must be 32 hex digits');
  }
  final p = arena<Uint8>(16);
  for (var i = 0; i < 16; i++) {
    final b = int.tryParse(hex.substring(2 * i, 2 * i + 2), radix: 16);
    if (b == null) {
      throw IdrException(IdrErrorCode.invalidArgument, 'transfer id must be 32 hex digits');
    }
    p[i] = b;
  }
  return p;
}

T _withId<T>(String hex, T Function(Pointer<Uint8>) f) => using((arena) => f(_idBuf(arena, hex)));

String _transferSend(IdrBindings bindings, IdrTransferBindings tb, Pointer<Void> engine,
        String target, List<String> paths) =>
    using((arena) {
      final out = arena<Uint8>(16);
      _trc(
          bindings,
          tb.send(engine, target.toNativeUtf8(allocator: arena), _strings(arena, paths),
              paths.length, out));
      return _hex(out);
    });

String _transferSendSelection(IdrBindings bindings, IdrTransferBindings tb, Pointer<Void> engine,
        String target, String folder, List<String> selected) =>
    using((arena) {
      final out = arena<Uint8>(16);
      _trc(
          bindings,
          tb.sendSelection(engine, target.toNativeUtf8(allocator: arena),
              folder.toNativeUtf8(allocator: arena), _strings(arena, selected), selected.length, out));
      return _hex(out);
    });

void _transferCmd(IdrBindings bindings, IdrTransferBindings tb, Pointer<Void> engine, String cmd,
    String id, String? outDir) {
  using((arena) {
    final p = _idBuf(arena, id);
    final rc = switch (cmd) {
      'accept' => tb.accept(engine, p, outDir == null ? nullptr : outDir.toNativeUtf8(allocator: arena)),
      'reject' => tb.reject(engine, p),
      'pause' => tb.pause(engine, p),
      'resume' => tb.resume(engine, p),
      'cancel' => tb.cancel(engine, p),
      'retryFailed' => tb.retryFailed(engine, p),
      _ => throw IdrException(IdrErrorCode.invalidArgument, 'unknown transfer command'),
    };
    _trc(bindings, rc);
  });
}

/// Call a JSON-returning function, growing the buffer while it is too small.
Object? _json(IdrBindings bindings, int Function(Pointer<Utf8>, int) call) {
  for (var cap = 64 * 1024; cap <= 64 * 1024 * 1024; cap *= 4) {
    final buf = calloc<Uint8>(cap);
    try {
      final rc = call(buf.cast<Utf8>(), cap);
      if (rc == -IdrErrorCode.resourceExhausted) continue;
      _trc(bindings, rc < 0 ? rc : 0);
      return jsonDecode(buf.cast<Utf8>().toDartString(length: rc));
    } finally {
      calloc.free(buf);
    }
  }
  throw IdrException(IdrErrorCode.resourceExhausted, 'transfer JSON too large');
}

List<Map<String, Object>> _transferPoll(IdrTransferBindings tb, Pointer<Void> engine) {
  const max = 64;
  final out = <Map<String, Object>>[];
  using((arena) {
    final buf = arena<IdrTransferEventNative>(max);
    final count = arena<IntPtr>();
    while (true) {
      if (tb.pollEvents(engine, buf, max, count) != 0) return;
      final n = count.value;
      for (var i = 0; i < n; i++) {
        final e = buf[i];
        out.add({
          'kind': e.kind,
          'code': e.code,
          'id': List.generate(16, (j) => e.transferId[j].toRadixString(16).padLeft(2, '0')).join(),
          'entry': e.entry,
          'filesDone': e.filesDone,
          'filesTotal': e.filesTotal,
          'filesFailed': e.filesFailed,
          'bytesDone': e.bytesDone,
          'bytesTotal': e.bytesTotal,
          'bytesPerSec': e.bytesPerSec,
        });
      }
      if (n < max) return;
    }
  });
  return out;
}
