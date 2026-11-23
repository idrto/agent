// Public API: Telemetry.init/shutdown, IdrLog, Zone-scoped spans and correlation IDs,
// crash capture (runGuarded), worker-isolate link. docs/observability/01 §2.4.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';

import 'ctx.dart';
import 'files.dart';
import 'ids.dart';
import 'pipeline.dart';
import 'record.dart';
import 'secret.dart';

const _correlationKeys = {'session_id', 'connection_id', 'transfer_id', 'operation_id', 'report_id'};

class TelemetryConfig {
  const TelemetryConfig({
    required this.service,
    required this.serviceVersion,
    this.logRoot,
    this.filter = 'info',
    this.stderrLevel,
    this.recorderBytes = 3 * 1024 * 1024,
    this.queueBytes = 1024 * 1024,
    this.parentAppSessionId,
    this.limits,
  });

  /// Process kind: `idr_target_app`, `idrs`, `idr` (03 §1.3 `service`).
  final String service;
  final String serviceVersion;

  /// Log root (`IDR_LOG_DIR`); files in `<root>/<service>/`, crashes in `<root>/crash/`.
  /// Null = no files (tests).
  final String? logRoot;

  /// `IDR_LOG` directives, default `info`.
  final String filter;

  /// CLI `-v`: also print records at or above this level to stderr (pretty). Null = off.
  final Level? stderrLevel;
  final int recorderBytes;
  final int queueBytes;
  final String? parentAppSessionId;

  /// Test hook; production uses the defaults from [recorderBytes]/[queueBytes].
  final Limits? limits;
}

/// Correlation IDs in scope (inherited through Zones).
class _Corr {
  const _Corr({this.sessionId, this.connectionId, this.transferId, this.operationId, this.reportId});
  final String? sessionId, connectionId, transferId, operationId, reportId;

  _Corr merge(Map<String, Object?> m) {
    String? pick(String k, String? old) {
      final v = m[k];
      return v is String && isUuid(v) ? v : old;
    }

    return _Corr(
      sessionId: pick('session_id', sessionId),
      connectionId: pick('connection_id', connectionId),
      transferId: pick('transfer_id', transferId),
      operationId: pick('operation_id', operationId),
      reportId: pick('report_id', reportId),
    );
  }

  void applyTo(Record r) => r
    ..sessionId = sessionId
    ..connectionId = connectionId
    ..transferId = transferId
    ..operationId = operationId
    ..reportId = reportId;
}

final Object _spanKey = Object();
final Object _corrKey = Object();

_Corr get _corr => Zone.current[_corrKey] as _Corr? ?? const _Corr();

/// One instrumented step. Attributes and outcome can be set while it runs.
class Span {
  Span._(this.name, this.component, this.level, this.traceId, this.spanId, this.parentSpanId, this.links, this._corr);

  final String name;
  final String component;
  final Level level;
  final String traceId;
  final String spanId;
  final String? parentSpanId;
  final List<(String, String)> links;
  final _Corr _corr;
  final Map<String, Object> attrs = {};
  final DateTime _startWall = DateTime.now();
  final Stopwatch _sw = Stopwatch()..start();
  ErrorInfo? _error;

  TraceContext get context => TraceContext(traceId, spanId);

  void set(String key, Object value) => attrs[key] = _checkAttr(key, value);

  /// Marks the outcome failed with a stable `error.type`.
  void fail(String errorType, {String? message}) => _error = ErrorInfo(errorType, message: message);
}

Span? get currentSpan => Zone.current[_spanKey] as Span?;

TraceContext? currentTrace() => currentSpan?.context;
String? currentTraceparent() => currentTrace()?.toTraceparent();

/// The full local context for FFI, isolates and IPC (`ctx_json`).
LocalContext currentContext() {
  final c = _corr;
  return LocalContext(trace: currentTrace(), sessionId: c.sessionId, operationId: c.operationId, transferId: c.transferId);
}

String currentContextJson() => currentContext().toJson();

/// Runs [body] with correlation IDs in scope (no span).
T withIds<T>(T Function() body, {String? sessionId, String? connectionId, String? transferId, String? operationId}) {
  final c = _corr.merge({
    'session_id': sessionId,
    'connection_id': connectionId,
    'transfer_id': transferId,
    'operation_id': operationId,
  });
  return runZoned(body, zoneValues: {_corrKey: c});
}

/// Restores a context received over FFI, IPC or from another isolate (`ctx_json`).
T withContext<T>(LocalContext ctx, T Function() body) {
  final c = _corr.merge({'session_id': ctx.sessionId, 'operation_id': ctx.operationId, 'transfer_id': ctx.transferId});
  return runZoned(body, zoneValues: {_corrKey: c, if (ctx.trace != null) _spanKey: _RemoteParent(ctx.trace!)});
}

/// A parent known only by its W3C context (from another process or isolate).
class _RemoteParent extends Span {
  _RemoteParent(TraceContext t) : super._('remote', 'remote', Level.info, t.traceId, t.spanId, null, const [], const _Corr());
}

Object _checkAttr(String key, Object? value) {
  if (value is Secret) throw ArgumentError('Secret values cannot be logged ($key)');
  return switch (value) {
    String() || int() || bool() || double() || List<String>() => value as Object,
    Iterable() => [for (final v in value) '$v'],
    null => 'null',
    _ => value.toString(),
  };
}

/// Process-wide (per isolate) telemetry. Call [init] once at the composition point.
class Telemetry {
  Telemetry._(this.config, this.appSessionId, this._directives, this._pipeline, this._crashDir);

  static Telemetry? _instance;
  static Telemetry? get instance => _instance;

  final TelemetryConfig config;
  final String appSessionId;
  final Directives _directives;
  final Pipeline _pipeline;
  final Directory? _crashDir;
  _WorkerLink? _worker;
  ReceivePort? _linkPort;
  RawReceivePort? _errorPort;

  /// Installs telemetry for this isolate. Recovery runs before cleanup (04 §1.3).
  static Future<Telemetry> init(TelemetryConfig config) async {
    if (_instance != null) throw StateError('Telemetry already initialized');
    final id = newId();
    final directives = Directives.parse(config.filter);
    final limits = config.limits ?? Limits(queueBytes: config.queueBytes, ringBytes: config.recorderBytes);
    final startup = <Record>[];
    final root = config.logRoot;
    final crashDir = root == null ? null : Directory('$root${Platform.pathSeparator}crash');
    late final Telemetry t;
    Record make(Level level, String event) => t._record(Kind.log, level, event, 'idr_telemetry');
    final pipeline = Pipeline(
      limits: limits,
      stderrSink: config.stderrLevel == null ? null : stderr,
      makeRecord: (l, e) => make(l, e)..error = l >= Level.warn ? ErrorInfo(e.split('.').last) : null,
    );
    t = Telemetry._(config, id, directives, pipeline, crashDir);
    if (root != null) {
      final dir = Directory('$root${Platform.pathSeparator}${config.service}');
      final FileSink sink;
      try {
        final start = _fileStart(DateTime.now().toUtc());
        sink = FileSink.open(dir, start, id, 'jsonl');
        for (final r in recoverRuns(dir, crashDir!, 'jsonl', own: sink.key)) {
          startup.add(make(Level.warn, 'app.previous_exit_unclean')
            ..error = ErrorInfo(r.exit == Exit.crash ? 'crash' : 'unclean_exit')
            ..attrs.addAll({
              'previous_app_session_id': r.appSessionId,
              'crash_record': r.exit == Exit.crash,
              'open_operations': r.openOperations,
            }));
        }
        for (final k in sink.cleanup().unknownRuns) {
          startup.add(make(Level.warn, 'diag.sink.degraded')
            ..error = ErrorInfo('ownership_unknown')
            ..attrs.addAll({'reason': 'ownership_unknown', 'run': '$k'}));
        }
        pipeline.file = sink;
        unawaited(_diskGuard(t, dir));
      } on FileSystemException catch (e) {
        startup.add(make(Level.warn, 'diag.sink.unavailable')
          ..error = ErrorInfo('open_failed', message: e.message)
          ..attrs['reason'] = 'open_failed');
      }
    }
    _instance = t;
    t._emit(make(Level.info, 'app.started')
      ..attrs.addAll({
        'os.type': Platform.operatingSystem,
        'os.version': Platform.operatingSystemVersion,
        'process.pid': pid,
        'telemetry.schema_version': schema,
        if (config.parentAppSessionId != null) 'parent_app_session_id': config.parentAppSessionId!,
        'locale': Platform.localeName,
      }));
    for (final r in startup) {
      t._emit(r);
    }
    t._errorPort = RawReceivePort((Object? pair) {
      final l = pair as List<Object?>;
      t.recordCrash(l[0] ?? 'unknown', StackTrace.fromString('${l[1] ?? ''}'), source: 'isolate');
    });
    Isolate.current.addErrorListener(t._errorPort!.sendPort);
    return t;
  }

  /// Initializes a worker isolate: records are forwarded to the main isolate's pipeline,
  /// keeping one `app_session_id` and one file per process.
  static Telemetry initWorker(TelemetryLink link) {
    if (_instance != null) throw StateError('Telemetry already initialized');
    final config = TelemetryConfig(service: link.service, serviceVersion: link.serviceVersion, filter: link.filter);
    final t = Telemetry._(config, link.appSessionId, Directives.parse(link.filter),
        Pipeline(makeRecord: (l, e) => Record(Kind.log, l, e)), null)
      .._worker = _WorkerLink(link.port);
    _instance = t;
    return t;
  }

  /// A link to pass to a worker isolate (e.g. the FFI isolate) for [initWorker].
  TelemetryLink link() {
    _linkPort ??= ReceivePort()
      ..listen((m) {
        final msg = m as Map<String, Object?>;
        final r = recordFromJson(jsonDecode(msg['line'] as String) as Map<String, Object?>);
        _pipeline.submit(r, _route(r.component, r.level));
      });
    return TelemetryLink(_linkPort!.sendPort, appSessionId, config.service, config.serviceVersion, config.filter);
  }

  /// Drains the flight recorder and waits until it is on disk (bundle builds).
  static Future<void> flush() => _instance?._pipeline.flushAndWait() ?? Future.value();

  /// Waits until everything logged so far is written.
  static Future<void> sync() => _instance?._pipeline.sync() ?? Future.value();

  /// Writes remaining records and `app.stopping` as the final record (call before exit).
  static Future<void> shutdown({String reason = 'exit'}) async {
    final t = _instance;
    if (t == null) return;
    t._pipeline.shutdown(t._record(Kind.log, Level.info, 'app.stopping', 'idr_telemetry')..attrs['reason'] = reason);
    if (t._errorPort != null) {
      Isolate.current.removeErrorListener(t._errorPort!.sendPort);
      t._errorPort!.close();
    }
    t._linkPort?.close();
    _instance = null;
  }

  String? get logRoot => config.logRoot;
  Directory? get crashDir => _crashDir;

  Record _record(Kind kind, Level level, String event, String component) => Record(kind, level, event)
    ..ts = formatTs(DateTime.now())
    ..service = config.service
    ..serviceVersion = config.serviceVersion
    ..appSessionId = appSessionId
    ..component = component;

  Route _route(String component, Level level) {
    final out = level >= _directives.levelFor(component);
    return Route(
      toRing: level >= Level.debug && _pipeline.limits.ringBytes > 0,
      toFile: out,
      toStderr: config.stderrLevel != null && level >= config.stderrLevel!,
    );
  }

  bool _wants(String component, Level level) {
    if (_worker != null) return level >= _directives.levelFor(component) || level >= Level.debug;
    final r = _route(component, level);
    return r.toRing || r.toFile || r.toStderr;
  }

  void _emit(Record r) {
    if (_worker != null) {
      _worker!.port.send({'line': r.toLine()});
      return;
    }
    _pipeline.submit(r, _route(r.component, r.level));
  }

  /// Uncaught error: synchronous crash record, FATAL log record, best-effort sync.
  void recordCrash(Object error, StackTrace stack, {String source = 'zone'}) {
    final span = currentSpan;
    final r = _record(Kind.crash, Level.fatal, 'app.crashed', 'idr_telemetry')
      ..error = ErrorInfo(error.runtimeType.toString().toLowerCase().replaceAll(RegExp('[^a-z0-9_]'), '_'),
          message: error.toString(), stack: stack.toString())
      ..attrs.addAll({
        'panic.message': error.toString(),
        'thread': '${Isolate.current.debugName ?? 'main'}/$source',
        'open_operations': [if (span != null && span is! _RemoteParent) '${span.name} ${span.traceId} ${span.spanId}'],
        'ring': _pipeline.ringTail(200),
      });
    if (span != null) {
      r
        ..traceId = span.traceId
        ..spanId = span.spanId;
    }
    _corr.applyTo(r);
    r.redactInPlace();
    final dir = _crashDir;
    if (dir != null) {
      try {
        dir.createSync(recursive: true);
        final name = '${appSessionId}_${_fileStart(DateTime.now().toUtc())}.crash.json';
        File('${dir.path}${Platform.pathSeparator}$name').writeAsStringSync(r.toCappedLine(maxCrashBytes), flush: true);
      } on FileSystemException {
        // best effort
      }
    }
    final log = r
      ..kind = Kind.log
      ..attrs.remove('ring');
    _emit(log);
    unawaited(_pipeline.sync());
  }
}

class TelemetryLink {
  TelemetryLink(this.port, this.appSessionId, this.service, this.serviceVersion, this.filter);
  final SendPort port;
  final String appSessionId;
  final String service;
  final String serviceVersion;
  final String filter;
}

class _WorkerLink {
  _WorkerLink(this.port);
  final SendPort port;
}

String _fileStart(DateTime u) => '${formatTs(u).substring(0, 19).replaceAll(':', '-')}Z';

Future<void> _diskGuard(Telemetry t, Directory dir) async {
  final free = await freeBytes(dir);
  if (free != null && free < minFreeBytes && t._pipeline.file != null) {
    await t._pipeline.sync();
    t._pipeline.file?.close();
    t._pipeline.file = null;
    t._emit(t._record(Kind.log, Level.warn, 'diag.sink.unavailable', 'idr_telemetry')
      ..error = ErrorInfo('low_disk')
      ..attrs['reason'] = 'low_disk');
  }
}

/// Runs [body] so that uncaught errors become crash records (04 §3.1).
R? runGuarded<R>(R Function() body) => runZonedGuarded(body, (e, st) {
      final t = Telemetry.instance;
      if (t != null) {
        t.recordCrash(e, st);
      } else {
        stderr.writeln('uncaught: $e'); // idr-lint: allow (telemetry not initialized: last resort)
      }
    });

/// A logger for one component (`idr_source.connect`). Cheap to create; keep one per file.
class IdrLog {
  const IdrLog(this.component);
  final String component;

  void trace(String event, {Map<String, Object?> Function()? lazy, String? msg}) =>
      _log(Level.trace, event, msg: msg, lazy: lazy);
  void debug(String event, {Map<String, Object?>? attrs, Map<String, Object?> Function()? lazy, String? msg}) =>
      _log(Level.debug, event, attrs: attrs, lazy: lazy, msg: msg);
  void info(String event, {Map<String, Object?>? attrs, String? msg}) => _log(Level.info, event, attrs: attrs, msg: msg);
  void warn(String event, {required String errorType, Map<String, Object?>? attrs, String? msg, Object? error, StackTrace? stack}) =>
      _log(Level.warn, event, attrs: attrs, msg: msg, errorType: errorType, error: error, stack: stack);
  void error(String event, {required String errorType, Map<String, Object?>? attrs, String? msg, Object? error, StackTrace? stack}) =>
      _log(Level.error, event, attrs: attrs, msg: msg, errorType: errorType, error: error, stack: stack);

  void _log(Level level, String event,
      {Map<String, Object?>? attrs,
      Map<String, Object?> Function()? lazy,
      String? msg,
      String? errorType,
      Object? error,
      StackTrace? stack}) {
    final t = Telemetry.instance;
    if (t == null || !t._wants(component, level)) return; // gate before building attrs
    final r = t._record(Kind.log, level, event, component)..msg = msg;
    final span = currentSpan;
    if (span != null) {
      r
        ..traceId = span.traceId
        ..spanId = span.spanId;
    }
    final all = {...?attrs, ...?lazy?.call()};
    _corr.merge(all).applyTo(r);
    all.forEach((k, v) {
      if (!_correlationKeys.contains(k)) r.attrs[k] = _checkAttr(k, v);
    });
    if (errorType != null || level >= Level.warn) {
      r.error = ErrorInfo(errorType ?? 'unspecified', message: error?.toString(), stack: level >= Level.error ? stack?.toString() : null);
    }
    t._emit(r);
  }

  /// Runs [body] inside a span. Correlation IDs in [attrs] (`session_id`, …) are inherited by
  /// everything inside. [remoteParent] parents from another process; [persistStart] writes a
  /// `<name>.started` record (03 §3.2). An exception marks the span failed and is rethrown.
  Future<T> span<T>(String name, Future<T> Function(Span s) body,
          {Map<String, Object?>? attrs,
          TraceContext? remoteParent,
          List<TraceContext> links = const [],
          bool newTrace = false,
          bool persistStart = false,
          Level level = Level.info}) =>
      _run(name, attrs, remoteParent, links, newTrace, persistStart, level, (s) => body(s));

  T spanSync<T>(String name, T Function(Span s) body,
          {Map<String, Object?>? attrs, TraceContext? remoteParent, bool persistStart = false, Level level = Level.info}) =>
      _runSync(name, attrs, remoteParent, persistStart, level, body);

  Span _open(String name, Map<String, Object?>? attrs, TraceContext? remoteParent, List<TraceContext> links, bool newTrace,
      bool persistStart, Level level) {
    final parent = newTrace ? null : currentSpan;
    final traceId = remoteParent?.traceId ?? parent?.traceId ?? newTraceIdHex();
    final parentId = remoteParent?.spanId ?? parent?.spanId;
    final corr = _corr.merge(attrs ?? const {});
    final s = Span._(name, component, level, traceId, newSpanIdHex(), parentId,
        [for (final l in links) (l.traceId, l.spanId)], corr);
    attrs?.forEach((k, v) {
      if (!_correlationKeys.contains(k)) s.attrs[k] = _checkAttr(k, v);
    });
    final t = Telemetry.instance;
    if (persistStart && t != null) {
      final r = t._record(Kind.log, Level.info, '$name.started', component)
        ..traceId = s.traceId
        ..spanId = s.spanId
        ..parentSpanId = s.parentSpanId
        ..attrs.addAll(s.attrs);
      corr.applyTo(r);
      t._emit(r);
    }
    return s;
  }

  void _close(Span s) {
    final t = Telemetry.instance;
    if (t == null) return;
    final failed = s._error != null;
    final level = failed && s.level < Level.warn ? Level.warn : s.level;
    if (!t._wants(component, level)) return;
    final r = t._record(Kind.span, level, s.name, component)
      ..traceId = s.traceId
      ..spanId = s.spanId
      ..parentSpanId = s.parentSpanId
      ..links = s.links
      ..startTs = formatTs(s._startWall)
      ..durationMs = (s._sw.elapsedMicroseconds / 10).round() / 100
      ..status = failed ? 'error' : 'ok'
      ..error = s._error
      ..attrs.addAll(s.attrs);
    s._corr.applyTo(r);
    t._emit(r);
  }

  Future<T> _run<T>(String name, Map<String, Object?>? attrs, TraceContext? remote, List<TraceContext> links, bool newTrace,
      bool persistStart, Level level, Future<T> Function(Span) body) async {
    final s = _open(name, attrs, remote, links, newTrace, persistStart, level);
    try {
      return await runZoned(() => body(s), zoneValues: {_spanKey: s, _corrKey: s._corr});
    } catch (e) {
      s._error ??= ErrorInfo('exception', message: e.toString());
      rethrow;
    } finally {
      _close(s);
    }
  }

  T _runSync<T>(String name, Map<String, Object?>? attrs, TraceContext? remote, bool persistStart, Level level, T Function(Span) body) {
    final s = _open(name, attrs, remote, const [], false, persistStart, level);
    try {
      return runZoned(() => body(s), zoneValues: {_spanKey: s, _corrKey: s._corr});
    } catch (e) {
      s._error ??= ErrorInfo('exception', message: e.toString());
      rethrow;
    } finally {
      _close(s);
    }
  }
}

/// Rebuilds a record from its JSON line (worker forwarding, bundle re-redaction).
Record recordFromJson(Map<String, Object?> j) {
  ErrorInfo? err(Object? e) {
    if (e is! Map<String, Object?>) return null;
    return ErrorInfo(e['type'] as String? ?? 'unspecified',
        message: e['message'] as String?, code: e['code'] as int?, stack: e['stack'] as String?, cause: err(e['cause']));
  }

  final r = Record(Kind.values.byName(j['kind'] as String? ?? 'log'), Level.parse(j['level'] as String? ?? 'info') ?? Level.info,
      j['event'] as String? ?? 'diag.log.unstructured')
    ..ts = j['ts'] as String? ?? formatTs(DateTime.now())
    ..msg = j['msg'] as String?
    ..service = j['service'] as String? ?? ''
    ..serviceVersion = j['service_version'] as String? ?? ''
    ..component = j['component'] as String? ?? ''
    ..appSessionId = j['app_session_id'] as String? ?? ''
    ..traceId = j['trace_id'] as String?
    ..spanId = j['span_id'] as String?
    ..parentSpanId = j['parent_span_id'] as String?
    ..links = [for (final l in (j['links'] as List? ?? const [])) ((l as Map)['trace_id'] as String, l['span_id'] as String)]
    ..startTs = j['start_ts'] as String?
    ..durationMs = (j['duration_ms'] as num?)?.toDouble()
    ..status = j['status'] as String?
    ..sessionId = j['session_id'] as String?
    ..connectionId = j['connection_id'] as String?
    ..transferId = j['transfer_id'] as String?
    ..operationId = j['operation_id'] as String?
    ..reportId = j['report_id'] as String?
    ..error = err(j['error']);
  (j['attrs'] as Map<String, Object?>? ?? const {}).forEach((k, v) {
    r.attrs[k] = v is List ? [for (final x in v) '$x'] : (v ?? 'null');
  });
  return r;
}
