// Producer → writer pipeline: byte-capped queue (drop incoming), byte-capped flight recorder
// ring (evict oldest), writer-controlled drain with persisted flags, watermark split, and
// active/pending follow-up drains (04 §2.1, §6). Mirrors crates/idr-telemetry pipeline.rs.
// Single isolate: no locks; the writer runs on a timer and never blocks the caller.

import 'dart:async';
import 'dart:collection';
import 'dart:io';

import 'files.dart';
import 'record.dart';

enum StdoutFormat { json, pretty, off }

/// `IDR_LOG` directives: `info,idr_source.connect=debug` (component prefixes).
class Directives {
  Directives._(this.defaultLevel, this.targets);

  final Level defaultLevel;
  final List<(String, Level)> targets;

  factory Directives.parse(String s) {
    var def = Level.info;
    final targets = <(String, Level)>[];
    for (final part in s.split(',').map((p) => p.trim()).where((p) => p.isNotEmpty)) {
      final eq = part.indexOf('=');
      if (eq < 0) {
        def = Level.parse(part) ?? def;
      } else {
        final l = Level.parse(part.substring(eq + 1).trim());
        if (l != null) targets.add((part.substring(0, eq).trim().replaceAll('::', '.'), l));
      }
    }
    targets.sort((a, b) => b.$1.length.compareTo(a.$1.length)); // longest prefix first
    return Directives._(def, targets);
  }

  Level levelFor(String component) {
    for (final (t, l) in targets) {
      if (component.startsWith(t)) return l;
    }
    return defaultLevel;
  }
}

class Route {
  const Route({required this.toRing, required this.toFile, required this.toStderr});
  final bool toRing;
  final bool toFile;
  final bool toStderr;
}

/// A finished record shared by the ring and the queue. [persisted] is set only by the
/// writer after the line went to the file — never inferred from severity.
class Entry {
  Entry(this.seq, this.level, this.traceId, this.sessionId, this.atMicros, this.line, this.pretty, this.route);
  final int seq;
  final Level level;
  final String? traceId;
  final String? sessionId;
  final int atMicros;
  final String line;
  final String? pretty;
  final Route route;
  bool persisted = false;
  int get bytes => line.length + 64;
}

class Limits {
  const Limits({
    this.queueBytes = 1024 * 1024,
    this.ringBytes = 3 * 1024 * 1024,
    this.drainPacing = const Duration(seconds: 1),
    this.triggerDebounce = const Duration(seconds: 30),
    this.drainWindow = const Duration(seconds: 60),
    this.batchDelay = const Duration(milliseconds: 50),
  });
  final int queueBytes;
  final int ringBytes;
  final Duration drainPacing;
  final Duration triggerDebounce;
  final Duration drainWindow;
  final Duration batchDelay;
}

class _FlushReq {
  int watermark = -1;
  final Set<String> traces = {};
  final Set<String> sessions = {};
  final List<Entry> triggers = [];
  final List<Completer<void>> done = [];
}

sealed class _Msg {}

class _RecordMsg extends _Msg {
  _RecordMsg(this.entry);
  final Entry entry;
  int dropped = 0;
}

class _FlushToken extends _Msg {}

class _SyncMsg extends _Msg {
  final Completer<void> done = Completer<void>();
}

typedef MakeRecord = Record Function(Level level, String event);

class Pipeline {
  Pipeline({this.limits = const Limits(), this.stdoutFormat = StdoutFormat.off, this.file, IOSink? stderrSink, required this.makeRecord})
      : _stderr = stderrSink;

  final Limits limits;
  final StdoutFormat stdoutFormat;
  FileSink? file;
  final IOSink? _stderr;
  final MakeRecord makeRecord;

  final Stopwatch _clock = Stopwatch()..start();
  int _seq = 0;
  final ListQueue<Entry> _ring = ListQueue();
  int _ringBytes = 0;
  final ListQueue<_Msg> _queue = ListQueue();
  int _queueBytes = 0;
  int _dropped = 0;
  int _droppedBytes = 0;
  int _ringEvictedUnflushed = 0;
  _FlushReq? _pending;
  final Map<String, int> _lastTrigger = {};
  bool _closed = false;
  Timer? _timer;
  int? _lastDrainEndMicros;
  int? _lastDroppedReport;
  bool _deferred = false;

  (int, int) get byteUsage => (_queueBytes, _ringBytes);

  /// Redacts, caps, sequences and routes a record. Never blocks on I/O.
  void submit(Record rec, Route route) {
    if (_closed || !(route.toRing || route.toFile || route.toStderr)) return;
    rec.redactInPlace();
    rec.seq = _seq++;
    final line = rec.toCappedLine();
    final e = Entry(rec.seq, rec.level, rec.traceId, rec.sessionId, _clock.elapsedMicroseconds, line,
        route.toStderr ? prettyLine(rec) : null, route);
    if (route.toRing && e.level >= Level.debug && limits.ringBytes > 0) {
      _ring.addLast(e);
      _ringBytes += e.bytes;
      while (_ringBytes > limits.ringBytes && _ring.isNotEmpty) {
        final old = _ring.removeFirst();
        _ringBytes -= old.bytes;
        final wm = _pending?.watermark;
        if (wm != null && old.seq <= wm && !old.persisted) _ringEvictedUnflushed++;
      }
    }
    if (route.toFile || route.toStderr) {
      if (_queueBytes + e.bytes <= limits.queueBytes) {
        _queueBytes += e.bytes;
        _queue.addLast(_RecordMsg(e));
      } else {
        _dropped++; // drop incoming (04 §6); stays persisted=false for a drain
        _droppedBytes += e.bytes;
      }
    }
    final trigger = rec.level >= Level.error || rec.event.endsWith('.stalled') || rec.event.endsWith('.timed_out');
    if (trigger && rec.kind == Kind.log) _trigger(e, null);
    _schedule();
  }

  void _trigger(Entry? t, Completer<void>? done) {
    if (t != null && done == null && t.traceId != null) {
      final now = _clock.elapsedMicroseconds;
      final last = _lastTrigger[t.traceId!];
      if (last != null && now - last < limits.triggerDebounce.inMicroseconds) return;
      _lastTrigger[t.traceId!] = now;
    }
    final isNew = _pending == null;
    final req = _pending ??= _FlushReq();
    if (_seq - 1 > req.watermark) req.watermark = _seq - 1;
    if (t != null) {
      if (t.traceId != null) req.traces.add(t.traceId!);
      if (t.sessionId != null) req.sessions.add(t.sessionId!);
      req.triggers.add(t);
    }
    if (done != null) req.done.add(done);
    if (isNew) _queue.addLast(_FlushToken()); // control: exempt from the byte cap
  }

  /// Drain now and wait until it is written and synced (bundle builds).
  Future<void> flushAndWait() {
    if (_closed) return Future.value();
    final c = Completer<void>();
    _trigger(null, c);
    _schedule(immediate: true);
    return c.future;
  }

  /// Completes when everything submitted so far has been handled by the writer.
  Future<void> sync() {
    if (_closed) return Future.value();
    final m = _SyncMsg();
    _queue.addLast(m);
    _schedule(immediate: true);
    return m.done.future;
  }

  /// Writes remaining records, then [stopping] as the final record, then closes the file.
  void shutdown(Record stopping) {
    if (_closed) return;
    stopping.seq = _seq++;
    _closed = true;
    _timer?.cancel();
    _pump();
    stopping.redactInPlace();
    final line = stopping.toCappedLine();
    file?.writeLine(line);
    if (stdoutFormat != StdoutFormat.off) stdout.writeln(stdoutFormat == StdoutFormat.pretty ? prettyLine(stopping) : line);
    file?.close();
    file = null;
  }

  List<String> ringTail(int n) => _ring.skip(_ring.length > n ? _ring.length - n : 0).map((e) => e.line).toList();

  void _schedule({bool immediate = false}) {
    if (_closed) return;
    if (immediate) {
      _timer?.cancel();
      _timer = Timer(Duration.zero, _tick);
    } else {
      _timer ??= Timer(limits.batchDelay, _tick);
    }
  }

  void _tick() {
    _timer = null;
    _pump();
  }

  int _pacingLeftMicros() {
    final end = _lastDrainEndMicros;
    if (end == null) return 0;
    final left = limits.drainPacing.inMicroseconds - (_clock.elapsedMicroseconds - end);
    return left > 0 ? left : 0;
  }

  void _pump() {
    if (_deferred && _pacingLeftMicros() == 0) {
      _deferred = false;
      _drain();
    }
    while (_queue.isNotEmpty) {
      final m = _queue.removeFirst();
      switch (m) {
        case _RecordMsg():
          _queueBytes -= m.entry.bytes;
          m.dropped = _dropped;
          _dropped = 0;
          if (m.dropped > 0) _reportDropped(m.dropped);
          _write(m.entry, m.dropped, flushed: false);
        case _FlushToken():
          _drain();
        case _SyncMsg():
          file?.sync();
          m.done.complete();
      }
    }
    file?.flush();
    if (_deferred && !_closed) {
      _timer?.cancel();
      _timer = Timer(Duration(microseconds: _pacingLeftMicros()), _tick);
    }
  }

  void _reportDropped(int count) {
    final now = _clock.elapsedMicroseconds;
    if (_lastDroppedReport != null && now - _lastDroppedReport! < 10 * 1000000) return;
    _lastDroppedReport = now;
    final r = makeRecord(Level.warn, 'diag.records.dropped')
      ..attrs.addAll({'count': count, 'bytes': _droppedBytes, 'reason': 'queue_full'});
    _droppedBytes = 0;
    _writeDirect(r);
  }

  void _writeDirect(Record r) {
    r.seq = _seq++;
    r.redactInPlace();
    final line = r.toCappedLine();
    if (file?.writeLine(line) ?? false) file!.cleanup();
    _stderr?.writeln(prettyLine(r));
  }

  void _write(Entry e, int dropped, {required bool flushed}) {
    if ((e.route.toFile || flushed) && file != null) {
      final rotated = file!.writeLine(withTail(e.line, dropped, flushed));
      e.persisted = true;
      if (rotated) file!.cleanup();
    }
    if (e.route.toStderr && !flushed && e.pretty != null) _stderr?.writeln(e.pretty);
    if (stdoutFormat != StdoutFormat.off && e.route.toFile && !flushed) {
      stdout.writeln(stdoutFormat == StdoutFormat.pretty ? (e.pretty ?? e.line) : withTail(e.line, dropped, false));
    }
  }

  /// The drain (04 §2.1): take the pending request, write queued records up to the
  /// watermark, split the ring at the watermark, write unpersisted records, free.
  void _drain() {
    if (_pacingLeftMicros() > 0) {
      _deferred = true; // the request stays pending; later triggers merge into it
      return;
    }
    final req = _pending;
    if (req == null) return;
    _pending = null;
    // Everything enqueued up to the watermark first (normal path), incl. Sync messages.
    while (_queue.isNotEmpty) {
      final m = _queue.first;
      if (m is _RecordMsg && m.entry.seq <= req.watermark) {
        _queue.removeFirst();
        _queueBytes -= m.entry.bytes;
        final d = _dropped;
        _dropped = 0;
        _write(m.entry, d, flushed: false);
      } else if (m is _SyncMsg) {
        _queue.removeFirst();
        file?.sync();
        m.done.complete();
      } else {
        break;
      }
    }
    // Split: detach only seq <= watermark; later records stay in the live ring.
    final snapshot = <Entry>[];
    while (_ring.isNotEmpty && _ring.first.seq <= req.watermark) {
      final e = _ring.removeFirst();
      _ringBytes -= e.bytes;
      snapshot.add(e);
    }
    if (_ringEvictedUnflushed > 0) {
      final r = makeRecord(Level.warn, 'diag.records.dropped')
        ..attrs.addAll({'count': _ringEvictedUnflushed, 'bytes': 0, 'reason': 'ring_evicted_unflushed'});
      _ringEvictedUnflushed = 0;
      _writeDirect(r);
    }
    bool inScope(Entry e) =>
        (e.traceId != null && req.traces.contains(e.traceId)) || (e.sessionId != null && req.sessions.contains(e.sessionId));
    final windowStart = _clock.elapsedMicroseconds - limits.drainWindow.inMicroseconds;
    final chosen = <Entry>[for (final e in snapshot) if (!e.persisted && inScope(e)) e];
    for (final t in req.triggers) {
      if (!t.persisted && !chosen.contains(t)) chosen.add(t);
    }
    chosen.sort((a, b) => a.seq.compareTo(b.seq));
    final rest = [
      for (final e in snapshot)
        if (!e.persisted && !inScope(e) && e.atMicros >= windowStart && !chosen.contains(e)) e
    ];
    for (final e in [...chosen, ...rest]) {
      _write(e, 0, flushed: true);
    }
    file?.sync();
    _lastDrainEndMicros = _clock.elapsedMicroseconds;
    for (final d in req.done) {
      d.complete();
    }
  }
}

/// Human-readable single line for a terminal.
String prettyLine(Record r) {
  final sb = StringBuffer('${r.ts.length >= 23 ? r.ts.substring(11, 23) : r.ts} ${r.level.label.padRight(5)} ${r.event}');
  if (r.durationMs != null) sb.write(" duration_ms=${r.durationMs!.round()}");
  if (r.msg != null) sb.write(' — ${r.msg}');
  if (r.error != null) {
    sb.write(' error.type=${r.error!.type}');
    if (r.error!.message != null) sb.write(' error="${r.error!.message}"');
  }
  r.attrs.forEach((k, v) => sb.write(v is String ? ' $k="$v"' : ' $k=$v'));
  return sb.toString();
}
