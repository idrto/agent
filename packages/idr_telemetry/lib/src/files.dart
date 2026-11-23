// Local files: runs, lifetime locks, rotation, ownership-safe retention, per-run exit
// recovery and the disk guard (04 §1.3, §3.3). Mirrors crates/idr-telemetry files.rs.
//
// Each producer manages only runs of its own producer type (`jsonl` here, `rust.jsonl` in
// Rust): lock primitives differ between languages on POSIX (fcntl vs flock), so ownership
// is only ever tested by the same implementation that takes it.

import 'dart:convert';
import 'dart:io';

import 'ids.dart';

const int segmentBytes = 10 * 1024 * 1024;
const int defaultCapBytes = 100 * 1024 * 1024;
const Duration defaultMaxAge = Duration(days: 7);
const int minFreeBytes = 500 * 1024 * 1024;
const int _startLen = 20; // 2026-11-21T10-00-00Z

class RunKey {
  const RunKey(this.start, this.appSessionId, this.producer);
  final String start;
  final String appSessionId;
  final String producer;

  String get _base => '${start}_$appSessionId';
  String get lockName => '$_base.$producer.lock';
  String get endedName => '$_base.$producer.ended';
  String segmentName(int n) => '${_base}_${n.toString().padLeft(3, '0')}.$producer';

  @override
  bool operator ==(Object other) =>
      other is RunKey && other.start == start && other.appSessionId == appSessionId && other.producer == producer;
  @override
  int get hashCode => Object.hash(start, appSessionId, producer);
  @override
  String toString() => '$_base.$producer';
}

enum RunState { active, ended, unknown }

enum Exit { clean, unclean, crash }

class _RunFiles {
  final Map<int, File> segments = {};
  bool hasLock = false;
  bool hasEnded = false;
  int get highest => segments.keys.reduce((a, b) => a > b ? a : b);
}

/// Returns (key, kind, segmentNumber) for a run file name, or null.
(RunKey, String, int)? _parse(String name) {
  if (name.length < _startLen + 1 + 36 + 2 || name[_startLen] != '_') return null;
  final start = name.substring(0, _startLen);
  final id = name.substring(_startLen + 1, _startLen + 37);
  if (!isUuid(id)) return null;
  final rest = name.substring(_startLen + 37);
  if (rest.startsWith('.')) {
    final r = rest.substring(1);
    if (r.endsWith('.lock')) return (RunKey(start, id, r.substring(0, r.length - 5)), 'lock', -1);
    if (r.endsWith('.ended')) return (RunKey(start, id, r.substring(0, r.length - 6)), 'ended', -1);
    return null;
  }
  if (!rest.startsWith('_')) return null;
  final dot = rest.indexOf('.');
  if (dot < 0) return null;
  final n = int.tryParse(rest.substring(1, dot));
  if (n == null) return null;
  return (RunKey(start, id, rest.substring(dot + 1)), 'segment', n);
}

Map<RunKey, _RunFiles> _scan(Directory dir) {
  final runs = <RunKey, _RunFiles>{};
  if (!dir.existsSync()) return runs;
  for (final e in dir.listSync()) {
    if (e is! File) continue;
    final p = _parse(e.uri.pathSegments.last);
    if (p == null) continue;
    final files = runs.putIfAbsent(p.$1, _RunFiles.new);
    switch (p.$2) {
      case 'segment':
        files.segments[p.$3] = e;
      case 'lock':
        files.hasLock = true;
      case 'ended':
        files.hasEnded = true;
    }
  }
  return runs;
}

// Lock contention errno/Win32 codes: EAGAIN (Linux 11, macOS 35), EACCES 13, ERROR_LOCK_VIOLATION 33.
const _busyCodes = {11, 35, 13, 33};

/// Ownership by lock test (04 §1.3). Never inferred from modification time.
RunState runState(Directory dir, RunKey key) {
  final f = File('${dir.path}${Platform.pathSeparator}${key.lockName}');
  if (!f.existsSync()) return RunState.unknown;
  RandomAccessFile? raf;
  try {
    raf = f.openSync(mode: FileMode.append);
    raf.lockSync(FileLock.exclusive);
    raf.unlockSync();
    return RunState.ended;
  } on FileSystemException catch (e) {
    if (raf != null && _busyCodes.contains(e.osError?.errorCode)) return RunState.active;
    return RunState.unknown;
  } finally {
    raf?.closeSync();
  }
}

/// The active writer of one run. Holds the run lock for its whole lifetime.
class FileSink {
  FileSink._(this.dir, this.key, this._lock, this._out);

  final Directory dir;
  final RunKey key;
  final RandomAccessFile _lock;
  RandomAccessFile _out;
  int _seg = 0;
  int _size = 0;
  final StringBuffer _buf = StringBuffer();
  int _bufBytes = 0;
  int capBytes = defaultCapBytes;
  Duration maxAge = defaultMaxAge;

  static FileSink open(Directory dir, String start, String appSessionId, String producer) {
    dir.createSync(recursive: true);
    final key = RunKey(start, appSessionId, producer);
    final lock = File(_join(dir, key.lockName)).openSync(mode: FileMode.append);
    try {
      lock.lockSync(FileLock.exclusive);
    } on FileSystemException {
      lock.closeSync();
      rethrow;
    }
    final out = File(_join(dir, key.segmentName(0))).openSync(mode: FileMode.append);
    return FileSink._(dir, key, lock, out);
  }

  /// Buffers one line; rotates first when the segment would exceed 10 MiB.
  /// Returns true when a rotation happened (caller runs retention).
  bool writeLine(String line) {
    final bytes = utf8.encode(line).length + 1;
    var rotated = false;
    if (_size > 0 && _size + bytes > segmentBytes) {
      flush();
      _out.closeSync();
      _seg++;
      _out = File(_join(dir, key.segmentName(_seg))).openSync(mode: FileMode.append);
      _size = 0;
      rotated = true;
    }
    _buf
      ..write(line)
      ..write('\n');
    _bufBytes += bytes;
    _size += bytes;
    if (_bufBytes >= 64 * 1024) flush();
    return rotated;
  }

  // ponytail: synchronous writes of <=64 KiB batches on the writer timer; move to an
  // isolate-backed writer if UI jank is ever measured.
  void flush() {
    if (_bufBytes == 0) return;
    _out.writeStringSync(_buf.toString());
    _buf.clear();
    _bufBytes = 0;
  }

  void sync() {
    flush();
    _out.flushSync();
  }

  void close() {
    sync();
    _out.closeSync();
    _lock.unlockSync();
    _lock.closeSync();
  }

  CleanupReport cleanup() => cleanupRuns(dir, key.producer, own: key, capBytes: capBytes, maxAge: maxAge);
}

String _join(Directory d, String name) => '${d.path}${Platform.pathSeparator}$name';

class CleanupReport {
  final List<String> deleted = [];
  final List<RunKey> unknownRuns = [];
}

/// Retention over provably-closed segments of [producer] runs only (04 §1.3).
CleanupReport cleanupRuns(Directory dir, String producer,
    {RunKey? own, int capBytes = defaultCapBytes, Duration maxAge = defaultMaxAge, DateTime? now}) {
  final report = CleanupReport();
  final when = now ?? DateTime.now();
  final runs = _scan(dir);
  final deletable = <(DateTime, File, int)>[];
  final ended = <RunKey>[];
  runs.forEach((key, files) {
    if (key.producer != producer || files.segments.isEmpty) return;
    final state = key == own ? RunState.active : runState(dir, key);
    final highest = files.highest;
    switch (state) {
      case RunState.unknown:
        report.unknownRuns.add(key);
      case RunState.ended:
        if (!files.hasEnded) return; // recovery has not classified it yet
        ended.add(key);
        for (final f in files.segments.values) {
          deletable.add((f.lastModifiedSync(), f, f.lengthSync()));
        }
      case RunState.active:
        files.segments.forEach((n, f) {
          if (n != highest) deletable.add((f.lastModifiedSync(), f, f.lengthSync()));
        });
    }
  });
  deletable.sort((a, b) => a.$1.compareTo(b.$1));
  var total = deletable.fold<int>(0, (s, d) => s + d.$3);
  for (final (mtime, file, size) in deletable) {
    final tooOld = when.difference(mtime) > maxAge;
    if (tooOld || total > capBytes) {
      try {
        file.deleteSync();
        total -= size;
        report.deleted.add(file.path);
      } on FileSystemException {
        // still open somewhere: keep it
      }
    }
  }
  final remaining = _scan(dir);
  for (final key in ended) {
    if (remaining[key]?.segments.isEmpty ?? true) {
      for (final n in [key.lockName, key.endedName]) {
        try {
          File(_join(dir, n)).deleteSync();
        } on FileSystemException {
          // ignore
        }
      }
    }
  }
  return report;
}

class Recovered {
  Recovered(this.appSessionId, this.exit, this.openOperations);
  final String appSessionId;
  final Exit exit;
  final List<String> openOperations;
}

/// Per-run exit recovery (04 §3.3). Each ended, unclaimed run of [producer] is classified
/// and claimed exactly once via exclusive create of its `.ended` sidecar. Returns only the
/// crash/unclean runs claimed by this call.
List<Recovered> recoverRuns(Directory dir, Directory crashDir, String producer, {RunKey? own}) {
  final out = <Recovered>[];
  _scan(dir).forEach((key, files) {
    if (key.producer != producer || files.hasEnded || files.segments.isEmpty || key == own) return;
    if (runState(dir, key) != RunState.ended) return; // active or unknown: nothing claimed
    final last = files.segments[files.highest]!;
    final crash = _hasCrashRecord(crashDir, key.appSessionId);
    final exit = crash ? Exit.crash : (_lastEvent(last) == 'app.stopping' ? Exit.clean : Exit.unclean);
    try {
      File(_join(dir, key.endedName))
        ..createSync(exclusive: true)
        ..writeAsStringSync('{"exit":"${exit.name}"}\n');
    } on FileSystemException {
      return; // another process claimed it
    }
    if (exit != Exit.clean) out.add(Recovered(key.appSessionId, exit, _openOperations(last)));
  });
  return out;
}

bool _hasCrashRecord(Directory crashDir, String appSessionId) {
  if (!crashDir.existsSync()) return false;
  return crashDir.listSync().any((e) {
    final n = e.uri.pathSegments.last;
    return n.startsWith(appSessionId) && n.endsWith('.crash.json');
  });
}

Iterable<Map<String, Object?>> _records(String text) sync* {
  for (final l in const LineSplitter().convert(text)) {
    try {
      final v = jsonDecode(l);
      if (v is Map<String, Object?>) yield v;
    } on FormatException {
      // partial last line after a crash
    }
  }
}

String? _lastEvent(File f) {
  final len = f.lengthSync();
  final raf = f.openSync();
  try {
    raf.setPositionSync(len > 65536 ? len - 65536 : 0);
    final text = utf8.decode(raf.readSync(65536), allowMalformed: true);
    final recs = _records(text).toList();
    return recs.isEmpty ? null : recs.last['event'] as String?;
  } finally {
    raf.closeSync();
  }
}

/// `*.started` records without a matching span end, within the last segment (best effort).
List<String> _openOperations(File f) {
  final open = <(String, String)>[];
  for (final r in _records(f.readAsStringSync())) {
    final span = r['span_id'] as String? ?? '';
    final event = r['event'] as String? ?? '';
    if (r['kind'] == 'log' && event.endsWith('.started')) {
      open.add((span, event.substring(0, event.length - '.started'.length)));
    } else if (r['kind'] == 'span') {
      open.removeWhere((o) => o.$1 == span);
    }
  }
  return [for (final o in open) o.$2];
}

/// Free bytes on the volume holding [dir]; null when unknown. Asynchronous and off the
/// startup path: the sink starts enabled and is disabled if the answer is too low.
// ponytail: shells out (pure Dart has no statvfs); move to dart:ffi if it shows up in profiles.
Future<int?> freeBytes(Directory dir) async {
  try {
    if (Platform.isWindows) {
      final drive = dir.absolute.path[0];
      final r = await Process.run('powershell', ['-NoProfile', '-Command', "(Get-PSDrive -Name '$drive').Free"]);
      return int.tryParse((r.stdout as String).trim());
    }
    final r = await Process.run('df', ['-Pk', dir.path]);
    final cols = (r.stdout as String).trim().split('\n').last.split(RegExp(r'\s+'));
    final kb = cols.length > 3 ? int.tryParse(cols[3]) : null;
    return kb == null ? null : kb * 1024;
  } on Object {
    return null;
  }
}
