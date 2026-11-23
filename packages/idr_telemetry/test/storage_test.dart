import 'dart:io';

import 'package:idr_telemetry/idr_telemetry.dart';
import 'package:test/test.dart';

import 'support.dart';

const start = '2026-11-01T10-00-00Z';

void main() {
  late Directory dir;
  File f(String name) => File('${dir.path}${Platform.pathSeparator}$name');
  String rec(String event) => '{"kind":"log","event":"$event","span_id":"a1b2c3d4e5f60718"}\n';
  const old = Duration(days: 30);

  setUp(() => dir = Directory.systemTemp.createTempSync('idr_store_'));
  tearDown(() => dir.deleteSync(recursive: true));

  test('retention never deletes an idle live owner\'s open segment', () async {
    final id = newId();
    final key = RunKey(start, id, 'jsonl');
    f(key.lockName).createSync();
    final release = await holdLockInOtherProcess(f(key.lockName).path); // a live, idle process
    try {
      for (final n in [0, 1, 2]) {
        touch(f(key.segmentName(n)), '{}\n', age: old);
      }
      expect(runState(dir, key), RunState.active);
      final report = cleanupRuns(dir, 'jsonl', capBytes: 0, maxAge: const Duration(seconds: 1));
      expect(report.deleted.length, 2);
      expect(f(key.segmentName(2)).existsSync(), isTrue, reason: 'idle owner keeps its open segment');
    } finally {
      await release();
    }
  });

  test('unknown ownership (no lock file) deletes nothing and is reported', () {
    final id = newId();
    touch(f(RunKey(start, id, 'jsonl').segmentName(0)), '{}\n', age: old);
    final report = cleanupRuns(dir, 'jsonl', capBytes: 0, maxAge: const Duration(seconds: 1));
    expect(report.deleted, isEmpty);
    expect(report.unknownRuns, hasLength(1));
  });

  test('other producers\' runs are never touched', () {
    final id = newId();
    final key = RunKey(start, id, 'rust.jsonl');
    f(key.lockName).createSync();
    touch(f(key.segmentName(0)), '{}\n', age: old);
    f(key.endedName).writeAsStringSync('{"exit":"clean"}');
    expect(cleanupRuns(dir, 'jsonl', capBytes: 0).deleted, isEmpty);
  });

  test('recovery is per run, claimed once, and skips live or clean runs', () async {
    final crash = Directory('${dir.path}${Platform.pathSeparator}crash')..createSync();
    // Live run with rotated segments (none has app.stopping).
    final live = RunKey(start, newId(), 'jsonl');
    f(live.lockName).createSync();
    final release = await holdLockInOtherProcess(f(live.lockName).path);
    try {
      for (var n = 0; n <= 5; n++) {
        touch(f(live.segmentName(n)), rec('stream.opened'));
      }
      // Killed: lock free, no app.stopping, one open operation.
      final killed = RunKey(start, newId(), 'jsonl');
      f(killed.lockName).createSync();
      touch(f(killed.segmentName(0)), rec('transfer.send.started'));
      // Clean.
      final clean = RunKey(start, newId(), 'jsonl');
      f(clean.lockName).createSync();
      touch(f(clean.segmentName(0)), rec('app.stopping'));
      // Crashed (crash record wins even with app.stopping).
      final crashed = RunKey(start, newId(), 'jsonl');
      f(crashed.lockName).createSync();
      touch(f(crashed.segmentName(0)), rec('app.stopping'));
      File('${crash.path}${Platform.pathSeparator}${crashed.appSessionId}_x.crash.json').writeAsStringSync('{}');

      final found = recoverRuns(dir, crash, 'jsonl');
      expect(found.map((r) => r.appSessionId), unorderedEquals([killed.appSessionId, crashed.appSessionId]));
      final k = found.singleWhere((r) => r.appSessionId == killed.appSessionId);
      expect(k.exit, Exit.unclean);
      expect(k.openOperations, ['transfer.send']);
      expect(found.singleWhere((r) => r.appSessionId == crashed.appSessionId).exit, Exit.crash);
      expect(recoverRuns(dir, crash, 'jsonl'), isEmpty, reason: 'claimed exactly once');
      expect(f(clean.endedName).readAsStringSync(), contains('clean'));
      expect(f(live.endedName).existsSync(), isFalse, reason: 'live run never claimed');
    } finally {
      await release();
    }
  });
}
