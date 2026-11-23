// Recorder drain: review findings R2-3a/b/c (docs/observability/09 §2).
import 'dart:io';

import 'package:idr_telemetry/idr_telemetry.dart';
import 'package:idr_telemetry/src/pipeline.dart';
import 'package:test/test.dart';

import 'support.dart';

const t1 = '11111111111111111111111111111111';
const t2 = '22222222222222222222222222222222';

void main() {
  late Directory dir;
  late Pipeline p;
  final id = newId();

  Pipeline make(int queueBytes, {int ringBytes = 3 * 1024 * 1024}) => Pipeline(
        limits: Limits(queueBytes: queueBytes, ringBytes: ringBytes, drainPacing: Duration.zero),
        file: FileSink.open(dir, '2026-11-01T10-00-00Z', id, 'jsonl'),
        makeRecord: (l, e) => Record(Kind.log, l, e)..appSessionId = id,
      );

  void submit(Level level, String event, String trace) {
    final r = Record(Kind.log, level, event)
      ..ts = formatTs(DateTime.now())
      ..service = 't'
      ..serviceVersion = '1'
      ..component = 'c'
      ..appSessionId = id
      ..traceId = trace
      ..error = level >= Level.warn ? ErrorInfo('x') : null;
    p.submit(r, Route(toRing: true, toFile: level >= Level.info, toStderr: false));
  }

  List<Map<String, Object?>> stop() {
    p.shutdown(Record(Kind.log, Level.info, 'app.stopping')..appSessionId = id);
    return readRecords(dir);
  }

  setUp(() => dir = Directory.systemTemp.createTempSync('idr_drain_'));
  tearDown(() => dir.deleteSync(recursive: true));

  // Everything below is submitted synchronously, before the writer timer fires: the
  // equivalent of "the writer has not reached the queue yet".

  test('the triggering ERROR survives a full queue; INFO is written exactly once', () async {
    p = make(1500); // ~3 records
    submit(Level.debug, 'webrtc.ice.candidate_gathered', t1);
    for (var i = 0; i < 8; i++) {
      submit(Level.info, 'stream.opened', t1);
    }
    submit(Level.error, 'connection.attempt.failed', t1); // dropped by the queue
    await p.sync();
    final all = stop();
    final err = named(all, 'connection.attempt.failed');
    expect(err, hasLength(1));
    expect(err.single['flushed'], isTrue, reason: 'recovered by the drain, not the queue');
    expect(named(all, 'webrtc.ice.candidate_gathered'), hasLength(1));
    final infos = named(all, 'stream.opened');
    expect(infos, hasLength(8));
    expect(infos.any((r) => r['flushed'] == true) && infos.any((r) => r['flushed'] == null), isTrue);
    expect(all.map((r) => r['seq']).toSet().length, all.length, reason: 'no record written twice');
  });

  test('records after the watermark stay in the live ring for a later drain', () async {
    p = make(1024 * 1024);
    submit(Level.debug, 'before.a', t1);
    submit(Level.error, 'trigger.a', t1);
    for (var i = 0; i < 3; i++) {
      submit(Level.debug, 'after.a', t2); // seq > watermark(A), before the split
    }
    await p.sync(); // drain A runs and frees its snapshot
    submit(Level.error, 'trigger.b', t2);
    await p.flushAndWait();
    final all = stop();
    expect(named(all, 'before.a'), hasLength(1));
    final after = named(all, 'after.a');
    expect(after, hasLength(3), reason: 'not lost when A\'s snapshot was freed');
    expect(after.every((r) => r['flushed'] == true), isTrue);
  });

  test('many triggers merge into one drain; a bundle request waits for it', () async {
    p = make(1024 * 1024);
    for (var i = 0; i < 5; i++) {
      submit(Level.debug, 'detail', t1);
      submit(Level.error, 'failure.n$i', (i + 1).toRadixString(16).padLeft(32, '0'));
    }
    await p.flushAndWait();
    expect(named(stop(), 'detail'), hasLength(5), reason: 'each DEBUG once');
  });

  test('memory stays within byte caps', () {
    p = make(64 * 1024, ringBytes: 128 * 1024);
    for (var i = 0; i < 2000; i++) {
      final r = Record(Kind.log, Level.info, 'stream.opened')
        ..appSessionId = id
        ..attrs['blob'] = '$i' * 3000;
      p.submit(r, const Route(toRing: true, toFile: true, toStderr: false));
      final (q, ring) = p.byteUsage;
      expect(q <= 64 * 1024 && ring <= 128 * 1024, isTrue, reason: 'q=$q ring=$ring');
    }
    stop();
  });
}
