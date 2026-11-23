import 'dart:async';
import 'dart:io';
import 'dart:isolate';

import 'package:idr_telemetry/idr_telemetry.dart';
import 'package:test/test.dart';

import 'support.dart';

const log = IdrLog('idr_source.connect');

void main() {
  late Directory root;
  Directory serviceDir() => Directory('${root.path}${Platform.pathSeparator}idrs');

  setUp(() async {
    root = Directory.systemTemp.createTempSync('idr_tel_');
    await Telemetry.init(TelemetryConfig(service: 'idrs', serviceVersion: '1.0.0', logRoot: root.path));
  });

  tearDown(() async {
    await Telemetry.shutdown();
    root.deleteSync(recursive: true);
  });

  test('spans and events inherit trace, parent and correlation; strings are redacted', () async {
    final session = newId();
    final remote = TraceContext.parse('00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01')!;
    LocalContext? seen;
    await log.span('source.connect', (s) async {
      await log.span('source.connect.attempt', (a) async {
        await Future<void>.delayed(Duration.zero); // across an await
        log.warn('connection.attempt.failed',
            errorType: 'ice_failed', attrs: {'phase': 'ice', 'elapsed_ms': 30012}, msg: 'ICE failed for bob@example.com');
        seen = currentContext();
      }, attrs: {'retry.attempt': 1});
    }, attrs: {'session_id': session, 'target.fqhn': 'gpu--acme.idr.to'}, remoteParent: remote, persistStart: true);
    await Telemetry.shutdown();

    final all = readRecords(serviceDir());
    expect(all.first['event'], 'app.started');
    expect(all.last['event'], 'app.stopping', reason: 'app.stopping is the final record');
    final failed = named(all, 'connection.attempt.failed').single;
    final attempt = named(all, 'source.connect.attempt').single;
    final rootSpan = named(all, 'source.connect').single;
    expect(failed['trace_id'], remote.traceId);
    expect(failed['session_id'], session);
    expect(failed['span_id'], attempt['span_id']);
    expect(failed['msg'], 'ICE failed for [REDACTED EMAIL]');
    expect((failed['error'] as Map)['type'], 'ice_failed');
    expect(attempt['parent_span_id'], rootSpan['span_id']);
    expect(rootSpan['parent_span_id'], remote.spanId);
    expect(rootSpan['session_id'], session);
    expect((rootSpan['attrs'] as Map)['target.fqhn'], 'gpu--acme.idr.to');
    expect(named(all, 'source.connect.started').single['span_id'], rootSpan['span_id']);
    expect(seen!.sessionId, session);
    expect(seen!.trace!.traceId, remote.traceId);
  });

  test('a thrown exception fails the span and is rethrown', () async {
    await expectLater(log.span('stream.open', (s) async => throw StateError('nope')), throwsStateError);
    await Telemetry.shutdown();
    final span = named(readRecords(serviceDir()), 'stream.open').single;
    expect(span['status'], 'error');
    expect(span['level'], 'WARN');
  });

  test('100 concurrent operations never mix ids across awaits', () async {
    final sessions = <String>[];
    await Future.wait(List.generate(100, (i) {
      final s = newId();
      sessions.add(s);
      return log.span('source.connect', (sp) async {
        for (var k = 0; k < 5; k++) {
          await Future<void>.delayed(Duration(microseconds: (i * 7 + k) % 13));
          log.info('stream.opened', attrs: {'stream.id': k});
        }
      }, attrs: {'session_id': s});
    }));
    await Telemetry.shutdown();
    final all = readRecords(serviceDir());
    final spans = named(all, 'source.connect');
    final opened = named(all, 'stream.opened');
    expect(opened.length, 500);
    for (final s in sessions) {
      final span = spans.singleWhere((r) => r['session_id'] == s);
      final mine = opened.where((r) => r['session_id'] == s).toList();
      expect(mine.length, 5);
      expect(mine.every((r) => r['trace_id'] == span['trace_id'] && r['span_id'] == span['span_id']), isTrue);
    }
  });

  test('Secret values cannot be logged', () {
    expect(() => log.info('stream.opened', attrs: {'token': const Secret('x')}), throwsArgumentError);
  });

  test('a worker isolate logs into the main pipeline with restored context', () async {
    final link = Telemetry.instance!.link();
    final ctxJson = await log.span('transfer.send', (s) async => currentContextJson(), attrs: {'transfer_id': newId()});
    await Isolate.run(() {
      Telemetry.initWorker(link);
      withContext(LocalContext.parse(ctxJson).ctx, () {
        const IdrLog('idr_client.ffi').info('transfer.started', attrs: {'direction': 'send', 'entries': 1, 'bytes.total': 9});
      });
    });
    await Future<void>.delayed(const Duration(milliseconds: 100));
    await Telemetry.shutdown();
    final all = readRecords(serviceDir());
    final span = named(all, 'transfer.send').single;
    final started = named(all, 'transfer.started').single;
    expect(started['app_session_id'], span['app_session_id'], reason: 'one process, one app_session_id');
    expect(started['trace_id'], span['trace_id']);
    expect(started['transfer_id'], span['transfer_id']);
    expect(started['component'], 'idr_client.ffi');
  });

  test('an uncaught error writes a crash record; the next start reports it', () async {
    final done = Completer<void>();
    runGuarded(() {
      Future<void>(() => throw StateError('boom at /home/alice/x')).whenComplete(done.complete);
    });
    await done.future;
    await Future<void>.delayed(const Duration(milliseconds: 50));
    await Telemetry.shutdown();
    final crash = Directory('${root.path}${Platform.pathSeparator}crash').listSync().single as File;
    final text = crash.readAsStringSync();
    expect(text, contains('"kind":"crash"'));
    expect(text, contains('boom at ~/x'), reason: 'crash records are redacted');

    await Telemetry.init(TelemetryConfig(service: 'idrs', serviceVersion: '1.0.0', logRoot: root.path));
    await Telemetry.sync();
    final report = named(readRecords(serviceDir()), 'app.previous_exit_unclean').single;
    expect((report['attrs'] as Map)['crash_record'], isTrue);
  });

  test('a diagnostic bundle contains logs, crash records and a manifest index', () async {
    final session = newId();
    await log.span('source.connect', (s) async {
      log.info('session.started', attrs: {'target.fqhn': 'gpu--acme.idr.to'}, msg: 'by bob@example.com');
    }, attrs: {'session_id': session});
    final b = await DiagnosticBundle.collect(userNote: 'it broke, mail me at bob@example.com', state: {'agent_running': true});
    final files = unzip(b.file.readAsBytesSync());
    expect(files.keys, containsAll(['manifest.json', 'state/summary.json']));
    expect(files.keys.any((k) => k.startsWith('logs/idrs/')), isTrue);
    final manifest = files['manifest.json']!;
    expect(manifest, contains(session));
    expect(manifest, contains('[REDACTED EMAIL]'));
    expect(manifest, isNot(contains('bob@example.com')));
    expect(files.values.any((v) => v.contains('bob@example.com')), isFalse);
  });
}

/// Reads our own minimal zip (local headers, raw deflate).
Map<String, String> unzip(List<int> bytes) {
  final out = <String, String>{};
  var i = 0;
  int u16(int o) => bytes[o] | bytes[o + 1] << 8;
  int u32(int o) => u16(o) | u16(o + 2) << 16;
  while (u32(i) == 0x04034b50) {
    final size = u32(i + 18);
    final nameLen = u16(i + 26);
    final name = String.fromCharCodes(bytes.sublist(i + 30, i + 30 + nameLen));
    final data = bytes.sublist(i + 30 + nameLen, i + 30 + nameLen + size);
    out[name] = String.fromCharCodes(ZLibCodec(raw: true).decode(data));
    i += 30 + nameLen + size;
  }
  return out;
}
