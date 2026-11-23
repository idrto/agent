// Every gate must fail on a seeded violation (08 P1-07 acceptance) and pass on clean input.

import 'dart:convert';
import 'dart:io';

import 'package:idr_diag/idr_diag.dart';
import 'package:idr_telemetry/idr_telemetry.dart';
import 'package:test/test.dart';

const realRepo = '../..';

void main() {
  late Directory repo;

  void write(String rel, String content) {
    File('${repo.path}/$rel')
      ..createSync(recursive: true)
      ..writeAsStringSync(content);
  }

  setUp(() {
    repo = Directory.systemTemp.createTempSync('idr_diag_');
    for (final f in ['events.yaml', 'attributes.yaml', 'log-record.schema.json']) {
      write('spec/telemetry/$f', File('$realRepo/spec/telemetry/$f').readAsStringSync());
    }
    write('spec/telemetry/lint.yaml', '''
event_names: [lib_dart, crate/src]
banned_apis: {dart: [lib_dart], rust: [crate/src]}
secrets_debug: [crate/src]
secrets_debug_allow: []
tracing_subscriber_allowed: [allowed-bin]
dp_sdk_root: dp
''');
  });

  tearDown(() => repo.deleteSync(recursive: true));

  List<Finding> lint() {
    final cfg = LintConfig.load(repo.path);
    return [
      ...lintEventNames(Registry.load(repo.path), cfg),
      ...lintBannedApis(cfg),
      ...lintSecretDebug(cfg),
      ...lintDependencies(cfg),
    ];
  }

  test('clean sources pass every gate', () {
    write('lib_dart/a.dart', """
const log = IdrLog('idr_source.connect');
void f() { log.info('session.started', attrs: {'target.fqhn': 'x', 'session_id': 'y'}); }
""");
    write('crate/src/lib.rs', '''
#[derive(Debug)]
pub struct Hello { pub connection_token: Secret<String>, pub target_fqhn: String }
fn g() { tracing::info!(event = "connection.established", transport.selected = "p2p", setup_ms = 3u64, "ok"); }
''');
    write('crate/Cargo.toml', '[package]\nname = "lib-crate"\n[dependencies]\ntracing = "0.1"\n');
    write('dp/packages/dp-rust/Cargo.toml', '[package]\nname = "dp-rust"\n[dependencies]\nserde = "1"\n');
    expect(lint().map((f) => '$f'), isEmpty);
  });

  test('each gate fails on a seeded violation', () {
    write('lib_dart/a.dart', """
void f() {
  log.info('made.up.event');
  log.info('session.made_up');
  log.info('session.started', attrs: {'not.registered': 1});
  print('debugging');
}
""");
    write('crate/src/lib.rs', '''
#[derive(Clone, Debug)]
pub struct Leaky {
    pub auth_token: String,
}
fn g() { println!("x"); tracing::warn!(event = "Bad Name"); }
''');
    write('crate/Cargo.toml', '[package]\nname = "lib-crate"\n[dependencies]\ntracing-subscriber = "0.3"\n');
    write('dp/packages/dp-rust/Cargo.toml', '[package]\nname = "dp-rust"\n[dependencies]\ntracing = "0.1"\n');
    final rules = lint().map((f) => f.rule).toSet();
    expect(rules, containsAll(['event-domain', 'event-registry', 'attr-registry', 'banned-dart', 'secret-debug', 'banned-rust', 'event-name', 'subscriber-dep', 'dp-sdk-purity']));
  });

  test('validate accepts real records and rejects seeded problems', () {
    final reg = Registry.load(realRepo);
    final golden = (jsonDecode(File('$realRepo/spec/telemetry/vectors/records.json').readAsStringSync())['cases'] as List)
        .map((c) => (c as Map)['line'] as String)
        .join('\n');
    final good = File('${repo.path}/good.jsonl')..writeAsStringSync(golden);
    expect(validateRecords(reg, readAll([good.path]).records), isEmpty);

    final bad = File('${repo.path}/bad.jsonl')
      ..writeAsStringSync([
        '{"schema":"idr.log/1","kind":"log","ts":"2026-11-21T10:12:40.183512Z","seq":1,"level":"INFO","event":"made.up.event","service":"idrs","service_version":"1","component":"c","app_session_id":"019372b0-11aa-7e01-8c1d-2f6a9b0c0001"}',
        '{"schema":"idr.log/1","kind":"log","ts":"2026-11-21T10:12:40.183512Z","seq":2,"level":"INFO","event":"session.started","msg":"by bob@example.com","service":"idrs","service_version":"1","component":"c","app_session_id":"019372b0-11aa-7e01-8c1d-2f6a9b0c0001","attrs":{"nope":1}}',
        '{"schema":"idr.log/1","kind":"log","ts":"bad","seq":3,"level":"WARN","event":"connection.lost","service":"idrs","service_version":"1","component":"c","app_session_id":"NOT-A-UUID"}',
      ].join('\n'));
    final problems = validateRecords(reg, readAll([bad.path]).records).join('\n');
    expect(problems, contains('unregistered event "made.up.event"'));
    expect(problems, contains('unregistered attribute "nope"'));
    expect(problems, contains('unredacted content'));
    expect(problems, contains('missing "error"'), reason: 'WARN without error.type');
    expect(problems, contains('app_session_id'));
  });

  test('real idr_telemetry output (spans, drain, crash, recovery) validates against the spec', () async {
    final root = '${repo.path}/logs';
    const log = IdrLog('idr_source.connect');
    await Telemetry.init(TelemetryConfig(service: 'idrs', serviceVersion: '1.0.0', logRoot: root));
    await log.span('source.connect', (s) async {
      log.debug('webrtc.ice.candidate_gathered', attrs: {'candidate.type': 'host', 'candidate.protocol': 'udp'});
      log.warn('connection.attempt.failed', errorType: 'ice_failed', attrs: {'phase': 'ice', 'elapsed_ms': 30012});
      log.error('transfer.failed', errorType: 'storage_full', attrs: {'bytes.done': 1024}, msg: 'disk full at /home/bob/x');
    }, attrs: {'session_id': newId(), 'target.fqhn': 'gpu--acme.idr.to'}, persistStart: true);
    Telemetry.instance!.recordCrash(StateError('boom'), StackTrace.current);
    await Telemetry.shutdown();
    await Telemetry.init(TelemetryConfig(service: 'idrs', serviceVersion: '1.0.0', logRoot: root)); // recovery records
    await Telemetry.shutdown();
    final read = readAll([root]);
    expect(read.records.length, greaterThan(8));
    expect([...read.badLines, ...validateRecords(Registry.load(realRepo), read.records)], isEmpty);
  });

  test('merge orders across producers; tree nests spans and events', () {
    String rec(String ts, int seq, String service, String event, Map<String, Object?> extra) => jsonEncode({
          'schema': 'idr.log/1', 'kind': 'log', 'ts': ts, 'seq': seq, 'level': 'INFO', 'event': event,
          'service': service, 'service_version': '1', 'component': 'c', 'app_session_id': '019372b0-11aa-7e01-8c1d-2f6a9b0c0001', ...extra,
        });
    const t = '4bf92f3577b34da6a3ce929d0e0e4736';
    File('${repo.path}/a.jsonl').writeAsStringSync([
      rec('2026-11-21T10:00:02.000000Z', 5, 'idrs', 'connection.established', {'trace_id': t, 'span_id': 'a1b2c3d4e5f60718'}),
      rec('2026-11-21T10:00:03.000000Z', 6, 'idrs', 'source.connect',
          {'kind': 'span', 'trace_id': t, 'span_id': '00f067aa0ba902b7', 'start_ts': '2026-11-21T10:00:00.000000Z', 'duration_ms': 3000, 'status': 'ok'}),
    ].join('\n'));
    File('${repo.path}/b.rust.jsonl').writeAsStringSync([
      rec('2026-11-21T10:00:01.000000Z', 0, 'idr-c-api', 'signaling.message.sent', {'trace_id': t, 'span_id': 'a1b2c3d4e5f60718'}),
      rec('2026-11-21T10:00:02.500000Z', 1, 'idr-c-api', 'source.connect.attempt', {
        'kind': 'span', 'trace_id': t, 'span_id': 'a1b2c3d4e5f60718', 'parent_span_id': '00f067aa0ba902b7',
        'start_ts': '2026-11-21T10:00:00.500000Z', 'duration_ms': 2000, 'status': 'ok',
      }),
    ].join('\n'));
    final records = readAll([repo.path]).records;
    expect(merge(records).map((r) => r.event).toList(),
        ['signaling.message.sent', 'connection.established', 'source.connect.attempt', 'source.connect']);
    final tree = renderTree(records, t).split('\n');
    expect(tree[1], contains('▸'));
    expect(tree[1], contains('source.connect '));
    expect(tree.indexWhere((l) => l.contains('source.connect.attempt')), greaterThan(1));
    expect(tree.firstWhere((l) => l.contains('signaling.message.sent')), startsWith('    · '), reason: 'event under the attempt span');
  });
}
