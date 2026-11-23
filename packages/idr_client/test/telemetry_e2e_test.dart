// P1-30: trace and session_id continuity Dart → FFI isolate → native engine (ABI 4).
// Needs the built `idr_c_api` library (IDR_C_API_LIB or agents_engine/agent/target).
import 'dart:convert';
import 'dart:io';

import 'package:idr_client/idr_client.dart';
import 'package:idr_telemetry/idr_telemetry.dart';
import 'package:test/test.dart';

List<Map<String, Object?>> read(Directory dir, String suffix) => [
      for (final f in dir.listSync().whereType<File>().where((f) => f.path.endsWith(suffix)))
        for (final l in const LineSplitter().convert(f.readAsStringSync())) jsonDecode(l) as Map<String, Object?>,
    ];

void main() {
  test('the engine continues the Dart trace with the same session_id in the same run', () async {
    final root = Directory.systemTemp.createTempSync('idr_e2e_');
    addTearDown(() => root.deleteSync(recursive: true));
    final t = await Telemetry.init(TelemetryConfig(service: 'idrs', serviceVersion: '1.0.0', logRoot: root.path));
    const log = IdrLog('idr_source.connect');
    final session = newId();

    final rt = await IdrRuntime.create(authToken: 'test-bearer-token', useMock: true);
    late String traceId;
    await log.span('source.connect', (s) async {
      traceId = s.traceId;
      await rt.connect('demo.idr.to');
    }, attrs: {'session_id': session});
    await rt.dispose();
    await Telemetry.shutdown();

    final dir = Directory('${root.path}${Platform.pathSeparator}idrs');
    final dart = read(dir, '_000.jsonl').where((r) => r['service'] == 'idrs').toList();
    final rust = read(dir, '.rust.jsonl');
    final attempt = dart.singleWhere((r) => r['event'] == 'source.connect.attempt' && r['kind'] == 'span');
    final call = rust.singleWhere((r) => r['event'] == 'ffi.call' && r['kind'] == 'span');

    expect(rust.first['app_session_id'], t.appSessionId, reason: 'one process, one run');
    expect(attempt['trace_id'], traceId);
    expect(call['trace_id'], traceId, reason: 'trace continues across the FFI isolate and ABI');
    expect(call['parent_span_id'], attempt['span_id'], reason: 'engine work nests under the attempt');
    expect(call['session_id'], session);
    expect((call['attrs'] as Map)['ffi.fn'], 'idr_connect');
  });
}
