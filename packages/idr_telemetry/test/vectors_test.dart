// Shared conformance vectors (spec/telemetry/vectors). The Rust crate runs the same files.

import 'dart:convert';
import 'dart:io';

import 'package:idr_telemetry/idr_telemetry.dart';
import 'package:test/test.dart';

Map<String, Object?> vectors(String name) {
  final f = File('../../spec/telemetry/vectors/$name');
  return jsonDecode(f.readAsStringSync()) as Map<String, Object?>;
}

List<Map<String, Object?>> list(Object? v) => (v as List).cast<Map<String, Object?>>();

void main() {
  test('traceparent vectors', () {
    final v = vectors('ids.json');
    for (final c in list(v['traceparent_valid'])) {
      final t = TraceContext.parse(c['input'] as String);
      expect(t, isNotNull, reason: '${c['input']}');
      expect(t!.traceId, c['trace_id']);
      expect(t.spanId, c['span_id']);
      expect(t.sampled, c['sampled']);
    }
    for (final c in list(v['traceparent_invalid'])) {
      expect(TraceContext.parse(c['input'] as String), isNull, reason: '${c['why']}');
    }
    for (final c in list(v['traceparent_format'])) {
      final t = TraceContext(c['trace_id'] as String, c['span_id'] as String, sampled: c['sampled'] as bool);
      expect(t.toTraceparent(), c['output']);
    }
    final root = TraceContext.newRoot();
    expect(TraceContext.parse(root.toTraceparent()), root);
  });

  test('UUIDv7 ids match the pattern and strictly increase', () {
    final re = RegExp(vectors('ids.json')['uuid_pattern'] as String);
    final ids = List.generate(10000, (_) => newId());
    for (final id in ids) {
      expect(re.hasMatch(id) && isUuid(id), isTrue, reason: id);
    }
    for (var i = 1; i < ids.length; i++) {
      expect(ids[i - 1].compareTo(ids[i]), lessThan(0), reason: '${ids[i - 1]} ${ids[i]}');
    }
  });

  test('ctx_json vectors', () {
    final v = vectors('ctx.json');
    for (final c in list(v['cases'])) {
      final p = LocalContext.parse(c['input'] as String);
      expect(p.ctx.trace?.toTraceparent(), c['traceparent'], reason: '${c['input']}');
      expect(p.ctx.sessionId, c['session_id']);
      expect(p.ctx.operationId, c['operation_id']);
      expect(p.ctx.transferId, c['transfer_id']);
      expect(p.invalid, (c['invalid'] as List).cast<String>());
    }
    for (final c in list(v['format'])) {
      final ctx = LocalContext(
        trace: TraceContext.parse(c['traceparent'] as String),
        sessionId: c['session_id'] as String?,
        operationId: c['operation_id'] as String?,
        transferId: c['transfer_id'] as String?,
      );
      expect(ctx.toJson(), c['output']);
    }
  });

  test('redaction vectors', () {
    for (final c in list(vectors('redaction.json')['cases'])) {
      final input = c['input'] as String;
      expect(redact(input), c['expected'], reason: '${c['name']}');
      expect(redact(redact(input)), redact(input), reason: 'idempotent ${c['name']}');
    }
  });

  test('golden record vectors', () {
    for (final c in list(vectors('records.json')['cases'])) {
      final r = c['record'] as Map<String, Object?>;
      final j = {...r, 'attrs': {for (final a in r['attrs'] as List) (a as List)[0] as String: a[1]}};
      final rec = recordFromJson(j)..seq = (r['seq'] as num).toInt();
      rec.redactInPlace();
      expect(withTail(rec.toLine(), 0, r['flushed'] == true), c['line'], reason: '${c['name']}');
    }
  });

  test('redaction stays fast on adversarial input (no quadratic patterns)', () {
    for (final s in ['10' * 3000, '${'a' * 6000}@', 'ab1.' * 3000, 'x ' * 6000, '/a' * 6000, 'a:' * 6000, '1.' * 6000]) {
      final sw = Stopwatch()..start();
      redact(s);
      expect(sw.elapsedMilliseconds, lessThan(100), reason: s.substring(0, 8));
    }
  });

  test('Secret is wire-transparent and never printed', () {
    const s = Secret('tok-123');
    expect(jsonEncode({'connection_token': s}), '{"connection_token":"tok-123"}');
    expect('$s', '[REDACTED]');
    expect(s.value, 'tok-123');
  });
}
