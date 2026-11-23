// Reading, validating, merging and tree-rendering idr.log/1 records; opening bundles.

import 'dart:convert';
import 'dart:io';

import 'package:idr_telemetry/idr_telemetry.dart' show redact;

import 'registry.dart';

class LogRecord {
  LogRecord(this.source, this.line, this.json);
  final String source;
  final int line;
  final Map<String, Object?> json;

  String get ts => json['ts'] as String? ?? '';
  String get service => json['service'] as String? ?? '';
  int get seq => (json['seq'] as num?)?.toInt() ?? 0;
  String get event => json['event'] as String? ?? '';
}

/// Records from JSONL files, directories (recursive) and bundle zips. Invalid JSON lines
/// are returned in [badLines].
({List<LogRecord> records, List<String> badLines}) readAll(List<String> paths) {
  final records = <LogRecord>[];
  final bad = <String>[];
  void text(String source, String content) {
    var n = 0;
    for (final l in const LineSplitter().convert(content)) {
      n++;
      if (l.trim().isEmpty) continue;
      try {
        records.add(LogRecord(source, n, jsonDecode(l) as Map<String, Object?>));
      } on Object {
        bad.add('$source:$n: not a JSON object');
      }
    }
  }

  for (final p in paths) {
    if (FileSystemEntity.isDirectorySync(p)) {
      for (final f in Directory(p).listSync(recursive: true).whereType<File>()) {
        if (f.path.endsWith('.jsonl')) text(f.path, f.readAsStringSync());
      }
    } else if (p.endsWith('.zip')) {
      unzip(File(p).readAsBytesSync()).forEach((name, content) {
        if (name.endsWith('.jsonl')) text('$p!$name', content);
      });
    } else {
      text(p, File(p).readAsStringSync());
    }
  }
  return (records: records, badLines: bad);
}

/// Schema, registry and privacy violations, one message per problem.
List<String> validateRecords(Registry reg, List<LogRecord> records) {
  final out = <String>[];
  for (final r in records) {
    final at = '${r.source}:${r.line}';
    for (final e in reg.schema.validate(r.json)) {
      out.add('$at schema $e');
    }
    final event = r.event;
    if (event != 'diag.log.unstructured' && !reg.isRegistered(event)) out.add('$at unregistered event "$event"');
    final attrs = r.json['attrs'];
    if (attrs is Map) {
      for (final k in attrs.keys) {
        if (!reg.attributes.containsKey(k)) out.add('$at unregistered attribute "$k"');
      }
    }
    // Every string must already be redacted (04 §5): redact() must be a no-op.
    for (final s in _strings(r.json)) {
      if (redact(s) != s) out.add('$at unredacted content: ${_clip(s)}');
    }
  }
  return out;
}

Iterable<String> _strings(Object? v) sync* {
  if (v is String) {
    yield v;
  } else if (v is Map) {
    for (final e in v.entries) {
      if (e.key is String && const {'ts', 'start_ts'}.contains(e.key)) continue;
      yield* _strings(e.value);
    }
  } else if (v is List) {
    for (final x in v) {
      yield* _strings(x);
    }
  }
}

String _clip(String s) => s.length > 60 ? '${s.substring(0, 60)}…' : s;

const _idKeys = ['app_session_id', 'session_id', 'connection_id', 'transfer_id', 'operation_id', 'report_id', 'trace_id', 'span_id'];

/// All records ordered by ts, then producer, then seq (03 §1.3); optionally only those
/// carrying [id] in any correlation field.
List<LogRecord> merge(List<LogRecord> records, {String? id}) {
  final selected = id == null ? records : records.where((r) => _idKeys.any((k) => r.json[k] == id)).toList();
  return [...selected]..sort((a, b) {
      final t = a.ts.compareTo(b.ts);
      if (t != 0) return t;
      final p = '${a.service}|${a.source}'.compareTo('${b.service}|${b.source}');
      return p != 0 ? p : a.seq.compareTo(b.seq);
    });
}

String oneLine(LogRecord r) {
  final j = r.json;
  final err = j['error'] is Map ? ' error.type=${(j['error'] as Map)['type']}' : '';
  final attrs = j['attrs'] is Map ? ' ${(j['attrs'] as Map).entries.map((e) => '${e.key}=${e.value}').join(' ')}' : '';
  final kind = j['kind'] == 'span' ? ' [span ${j['duration_ms']} ms ${j['status']}]' : '';
  return '${r.ts} ${'${j['level']}'.padRight(5)} ${r.service.padRight(14)} ${r.event}$kind$err$attrs';
}

/// Span tree of one trace: spans nest by parent_span_id; log records attach to their span.
String renderTree(List<LogRecord> records, String traceId) {
  final mine = merge(records.where((r) => r.json['trace_id'] == traceId).toList());
  final spans = {for (final r in mine) if (r.json['kind'] == 'span') r.json['span_id'] as String: r};
  final children = <String?, List<LogRecord>>{};
  for (final r in mine) {
    final isSpan = r.json['kind'] == 'span';
    final parent = isSpan ? r.json['parent_span_id'] as String? : r.json['span_id'] as String?;
    final key = parent != null && spans.containsKey(parent) ? parent : null;
    children.putIfAbsent(key, () => []).add(r);
  }
  final sb = StringBuffer('trace $traceId\n');
  void walk(String? parent, String indent) {
    for (final r in children[parent] ?? const <LogRecord>[]) {
      sb.writeln('$indent${r.json['kind'] == 'span' ? '▸ ' : '· '}${oneLine(r)}');
      if (r.json['kind'] == 'span') walk(r.json['span_id'] as String, '$indent  ');
    }
  }

  walk(null, '');
  return sb.toString();
}

/// Summary of a diagnostic bundle: manifest, runs, failures and open operations.
String summarizeBundle(String path) {
  final files = unzip(File(path).readAsBytesSync());
  final sb = StringBuffer();
  final manifest = files['manifest.json'];
  if (manifest != null) {
    final m = jsonDecode(manifest) as Map<String, Object?>;
    sb
      ..writeln('report ${m['report_id']}  created ${m['created_at']}  ${m['service']} ${m['service_version']}  ${m['os']}')
      ..writeln('window ${(m['window'] as Map?)?['from']} → ${(m['window'] as Map?)?['to']}');
    if (m['user_note'] != null) sb.writeln('note: ${m['user_note']}');
    (m['ids'] as Map? ?? const {}).forEach((k, v) => sb.writeln('$k: ${(v as List).length}'));
  }
  final read = readAll([path]);
  final failures = read.records.where((r) => const {'WARN', 'ERROR', 'FATAL'}.contains(r.json['level'])).toList();
  sb.writeln('\n${read.records.length} records, ${failures.length} WARN+, ${files.keys.where((k) => k.startsWith('crash/')).length} crash records');
  for (final r in merge(failures)) {
    sb.writeln('  ${oneLine(r)}${r.json['trace_id'] != null ? '  trace=${r.json['trace_id']}' : ''}');
  }
  final open = read.records.where((r) => r.event == 'app.previous_exit_unclean');
  for (final r in open) {
    sb.writeln('unclean exit of ${(r.json['attrs'] as Map)['previous_app_session_id']}: open ${(r.json['attrs'] as Map)['open_operations']}');
  }
  return sb.toString();
}

/// Reads zip files with stored or deflate entries (no zip64, no data descriptors).
Map<String, String> unzip(List<int> bytes) {
  final out = <String, String>{};
  int u16(int o) => bytes[o] | bytes[o + 1] << 8;
  int u32(int o) => u16(o) | u16(o + 2) << 16;
  var i = 0;
  while (i + 30 <= bytes.length && u32(i) == 0x04034b50) {
    final method = u16(i + 8);
    final size = u32(i + 18);
    final nameLen = u16(i + 26);
    final extra = u16(i + 28);
    final name = utf8.decode(bytes.sublist(i + 30, i + 30 + nameLen));
    final start = i + 30 + nameLen + extra;
    final data = bytes.sublist(start, start + size);
    final raw = method == 8 ? ZLibCodec(raw: true).decode(data) : data;
    out[name] = utf8.decode(raw, allowMalformed: true);
    i = start + size;
  }
  return out;
}
