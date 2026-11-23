// idr.log/1 record: redaction of every string, fixed key order, 8 KiB cap (03 §1).
// Mirrors crates/idr-telemetry/src/subscriber/record.rs; both pass vectors/records.json.

import 'dart:convert';

import 'redact.dart';

const int maxRecordBytes = 8 * 1024;
const int maxCrashBytes = 256 * 1024;
const String schema = 'idr.log/1';

enum Level {
  trace('TRACE'),
  debug('DEBUG'),
  info('INFO'),
  warn('WARN'),
  error('ERROR'),
  fatal('FATAL');

  const Level(this.label);
  final String label;

  bool operator >=(Level o) => index >= o.index;
  bool operator <(Level o) => index < o.index;

  static Level? parse(String s) => switch (s.toLowerCase()) {
        'trace' => Level.trace,
        'debug' => Level.debug,
        'info' => Level.info,
        'warn' || 'warning' => Level.warn,
        'error' => Level.error,
        'fatal' => Level.fatal,
        _ => null,
      };
}

enum Kind { log, span, crash }

class ErrorInfo {
  ErrorInfo(this.type, {this.message, this.code, this.stack, this.cause});

  String type;
  String? message;
  int? code;
  String? stack;
  ErrorInfo? cause;
}

/// Attribute values: String, int, double, bool, or List<String>.
class Record {
  Record(this.kind, this.level, this.event);

  Kind kind;
  String ts = '';
  int seq = 0;
  Level level;
  String event;
  String? msg;
  String service = '';
  String serviceVersion = '';
  String component = '';
  String appSessionId = '';
  String? traceId;
  String? spanId;
  String? parentSpanId;
  List<(String, String)> links = [];
  String? startTs;
  double? durationMs;
  String? status;
  String? sessionId;
  String? connectionId;
  String? transferId;
  String? operationId;
  String? reportId;
  ErrorInfo? error;
  Map<String, Object> attrs = {};

  /// Redacts every free-form string (msg, error tree, string attrs) — 04 §5.2 step 3.
  void redactInPlace() {
    if (msg != null) msg = redact(msg!);
    for (var e = error; e != null; e = e.cause) {
      if (e.message != null) e.message = redact(e.message!);
      if (e.stack != null) e.stack = redact(e.stack!);
    }
    for (final k in attrs.keys.toList()) {
      final v = attrs[k];
      if (v is String) {
        attrs[k] = redact(v);
      } else if (v is List<String>) {
        attrs[k] = [for (final s in v) redact(s)];
      }
    }
  }

  /// Fixed key order (vectors/records.json). `dropped`/`flushed` come from [withTail].
  String toLine() {
    final sb = StringBuffer('{');
    var first = true;
    void key(String k) {
      if (!first) sb.write(',');
      first = false;
      sb
        ..write('"')
        ..write(k)
        ..write('":');
    }

    void str(String k, String? v) {
      if (v == null) return;
      key(k);
      sb.write(jsonEncode(v));
    }

    str('schema', schema);
    str('kind', kind.name);
    str('ts', ts);
    key('seq');
    sb.write(seq);
    str('level', level.label);
    str('event', event);
    str('msg', msg);
    str('service', service);
    str('service_version', serviceVersion);
    str('component', component);
    str('app_session_id', appSessionId);
    str('trace_id', traceId);
    str('span_id', spanId);
    str('parent_span_id', parentSpanId);
    if (links.isNotEmpty) {
      key('links');
      sb.write('[${links.map((l) => '{"trace_id":"${l.$1}","span_id":"${l.$2}"}').join(',')}]');
    }
    str('start_ts', startTs);
    if (durationMs != null) {
      key('duration_ms');
      sb.write(_num(durationMs!));
    }
    str('status', status);
    str('session_id', sessionId);
    str('connection_id', connectionId);
    str('transfer_id', transferId);
    str('operation_id', operationId);
    str('report_id', reportId);
    if (error != null) {
      key('error');
      _writeError(sb, error!);
    }
    if (attrs.isNotEmpty) {
      key('attrs');
      sb.write('{');
      var i = 0;
      attrs.forEach((k, v) {
        if (i++ > 0) sb.write(',');
        sb
          ..write(jsonEncode(k))
          ..write(':')
          ..write(v is double ? _num(v) : jsonEncode(v));
      });
      sb.write('}');
    }
    sb.write('}');
    return sb.toString();
  }

  /// Serialized line within [cap] bytes: trims the stack, then string lists, then the
  /// longest string; if still too big, a `diag.record.oversized` replacement.
  String toCappedLine([int cap = maxRecordBytes]) {
    var line = toLine();
    if (utf8.encode(line).length <= cap) return line;
    final e = error;
    if (e?.stack != null) e!.stack = e.stack!.split('\n').take(32).join('\n');
    while (true) {
      line = toLine();
      final len = utf8.encode(line).length;
      if (len <= cap) return line;
      final over = len - cap + 32;
      final listKey = attrs.keys.where((k) => attrs[k] is List<String> && (attrs[k] as List<String>).isNotEmpty).firstOrNull;
      if (listKey != null) {
        attrs[listKey] = (attrs[listKey] as List<String>).sublist(1);
        continue;
      }
      // Longest of: string attrs, msg, error.message (only strings over 64 chars).
      String? best;
      void Function(String)? replace;
      void consider(String? v, void Function(String) set) {
        if (v != null && v.length > 64 && v.length > (best?.length ?? 0)) {
          best = v;
          replace = set;
        }
      }

      attrs.forEach((k, v) => consider(v is String ? v : null, (x) => attrs[k] = x));
      consider(msg, (x) => msg = x);
      consider(error?.message, (x) => error!.message = x);
      if (replace == null) break;
      replace!(_truncate(best!, over));
    }
    // Still too big: replace in place, keeping identity and trace position.
    final bytes = utf8.encode(toLine()).length;
    final name = event;
    kind = Kind.log;
    level = Level.warn;
    event = 'diag.record.oversized';
    msg = parentSpanId = startTs = status = null;
    sessionId = connectionId = transferId = operationId = reportId = null;
    durationMs = null;
    links = [];
    error = ErrorInfo('oversized');
    attrs = {'event.name': name, 'bytes': bytes};
    return toLine();
  }
}

String _truncate(String s, int removeBytes) {
  // ponytail: trims by UTF-16 code units, close enough to bytes for a size cap.
  final keep = (s.length - removeBytes).clamp(0, s.length);
  return '${s.substring(0, keep)}…[truncated ${s.length - keep}]';
}

/// Same shortest round-trip form as serde_json for finite doubles.
String _num(double d) => jsonEncode(d);

void _writeError(StringBuffer sb, ErrorInfo e) {
  sb.write('{"type":${jsonEncode(e.type)}');
  if (e.message != null) sb.write(',"message":${jsonEncode(e.message)}');
  if (e.code != null) sb.write(',"code":${e.code}');
  if (e.stack != null) sb.write(',"stack":${jsonEncode(e.stack)}');
  if (e.cause != null) {
    sb.write(',"cause":');
    _writeError(sb, e.cause!);
  }
  sb.write('}');
}

/// Appends writer-owned tail fields (`dropped`, `flushed`) before the closing brace.
String withTail(String line, int dropped, bool flushed) {
  if (dropped == 0 && !flushed) return line;
  final sb = StringBuffer(line.substring(0, line.length - 1));
  if (dropped > 0) sb.write(',"dropped":$dropped');
  if (flushed) sb.write(',"flushed":true');
  sb.write('}');
  return sb.toString();
}

/// RFC 3339 UTC with microseconds.
String formatTs(DateTime t) {
  final u = t.toUtc();
  String p(int v, int w) => v.toString().padLeft(w, '0');
  return '${p(u.year, 4)}-${p(u.month, 2)}-${p(u.day, 2)}T${p(u.hour, 2)}:${p(u.minute, 2)}:${p(u.second, 2)}'
      '.${p(u.millisecond * 1000 + u.microsecond, 6)}Z';
}
