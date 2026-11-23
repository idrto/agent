// IDs and W3C trace context (docs/observability/02).

import 'dart:math';
import 'dart:typed_data';

final Random _rng = Random.secure();

int _lastMs = -1;
int _counter = 0;

/// A new lowercase-hyphenated UUIDv7, strictly increasing within this isolate.
/// The only sanctioned way to mint correlation IDs.
String newId() {
  var ms = DateTime.now().millisecondsSinceEpoch;
  if (ms <= _lastMs) {
    ms = _lastMs;
    _counter++;
    if (_counter > 0xfff) {
      ms = ++_lastMs;
      _counter = _rng.nextInt(0x400);
    }
  } else {
    _counter = _rng.nextInt(0x400); // headroom for in-ms increments
  }
  _lastMs = ms;
  final b = Uint8List(16);
  for (var i = 0; i < 6; i++) {
    b[i] = (ms ~/ pow(2, 8 * (5 - i)).toInt()) & 0xff;
  }
  b[6] = 0x70 | (_counter >> 8);
  b[7] = _counter & 0xff;
  for (var i = 8; i < 16; i++) {
    b[i] = _rng.nextInt(256);
  }
  b[8] = 0x80 | (b[8] & 0x3f);
  final h = hex(b);
  return '${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-'
      '${h.substring(16, 20)}-${h.substring(20)}';
}

final RegExp _uuid = RegExp(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$');

/// True for a lowercase hyphenated UUID (any version), the only accepted ID text form.
bool isUuid(String s) => _uuid.hasMatch(s);

String hex(List<int> bytes) {
  final sb = StringBuffer();
  for (final b in bytes) {
    sb.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}

Uint8List _randomNonZero(int n) {
  final b = Uint8List(n);
  while (b.every((x) => x == 0)) {
    for (var i = 0; i < n; i++) {
      b[i] = _rng.nextInt(256);
    }
  }
  return b;
}

String newTraceIdHex() => hex(_randomNonZero(16));
String newSpanIdHex() => hex(_randomNonZero(8));

/// W3C trace context: 32-hex trace id, 16-hex parent span id, sampled flag.
class TraceContext {
  const TraceContext(this.traceId, this.spanId, {this.sampled = true});

  final String traceId;
  final String spanId;
  final bool sampled;

  factory TraceContext.newRoot() => TraceContext(newTraceIdHex(), newSpanIdHex());

  static final RegExp _hex2 = RegExp(r'^[0-9a-f]{2}$');
  static final RegExp _trace = RegExp(r'^[0-9a-f]{32}$');
  static final RegExp _span = RegExp(r'^[0-9a-f]{16}$');

  /// Parses a `traceparent` value; null when invalid (vectors/ids.json).
  static TraceContext? parse(String tp) {
    if (tp.length < 55 || tp[2] != '-' || tp[35] != '-' || tp[52] != '-') return null;
    final version = tp.substring(0, 2);
    if (!_hex2.hasMatch(version) || version == 'ff') return null;
    if (version == '00' && tp.length != 55) return null;
    if (version != '00' && tp.length > 55 && tp[55] != '-') return null;
    final traceId = tp.substring(3, 35);
    final spanId = tp.substring(36, 52);
    final flags = tp.substring(53, 55);
    if (!_trace.hasMatch(traceId) || !_span.hasMatch(spanId) || !_hex2.hasMatch(flags)) return null;
    if (traceId == '0' * 32 || spanId == '0' * 16) return null;
    return TraceContext(traceId, spanId, sampled: int.parse(flags, radix: 16) & 1 == 1);
  }

  String toTraceparent() => '00-$traceId-$spanId-${sampled ? '01' : '00'}';

  @override
  bool operator ==(Object other) =>
      other is TraceContext && other.traceId == traceId && other.spanId == spanId && other.sampled == sampled;

  @override
  int get hashCode => Object.hash(traceId, spanId, sampled);

  @override
  String toString() => toTraceparent();
}
