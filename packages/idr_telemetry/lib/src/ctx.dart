// Local context (`ctx_json`) carried across FFI, isolates and IPC (01 §4.2).

import 'dart:convert';

import 'ids.dart';

class LocalContext {
  const LocalContext({this.trace, this.sessionId, this.operationId, this.transferId});

  final TraceContext? trace;
  final String? sessionId;
  final String? operationId;
  final String? transferId;

  /// Parses `ctx_json`. Invalid fields are dropped individually and named in [invalid]
  /// (`ctx` when the input is not a JSON object). Empty input is no context.
  static ({LocalContext ctx, List<String> invalid}) parse(String json) {
    final invalid = <String>[];
    if (json.trim().isEmpty) return (ctx: const LocalContext(), invalid: invalid);
    Object? decoded;
    try {
      decoded = jsonDecode(json);
    } on FormatException {
      decoded = null;
    }
    if (decoded is! Map<String, Object?>) {
      return (ctx: const LocalContext(), invalid: ['ctx']);
    }
    TraceContext? trace;
    final tp = decoded['traceparent'];
    if (tp != null) {
      trace = tp is String ? TraceContext.parse(tp) : null;
      if (trace == null) invalid.add('traceparent');
    }
    String? id(String key) {
      final v = decoded as Map<String, Object?>;
      final x = v[key];
      if (x == null) return null;
      if (x is String && isUuid(x)) return x;
      invalid.add(key);
      return null;
    }

    final ctx = LocalContext(
      trace: trace,
      sessionId: id('session_id'),
      operationId: id('operation_id'),
      transferId: id('transfer_id'),
    );
    return (ctx: ctx, invalid: invalid);
  }

  /// Serializes with null fields omitted, keys in the fixed order.
  String toJson() => jsonEncode({
        if (trace != null) 'traceparent': trace!.toTraceparent(),
        if (sessionId != null) 'session_id': sessionId,
        if (operationId != null) 'operation_id': operationId,
        if (transferId != null) 'transfer_id': transferId,
      });
}
