// A minimal JSON Schema (2020-12) evaluator for the keywords log-record.schema.json uses,
// so the schema file stays the single source of truth without a schema dependency.

class SchemaValidator {
  SchemaValidator(this.root);
  final Map<String, Object?> root;

  /// Error messages for [value]; empty when valid.
  List<String> validate(Object? value) {
    final errors = <String>[];
    _check(root, value, r'$', errors);
    return errors;
  }

  Map<String, Object?> _resolve(Map<String, Object?> s) {
    final ref = s[r'$ref'];
    if (ref is! String) return s;
    Object? node = root;
    for (final part in ref.replaceFirst('#/', '').split('/')) {
      node = (node as Map<String, Object?>)[part];
    }
    return _resolve(node as Map<String, Object?>);
  }

  bool _ok(Map<String, Object?> s, Object? v) {
    final e = <String>[];
    _check(s, v, '', e);
    return e.isEmpty;
  }

  void _check(Map<String, Object?> schema, Object? v, String at, List<String> errors) {
    final s = _resolve(schema);
    void fail(String m) => errors.add('$at: $m');

    if (s.containsKey('const') && s['const'] != v) fail('must be ${s['const']}');
    if (s['enum'] is List && !(s['enum'] as List).contains(v)) fail('must be one of ${s['enum']}');
    final type = s['type'];
    if (type != null) {
      final types = type is List ? type.cast<String>() : [type as String];
      if (!types.any((t) => _isType(t, v))) {
        fail('must be of type $type');
        return;
      }
    }
    if (v is String) {
      final p = s['pattern'];
      if (p is String && !RegExp(p).hasMatch(v)) fail('"$v" does not match $p');
      final min = s['minLength'];
      if (min is int && v.length < min) fail('shorter than $min');
    }
    if (v is num) {
      final min = s['minimum'];
      if (min is num && v < min) fail('below $min');
    }
    if (v is List && s['items'] is Map) {
      for (var i = 0; i < v.length; i++) {
        _check(s['items'] as Map<String, Object?>, v[i], '$at[$i]', errors);
      }
    }
    if (v is Map<String, Object?>) {
      for (final r in (s['required'] as List? ?? const [])) {
        if (!v.containsKey(r)) fail('missing "$r"');
      }
      final props = s['properties'] as Map<String, Object?>? ?? const {};
      final additional = s['additionalProperties'];
      final names = s['propertyNames'];
      v.forEach((k, val) {
        if (names is Map<String, Object?>) _check(names, k, '$at.$k(name)', errors);
        if (props.containsKey(k)) {
          _check(props[k] as Map<String, Object?>, val, '$at.$k', errors);
        } else if (additional == false) {
          fail('unexpected property "$k"');
        } else if (additional is Map<String, Object?>) {
          _check(additional, val, '$at.$k', errors);
        }
      });
    }
    final oneOf = s['oneOf'];
    if (oneOf is List && oneOf.where((o) => _ok(o as Map<String, Object?>, v)).length != 1) fail('must match exactly one alternative');
    for (final sub in (s['allOf'] as List? ?? const [])) {
      _check(sub as Map<String, Object?>, v, at, errors);
    }
    final ifS = s['if'];
    if (ifS is Map<String, Object?> && _ok(ifS, v) && s['then'] is Map) _check(s['then'] as Map<String, Object?>, v, at, errors);
  }

  static bool _isType(String t, Object? v) => switch (t) {
        'object' => v is Map,
        'array' => v is List,
        'string' => v is String,
        'integer' => v is int || (v is double && v == v.roundToDouble()),
        'number' => v is num,
        'boolean' => v is bool,
        'null' => v == null,
        _ => false,
      };
}
