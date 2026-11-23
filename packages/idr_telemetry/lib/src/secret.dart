// `Secret<T>`: travels on the wire, never reaches a log (01 §2.3).

/// - `toJson()` returns the value, so `jsonEncode` keeps wire bytes unchanged;
/// - `toString()` prints `[REDACTED]`;
/// - passing it as a log attribute throws (see `IdrLog`);
/// - the value is read only through [value].
class Secret<T> {
  const Secret(this._value);

  final T _value;

  /// The only way to read the value. Grep for `.value` on secrets in review.
  T get value => _value;

  Object? toJson() => _value;

  @override
  String toString() => '[REDACTED]';

  @override
  bool operator ==(Object other) => other is Secret<T> && other._value == _value;

  @override
  int get hashCode => _value.hashCode;
}
