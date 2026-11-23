// Redaction of free-form strings. The rules and their order are the spec in
// spec/telemetry/vectors/redaction.json; keep this file and that file identical in meaning.

typedef _Rule = (RegExp, String Function(Match));

String _g1(Match m) => m.group(1) ?? '';

final List<_Rule> _beforeIpv6 = [
  (RegExp(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----'), (_) => '[REDACTED PRIVATE KEY]'),
  (RegExp(r'v=0(?:\r?\n[a-z]=[^\r\n]*)+'), (_) => '[REDACTED SDP]'),
  (RegExp(r'''(candidate:)[^\r\n"']+'''), (m) => '${_g1(m)}[REDACTED]'),
  (RegExp(r'''(a=fingerprint:)[^\r\n"']+'''), (m) => '${_g1(m)}[REDACTED]'),
  (RegExp(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'), (_) => '[REDACTED JWT]'),
  (RegExp(r'(Bearer\s+)[A-Za-z0-9._~+/=-]+', caseSensitive: false), (m) => '${_g1(m)}[REDACTED]'),
  (RegExp(r'''(https?://[^\s?#"'<>]+)\?[^\s#"'<>]*''', caseSensitive: false), (m) => '${_g1(m)}?[REDACTED]'),
  (
    RegExp(r'''([?&](?:token|ott|code|access_token|refresh_token|key|secret|signature|password)=)[^&\s"]+''',
        caseSensitive: false),
    (m) => '${_g1(m)}[REDACTED]'
  ),
  (
    RegExp(r'("(?:token|accessToken|access_token|refreshToken|refresh_token|sessionCookie|cookie|privateKey|'
        r'private_key|private_jwk|secret|client_secret|password|api_key|apiKey|authorization|session_token|'
        r'connection_token|auth_token|credential|d)"\s*:\s*")[^"]*"'),
    (m) => '${_g1(m)}[REDACTED]"'
  ),
  (RegExp(r'((?:set-)?cookie:\s*)[^\r\n]+', caseSensitive: false), (m) => '${_g1(m)}[REDACTED]'),
];

// Email (rule `email`: [A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+) is a linear scan
// here: Dart's backtracking RegExp is quadratic on long runs of local-part characters.
final List<_Rule> _afterEmail = [
  (RegExp(r'''\b[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s"']+''', caseSensitive: false), (_) => '~'),
  (RegExp(r'''(^|[\s"'=(:])/(?:home|Users)/[^/\s"']+'''), (m) => '${_g1(m)}~'),
];

bool _isLocal(int c) =>
    (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || '._%+-'.codeUnits.contains(c);
bool _isLabel(int c) => (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c == 0x2d;

String _redactEmails(String s) {
  if (!s.contains('@')) return s;
  final out = StringBuffer();
  var copied = 0; // everything before this index is already in `out`
  var at = s.indexOf('@');
  while (at >= 0) {
    var start = at;
    while (start > copied && _isLocal(s.codeUnitAt(start - 1))) {
      start--;
    }
    // Domain: label, then one or more ".label"; end after the last complete one.
    var i = at + 1;
    while (i < s.length && _isLabel(s.codeUnitAt(i))) {
      i++;
    }
    var end = -1;
    if (i > at + 1) {
      while (i < s.length && s.codeUnitAt(i) == 0x2e) {
        var j = i + 1;
        while (j < s.length && _isLabel(s.codeUnitAt(j))) {
          j++;
        }
        if (j == i + 1) break;
        end = i = j;
      }
    }
    if (start < at && end > 0) {
      out
        ..write(s.substring(copied, start))
        ..write('[REDACTED EMAIL]');
      copied = end;
      at = s.indexOf('@', end);
    } else {
      at = s.indexOf('@', at + 1);
    }
  }
  out.write(s.substring(copied));
  return out.toString();
}

final _Rule _ipv4 = (
  RegExp(r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}'
      r'(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b'),
  (_) => '[REDACTED IP]'
);

final RegExp _word = RegExp(r'[0-9A-Za-z_:.%]+');
final RegExp _addrChars = RegExp(r'^[0-9A-Fa-f:.]+$');
final RegExp _hexDigit = RegExp(r'[0-9A-Fa-f]');

/// Masks secrets, personal data and addresses in [text]. Idempotent.
String redact(String text) {
  var out = text;
  for (final (re, replace) in _beforeIpv6) {
    out = out.replaceAllMapped(re, replace);
  }
  out = _redactEmails(out);
  for (final (re, replace) in _afterEmail) {
    out = out.replaceAllMapped(re, replace);
  }
  out = out.replaceAllMapped(_word, (m) => _ipv6Word(m.group(0)!));
  return out.replaceAllMapped(_ipv4.$1, _ipv4.$2);
}

String _ipv6Word(String word) {
  late final String addr;
  late final String tail;
  final pct = word.indexOf('%');
  if (pct >= 0) {
    addr = word.substring(0, pct);
    tail = word.substring(pct);
  } else if (word.endsWith('.') || word.endsWith(':')) {
    addr = word.substring(0, word.length - 1);
    tail = word.substring(word.length - 1);
  } else {
    addr = word;
    tail = '';
  }
  final candidate = addr.isNotEmpty &&
      _addrChars.hasMatch(addr) &&
      ':'.allMatches(addr).length >= 2 &&
      _hexDigit.hasMatch(addr);
  if (!candidate) return word;
  try {
    Uri.parseIPv6Address(addr);
    return '[REDACTED IP]$tail';
  } on FormatException {
    return word;
  }
}
