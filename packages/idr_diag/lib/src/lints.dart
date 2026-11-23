// Telemetry CI lints (docs/observability/07 §3). Scope comes from spec/telemetry/lint.yaml
// so each package is gated as it migrates.

import 'dart:io';

import 'package:yaml/yaml.dart';

import 'registry.dart';

class Finding {
  Finding(this.rule, this.path, this.line, this.message);
  final String rule;
  final String path;
  final int line;
  final String message;
  @override
  String toString() => '$path:$line [$rule] $message';
}

class LintConfig {
  LintConfig(this.repo, Map<String, Object?> y)
      : eventPaths = _list(y['event_names']),
        bannedDart = _list((y['banned_apis'] as Map?)?['dart']),
        bannedRust = _list((y['banned_apis'] as Map?)?['rust']),
        secretPaths = _list(y['secrets_debug']),
        secretAllow = _list(y['secrets_debug_allow']).toSet(),
        subscriberAllowed = _list(y['tracing_subscriber_allowed']).toSet(),
        dpSdk = y['dp_sdk_root'] as String?;

  factory LintConfig.load(String repo) =>
      LintConfig(repo, _plain(loadYaml(File('$repo/spec/telemetry/lint.yaml').readAsStringSync())) as Map<String, Object?>);

  final String repo;
  final List<String> eventPaths;
  final List<String> bannedDart;
  final List<String> bannedRust;
  final List<String> secretPaths;
  final Set<String> secretAllow;
  final Set<String> subscriberAllowed;
  final String? dpSdk;

  static List<String> _list(Object? v) => v is List ? v.map((e) => '$e').toList() : const [];
  static Object? _plain(Object? y) => switch (y) {
        YamlMap() => {for (final e in y.entries) '${e.key}': _plain(e.value)},
        YamlList() => [for (final x in y) _plain(x)],
        _ => y,
      };
}

Iterable<File> _sources(String repo, List<String> roots, String ext) sync* {
  for (final r in roots) {
    final path = '$repo/$r';
    if (FileSystemEntity.isFileSync(path)) {
      yield File(path);
      continue;
    }
    if (!FileSystemEntity.isDirectorySync(path)) continue;
    for (final f in Directory(path).listSync(recursive: true).whereType<File>()) {
      final p = f.path.replaceAll('\\', '/');
      if (!p.endsWith(ext) || p.contains('/target/') || p.contains('/.dart_tool/') || p.contains('/build/')) continue;
      yield f;
    }
  }
}

String _rel(String repo, File f) => f.path.replaceAll('\\', '/').replaceFirst('${repo.replaceAll('\\', '/')}/', '');

bool _allowed(String line) => line.contains('idr-lint: allow');

// Event/span names at call sites. Dart: log.info('x.y', …), .span('x.y', …), Record(…, 'x.y').
// Rust: event = "x.y", info_span!("x.y", …), record(…, "x.y"), Record::new(…, "x.y").
final _dartEvent = RegExp(r'''\.(?:trace|debug|info|warn|error|span|spanSync)\(\s*'([a-z][a-z0-9_.]*)'|(?:_record|make|Record)\([^)]*?'([a-z][a-z0-9_]*\.[a-z0-9_.]+)'\)''');
final _rustEvent = RegExp(r'''event\s*=\s*"([^"]+)"|_span!\(\s*(?:[a-z:]+\s*=\s*[^,]+,\s*)*"([^"]+)"|(?:record|Record::new|make_record)\([^)]*?"([a-z][a-z0-9_]*\.[a-z0-9_.]+)"\)''');
// Attribute keys: Dart `attrs: {'k.v': …}` entries; Rust macro fields `k.v = …` inside log macros.
final _dartAttrMap = RegExp(r'''attrs:\s*\{([^}]*)\}''');
final _dartAttrKey = RegExp(r"""'([a-z][a-z0-9_.]*)'\s*:""");
final _rustMacro = RegExp(r'''(?:trace|debug|info|warn|error)(?:_span)?!\(([^;]*?)\);''', dotAll: true);
final _rustField = RegExp(r'''(?:^|[,(]\s*)([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*)\s*=\s*[^=]''');
const _rustSpecialFields = {'event', 'message', 'target', 'parent', 'name', 'session_id', 'connection_id', 'transfer_id',
  'operation_id', 'report_id', 'traceparent', 'link', 'persist_start', 'status', 'error.type', 'error.message',
  'error.stack', 'error.code', 'error'};
const _dartSpecialKeys = {'session_id', 'connection_id', 'transfer_id', 'operation_id', 'report_id'};

List<Finding> lintEventNames(Registry reg, LintConfig cfg) {
  final out = <Finding>[];
  void check(String path, int line, String name) {
    if (!Registry.namePattern.hasMatch(name)) {
      out.add(Finding('event-name', path, line, '"$name" does not match <domain>.<object>.<action>'));
    } else if (!reg.hasDomain(name)) {
      out.add(Finding('event-domain', path, line, '"$name" uses an unregistered domain'));
    } else if (!reg.isRegistered(name)) {
      out.add(Finding('event-registry', path, line, '"$name" is not in spec/telemetry/events.yaml'));
    }
  }

  void attr(String path, int line, String key) {
    if (!reg.attributes.containsKey(key)) {
      out.add(Finding('attr-registry', path, line, '"$key" is not in spec/telemetry/attributes.yaml'));
    }
  }

  for (final f in _sources(cfg.repo, cfg.eventPaths, '.dart')) {
    final rel = _rel(cfg.repo, f);
    final text = f.readAsStringSync();
    final lines = text.split('\n');
    for (var i = 0; i < lines.length; i++) {
      if (_allowed(lines[i])) continue;
      for (final m in _dartEvent.allMatches(lines[i])) {
        final name = m.group(1) ?? m.group(2)!;
        if (name.contains('.')) check(rel, i + 1, name);
      }
    }
    for (final m in _dartAttrMap.allMatches(text)) {
      final line = text.substring(0, m.start).split('\n').length;
      if (_allowed(lines[line - 1])) continue;
      for (final k in _dartAttrKey.allMatches(m.group(1)!)) {
        if (!_dartSpecialKeys.contains(k.group(1))) attr(rel, line, k.group(1)!);
      }
    }
  }
  for (final f in _sources(cfg.repo, cfg.eventPaths, '.rs')) {
    final rel = _rel(cfg.repo, f);
    final text = f.readAsStringSync();
    final lines = text.split('\n');
    for (var i = 0; i < lines.length; i++) {
      if (_allowed(lines[i])) continue;
      for (final m in _rustEvent.allMatches(lines[i])) {
        check(rel, i + 1, m.group(1) ?? m.group(2) ?? m.group(3)!);
      }
    }
    for (final m in _rustMacro.allMatches(text)) {
      final line = text.substring(0, m.start).split('\n').length;
      if (_allowed(lines[line - 1])) continue;
      final body = m.group(1)!.replaceAll(RegExp(r'"(?:[^"\\]|\\.)*"'), '""'); // ignore string contents
      for (final k in _rustField.allMatches(body)) {
        final key = k.group(1)!;
        if (!_rustSpecialFields.contains(key)) attr(rel, line, key);
      }
    }
  }
  return out;
}

final _dartBanned = RegExp(r'''(?<![\w.])(?:print|debugPrint)\(|developer\.log\(|\bstderr\.write(?:ln)?\(''');
final _rustBanned = RegExp(r'''\b(?:println|eprintln|print|eprint|dbg)!\(''');

/// print/debugPrint/developer.log/stderr in Dart lib code; println!/eprintln!/dbg! in Rust
/// library code (not src/bin, not tests, not examples).
List<Finding> lintBannedApis(LintConfig cfg) {
  final out = <Finding>[];
  void scan(Iterable<File> files, RegExp re, String rule, bool Function(String rel) skip) {
    for (final f in files) {
      final rel = _rel(cfg.repo, f);
      if (skip(rel)) continue;
      final lines = f.readAsLinesSync();
      var inTests = false;
      for (var i = 0; i < lines.length; i++) {
        final l = lines[i];
        if (l.contains('#[cfg(test)]')) inTests = true; // rest of file is the test module
        if (inTests || _allowed(l) || l.trimLeft().startsWith('//')) continue;
        if (re.hasMatch(l)) out.add(Finding(rule, rel, i + 1, 'banned API: ${l.trim()}'));
      }
    }
  }

  scan(_sources(cfg.repo, cfg.bannedDart, '.dart'), _dartBanned, 'banned-dart',
      (rel) => rel.contains('/bin/') || rel.contains('/test/') || rel.contains('/example/') || rel.contains('/tool/'));
  scan(_sources(cfg.repo, cfg.bannedRust, '.rs'), _rustBanned, 'banned-rust',
      (rel) => rel.contains('/src/bin/') || rel.contains('/tests/') || rel.contains('/examples/') || rel.contains('/benches/') || rel.endsWith('/main.rs'));
  return out;
}

final _deriveDebug = RegExp(r'#\[derive\([^)]*\bDebug\b[^)]*\)\]');
final _structStart = RegExp(r'^\s*pub(?:\([^)]*\))?\s+struct\s+(\w+)|^\s*struct\s+(\w+)');
final _secretField = RegExp(r'^\s*(?:pub(?:\([^)]*\))?\s+)?(\w*(?:key|token|secret|password|credential|private)\w*)\s*:\s*([^,]+),', caseSensitive: false);

/// `derive(Debug)` on structs with secret-looking fields that are not `Secret<…>` (R-PRIV-1).
List<Finding> lintSecretDebug(LintConfig cfg) {
  final out = <Finding>[];
  for (final f in _sources(cfg.repo, cfg.secretPaths, '.rs')) {
    final rel = _rel(cfg.repo, f);
    final lines = f.readAsLinesSync();
    for (var i = 0; i < lines.length; i++) {
      if (!_deriveDebug.hasMatch(lines[i])) continue;
      var j = i + 1;
      while (j < lines.length && lines[j].trimLeft().startsWith('#[')) {
        j++;
      }
      final m = j < lines.length ? _structStart.firstMatch(lines[j]) : null;
      if (m == null) continue;
      final name = m.group(1) ?? m.group(2)!;
      if (cfg.secretAllow.contains('$rel::$name')) continue;
      for (var k = j + 1; k < lines.length && !lines[k].startsWith('}'); k++) {
        final fm = _secretField.firstMatch(lines[k]);
        if (fm == null) continue;
        final field = fm.group(1)!.toLowerCase();
        final type = fm.group(2)!.trim();
        // Only raw content types can carry secret bytes; enums, bools and signed public
        // structures (e.g. CapabilityCredential) cannot. Ids, public keys and metadata are not secrets.
        final raw = RegExp(r'^(Option<)?(String|Vec<u8>|(serde_json::)?Value|PrivateKeyDer|Zeroizing|Bytes|\[u8;)').hasMatch(type);
        final metadata = RegExp(r'public|_id$|ski|_kind$|_type$|_mode$|_algo$|_len$|_path$|algorithm|^deny_').hasMatch(field);
        if (type.contains('Secret<') || !raw || metadata) continue;
        out.add(Finding('secret-debug', rel, i + 1, '$name derives Debug but field "${fm.group(1)}: ${type.trim()}" looks secret; '
            'use Secret<T> or a redacting Debug (07 R-PRIV-1)'));
      }
    }
  }
  return out;
}

/// dp-sdk crates never depend on tracing/log/idr-telemetry; only allow-listed crates depend
/// on tracing-subscriber (07 §3).
List<Finding> lintDependencies(LintConfig cfg) {
  final out = <Finding>[];
  Iterable<File> manifests(String root) sync* {
    final d = Directory(root);
    if (!d.existsSync()) return;
    for (final f in d.listSync(recursive: true).whereType<File>()) {
      final p = f.path.replaceAll('\\', '/');
      if (p.endsWith('/Cargo.toml') && !p.contains('/target/')) yield f;
    }
  }

  String? crateName(String toml) => RegExp(r'^\[package\][^\[]*?^name\s*=\s*"([^"]+)"', multiLine: true).firstMatch(toml)?.group(1);
  bool depends(String toml, String dep) => RegExp('^\\s*$dep\\s*=', multiLine: true).hasMatch(toml);

  for (final f in manifests(cfg.repo)) {
    final toml = f.readAsStringSync();
    final name = crateName(toml);
    if (name == null) continue;
    if (depends(toml, 'tracing-subscriber') && !cfg.subscriberAllowed.contains(name)) {
      out.add(Finding('subscriber-dep', _rel(cfg.repo, f), 1, '$name depends on tracing-subscriber; only composition points may (07 R-LIB-2)'));
    }
  }
  if (cfg.dpSdk != null) {
    final root = '${cfg.repo}/${cfg.dpSdk}';
    for (final f in manifests(root)) {
      final toml = f.readAsStringSync();
      final name = crateName(toml);
      if (name == null) continue;
      for (final dep in ['tracing', 'log', 'idr-telemetry']) {
        if (depends(toml, dep)) out.add(Finding('dp-sdk-purity', f.path, 1, '$name depends on $dep; dp-sdk never logs (07 R-PRIV-4)'));
      }
    }
  }
  return out;
}
