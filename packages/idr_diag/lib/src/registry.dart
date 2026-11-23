// spec/telemetry registries: events.yaml and attributes.yaml.

import 'dart:convert';
import 'dart:io';

import 'package:yaml/yaml.dart';

import 'schema.dart';

class Registry {
  Registry._(this.events, this.persistStart, this.domains, this.attributes, this.schema);

  final Map<String, Map<String, Object?>> events;
  final Set<String> persistStart;
  final Set<String> domains;
  final Map<String, Map<String, Object?>> attributes;
  final SchemaValidator schema;

  static final RegExp namePattern = RegExp(r'^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,4}$');

  /// Loads from `<repo>/spec/telemetry`.
  factory Registry.load(String repo) {
    final dir = '$repo${Platform.pathSeparator}spec${Platform.pathSeparator}telemetry${Platform.pathSeparator}';
    Map<String, Object?> yaml(String f) => _plain(loadYaml(File('$dir$f').readAsStringSync())) as Map<String, Object?>;
    final ev = yaml('events.yaml');
    final at = yaml('attributes.yaml');
    final events = (ev['events'] as Map<String, Object?>).map((k, v) => MapEntry(k, v as Map<String, Object?>));
    final schema = jsonDecode(File('${dir}log-record.schema.json').readAsStringSync()) as Map<String, Object?>;
    return Registry._(
      events,
      {for (final e in events.entries) if (e.value['persist_start'] == true) e.key},
      (ev['domains'] as List).cast<String>().toSet(),
      (at['attributes'] as Map<String, Object?>).map((k, v) => MapEntry(k, v as Map<String, Object?>)),
      SchemaValidator(schema),
    );
  }

  /// Registered event/span name, or `<persist_start span>.started`.
  bool isRegistered(String name) {
    if (events.containsKey(name)) return true;
    if (name.endsWith('.started')) return persistStart.contains(name.substring(0, name.length - '.started'.length));
    return false;
  }

  bool hasDomain(String name) => domains.contains(name.split('.').first);

  static Object? _plain(Object? y) => switch (y) {
        YamlMap() => {for (final e in y.entries) '${e.key}': _plain(e.value)},
        YamlList() => [for (final x in y) _plain(x)],
        _ => y,
      };
}
