// Local diagnostic bundle (V1): drain, collect the window, re-redact, index IDs, zip.
// Nothing is uploaded (04 §4.1–4.2).

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'ids.dart';
import 'record.dart';
import 'redact.dart';
import 'telemetry.dart';

class DiagnosticBundle {
  DiagnosticBundle._(this.reportId, this.file, this.manifest);

  final String reportId;
  final File file;
  final Map<String, Object?> manifest;

  /// Builds `<logRoot>/reports/<report_id>.zip` from the last [window] of every service in
  /// the log root (GUI, CLI, in-process Rust, spawned agents) plus crash records.
  /// [state] and [doctor] are caller-provided summaries; their strings are redacted.
  static Future<DiagnosticBundle> collect({
    Duration window = const Duration(hours: 2),
    String? userNote,
    Map<String, Object?>? state,
    Map<String, Object?>? doctor,
  }) async {
    final t = Telemetry.instance;
    final root = t?.logRoot;
    if (t == null || root == null) throw StateError('Telemetry with a log root is required');
    await Telemetry.flush();
    final reportId = newId();
    final now = DateTime.now().toUtc();
    final from = now.subtract(window);
    final fromTs = formatTs(from);
    final entries = <String, List<int>>{};
    final ids = <String, Set<String>>{
      for (final k in ['app_session_id', 'session_id', 'connection_id', 'transfer_id', 'operation_id', 'trace_id']) k: {},
    };
    final sep = Platform.pathSeparator;

    for (final dir in Directory(root).listSync().whereType<Directory>()) {
      final service = dir.uri.pathSegments.where((s) => s.isNotEmpty).last;
      if (service == 'crash' || service == 'reports') continue;
      for (final f in dir.listSync().whereType<File>()) {
        final name = f.uri.pathSegments.last;
        if (!name.endsWith('.jsonl') || f.lastModifiedSync().isBefore(from)) continue;
        final out = StringBuffer();
        for (final line in const LineSplitter().convert(f.readAsStringSync())) {
          final Map<String, Object?> j;
          try {
            j = jsonDecode(line) as Map<String, Object?>;
          } on Object {
            continue; // partial line
          }
          if ((j['ts'] as String? ?? '').compareTo(fromTs) < 0) continue;
          for (final k in ids.keys) {
            final v = j[k];
            if (v is String) ids[k]!.add(v);
          }
          // Re-redact with the current rules (04 §4.2), keeping the writer tail fields.
          final r = recordFromJson(j)..redactInPlace();
          r.seq = (j['seq'] as num?)?.toInt() ?? 0;
          out.writeln(withTail(r.toLine(), (j['dropped'] as num?)?.toInt() ?? 0, j['flushed'] == true));
        }
        if (out.isNotEmpty) entries['logs/$service/$name'] = utf8.encode(out.toString());
      }
    }
    final crashDir = Directory('$root${sep}crash');
    if (crashDir.existsSync()) {
      for (final f in crashDir.listSync().whereType<File>()) {
        if (f.lastModifiedSync().isBefore(from)) continue;
        entries['crash/${f.uri.pathSegments.last}'] = utf8.encode(redact(f.readAsStringSync()));
      }
    }
    if (state != null) entries['state/summary.json'] = utf8.encode(jsonEncode(_redactTree(state)));
    if (doctor != null) entries['checks/doctor.json'] = utf8.encode(jsonEncode(_redactTree(doctor)));
    final manifest = <String, Object?>{
      'report_id': reportId,
      'created_at': formatTs(now),
      if (userNote != null) 'user_note': redact(userNote),
      'service': t.config.service,
      'service_version': t.config.serviceVersion,
      'os': '${Platform.operatingSystem} ${Platform.operatingSystemVersion}',
      'window': {'from': fromTs, 'to': formatTs(now)},
      'ids': {for (final e in ids.entries) e.key: e.value.toList()..sort()},
      'redaction_version': 1,
      'files': {for (final e in entries.entries) e.key: {'bytes': e.value.length, 'crc32': _crc32(e.value).toRadixString(16)}},
    };
    entries['manifest.json'] = utf8.encode(const JsonEncoder.withIndent('  ').convert(manifest));

    final reports = Directory('$root${sep}reports')..createSync(recursive: true);
    final file = File('${reports.path}$sep$reportId.zip')..writeAsBytesSync(_zip(entries), flush: true);
    _keepNewest(reports, 5);
    const IdrLog('idr_telemetry.bundle')
        .info('diag.bundle.created', attrs: {'bytes': file.lengthSync(), 'window_s': window.inSeconds, 'report_id': reportId});
    return DiagnosticBundle._(reportId, file, manifest);
  }
}

Object? _redactTree(Object? v) => switch (v) {
      String() => redact(v),
      Map() => {for (final e in v.entries) '${e.key}': _redactTree(e.value)},
      List() => [for (final x in v) _redactTree(x)],
      _ => v,
    };

void _keepNewest(Directory dir, int n) {
  final zips = dir.listSync().whereType<File>().where((f) => f.path.endsWith('.zip')).toList()
    ..sort((a, b) => b.lastModifiedSync().compareTo(a.lastModifiedSync()));
  for (final f in zips.skip(n)) {
    try {
      f.deleteSync();
    } on FileSystemException {
      // in use
    }
  }
}

// ---------------------------------------------------------------------------- zip

final Uint32List _crcTable = () {
  final t = Uint32List(256);
  for (var n = 0; n < 256; n++) {
    var c = n;
    for (var k = 0; k < 8; k++) {
      c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
    }
    t[n] = c;
  }
  return t;
}();

int _crc32(List<int> data) {
  var c = 0xFFFFFFFF;
  for (final b in data) {
    c = _crcTable[(c ^ b) & 0xff] ^ (c >> 8);
  }
  return c ^ 0xFFFFFFFF;
}

/// Minimal zip (deflate, no zip64; bundles are capped well below 4 GiB).
List<int> _zip(Map<String, List<int>> files) {
  final out = BytesBuilder();
  final central = BytesBuilder();
  final deflate = ZLibCodec(raw: true);
  var count = 0;
  void u16(BytesBuilder b, int v) => b.add([v & 0xff, (v >> 8) & 0xff]);
  void u32(BytesBuilder b, int v) => b.add([v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff]);
  files.forEach((name, data) {
    final nameBytes = utf8.encode(name);
    final packed = deflate.encode(data);
    final crc = _crc32(data);
    final offset = out.length;
    for (final (b, central_) in [(out, false), (central, true)]) {
      u32(b, central_ ? 0x02014b50 : 0x04034b50);
      if (central_) u16(b, 20); // version made by
      u16(b, 20); // version needed
      u16(b, 0x0800); // UTF-8 names
      u16(b, 8); // deflate
      u16(b, 0);
      u16(b, 0x21); // DOS time/date (1980-01-01): bundles carry real times in manifest
      u32(b, crc);
      u32(b, packed.length);
      u32(b, data.length);
      u16(b, nameBytes.length);
      u16(b, 0);
      if (central_) {
        u16(b, 0); // comment
        u16(b, 0); // disk
        u16(b, 0); // internal attrs
        u32(b, 0); // external attrs
        u32(b, offset);
      }
      b.add(nameBytes);
      if (!central_) b.add(packed);
    }
    count++;
  });
  final cdOffset = out.length;
  final cd = central.takeBytes();
  out.add(cd);
  u32(out, 0x06054b50);
  u16(out, 0);
  u16(out, 0);
  u16(out, count);
  u16(out, count);
  u32(out, cd.length);
  u32(out, cdOffset);
  u16(out, 0);
  return out.takeBytes();
}
