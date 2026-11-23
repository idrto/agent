// idr_diag — validate/merge/tree/open idr.log/1 files and run the telemetry CI lints.
//
//   idr_diag validate <files|dirs|bundle.zip>...      schema + registry + redaction
//   idr_diag merge [--id <id>] <paths>...             one ordered timeline across processes
//   idr_diag tree --trace <trace_id> <paths>...       span tree of one trace
//   idr_diag open <bundle.zip>                        bundle summary
//   idr_diag lint [--only events,banned,secrets,deps] CI gates (scope: spec/telemetry/lint.yaml)
//
// --repo <agent repo root> (default: current directory). Exit 1 when anything is found.

import 'dart:io';

import 'package:args/args.dart';
import 'package:idr_diag/idr_diag.dart';

Future<void> main(List<String> argv) async {
  final parser = ArgParser()
    ..addOption('repo', defaultsTo: '.')
    ..addOption('id')
    ..addOption('trace')
    ..addOption('only', defaultsTo: 'events,banned,secrets,deps')
    ..addFlag('help', abbr: 'h', negatable: false);
  final ArgResults a;
  try {
    a = parser.parse(argv);
  } on FormatException catch (e) {
    stderr.writeln('${e.message}\n${parser.usage}');
    exit(64);
  }
  if (a['help'] as bool || a.rest.isEmpty) {
    stdout.writeln('usage: idr_diag <validate|merge|tree|open|lint> [options] [paths]\n${parser.usage}');
    exit(a.rest.isEmpty ? 64 : 0);
  }
  final repo = a['repo'] as String;
  final cmd = a.rest.first;
  final paths = a.rest.skip(1).toList();
  switch (cmd) {
    case 'validate':
      final read = readAll(paths);
      final problems = [...read.badLines, ...validateRecords(Registry.load(repo), read.records)];
      problems.forEach(stdout.writeln);
      stdout.writeln('${read.records.length} records, ${problems.length} problems');
      exit(problems.isEmpty ? 0 : 1);
    case 'merge':
      for (final r in merge(readAll(paths).records, id: a['id'] as String?)) {
        stdout.writeln(oneLine(r));
      }
    case 'tree':
      final trace = a['trace'] as String?;
      if (trace == null) {
        stderr.writeln('--trace is required');
        exit(64);
      }
      stdout.write(renderTree(readAll(paths).records, trace));
    case 'open':
      stdout.write(summarizeBundle(paths.single));
    case 'lint':
      final only = (a['only'] as String).split(',').toSet();
      final cfg = LintConfig.load(repo);
      final findings = [
        if (only.contains('events')) ...lintEventNames(Registry.load(repo), cfg),
        if (only.contains('banned')) ...lintBannedApis(cfg),
        if (only.contains('secrets')) ...lintSecretDebug(cfg),
        if (only.contains('deps')) ...lintDependencies(cfg),
      ];
      findings.forEach(stdout.writeln);
      stdout.writeln('${findings.length} findings');
      exit(findings.isEmpty ? 0 : 1);
    default:
      stderr.writeln('unknown command "$cmd"\n${parser.usage}');
      exit(64);
  }
}
