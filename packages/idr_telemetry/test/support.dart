import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// All JSONL records under [dir], in file-name then line order.
List<Map<String, Object?>> readRecords(Directory dir) {
  final files = dir.listSync().whereType<File>().where((f) => f.path.endsWith('.jsonl')).toList()
    ..sort((a, b) => a.path.compareTo(b.path));
  return [
    for (final f in files)
      for (final l in const LineSplitter().convert(f.readAsStringSync())) jsonDecode(l) as Map<String, Object?>,
  ];
}

List<Map<String, Object?>> named(List<Map<String, Object?>> all, String event) => all.where((r) => r['event'] == event).toList();

/// A separate process holding the run lock [lockPath] until [release] is called.
Future<Future<void> Function()> holdLockInOtherProcess(String lockPath) async {
  final p = await Process.start(Platform.resolvedExecutable, ['run', 'test/helpers/hold_lock.dart', lockPath]);
  final ready = Completer<void>();
  p.stdout.transform(utf8.decoder).listen((s) {
    if (s.contains('locked') && !ready.isCompleted) ready.complete();
  });
  p.stderr.drain<void>();
  await ready.future.timeout(const Duration(seconds: 60));
  return () async {
    await p.stdin.close();
    await p.exitCode;
  };
}

void touch(File f, String body, {Duration age = Duration.zero}) {
  f
    ..writeAsStringSync(body)
    ..setLastModifiedSync(DateTime.now().subtract(age));
}
