// Holds an exclusive lock on args[0] (a run's .lock file) until stdin closes: simulates
// another live process owning a run (fcntl locks are per process on POSIX).
import 'dart:io';

Future<void> main(List<String> args) async {
  final raf = File(args[0]).openSync(mode: FileMode.append)..lockSync(FileLock.exclusive);
  stdout.writeln('locked');
  await stdin.drain<void>();
  raf.closeSync();
}
