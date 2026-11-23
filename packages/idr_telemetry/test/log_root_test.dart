import 'dart:io';

import 'package:idr_telemetry/idr_telemetry.dart';
import 'package:test/test.dart';

void main() {
  test('IDR_LOG_DIR overrides the per-OS default', () {
    expect(defaultLogRoot({'IDR_LOG_DIR': '/custom/logs', 'HOME': '/h'}), '/custom/logs');
  });

  test('the per-OS default sits under the user profile, never the working directory', () {
    final env = Platform.isWindows
        ? {'LOCALAPPDATA': r'C:\Users\u\AppData\Local'}
        : {'HOME': '/home/u'};
    final root = defaultLogRoot(env)!;
    expect(root, contains(Platform.isWindows ? 'idr.to' : (Platform.isMacOS ? 'IDR' : 'idr')));
    expect(root, anyOf(startsWith(r'C:\Users\u'), startsWith('/home/u')));
  });

  test('no home directory means no files, not a crash', () {
    expect(defaultLogRoot(<String, String>{}), isNull);
  });
}
