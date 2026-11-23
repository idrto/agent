import 'dart:convert';
import 'dart:io';
import 'dart:ui' show PlatformDispatcher;

import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:idr_telemetry/idr_telemetry.dart';
import 'package:idr_telemetry_flutter/idr_telemetry_flutter.dart';

List<Map<String, Object?>> records(Directory root) {
  final dir = Directory('${root.path}${Platform.pathSeparator}idr_target_app');
  return [
    for (final f in dir.listSync().whereType<File>().where((f) => f.path.endsWith('.jsonl')))
      for (final l in const LineSplitter().convert(f.readAsStringSync())) jsonDecode(l) as Map<String, Object?>,
  ];
}

void main() {
  final binding = TestWidgetsFlutterBinding.ensureInitialized();
  late Directory root;

  setUp(() async {
    root = Directory.systemTemp.createTempSync('idr_tf_');
    await TelemetryFlutter.init(service: 'idr_target_app', serviceVersion: '0.9.0', logRoot: root.path);
  });

  tearDown(() async {
    await Telemetry.shutdown();
    root.deleteSync(recursive: true);
  });

  test('framework errors, lifecycle changes and platform crashes are recorded', () async {
    FlutterError.reportError(FlutterErrorDetails(
      exception: StateError('layout overflow at C:\\Users\\alice\\x'),
      library: 'rendering library',
    ));
    for (final s in [AppLifecycleState.inactive, AppLifecycleState.hidden, AppLifecycleState.paused]) {
      binding.handleAppLifecycleStateChanged(s); // a valid sequence: invalid jumps are framework errors
    }
    PlatformDispatcher.instance.onError!(StateError('engine boom'), StackTrace.current);
    await Telemetry.shutdown();
    // Back to resumed (a paused app schedules no frames, which would break later widget tests).
    for (final s in [AppLifecycleState.hidden, AppLifecycleState.inactive, AppLifecycleState.resumed]) {
      binding.handleAppLifecycleStateChanged(s);
    }

    final all = records(root);
    final fw = all.singleWhere((r) => r['event'] == 'ui.framework.error');
    expect((fw['error'] as Map)['type'], 'flutter_rendering_library');
    expect((fw['error'] as Map)['message'], contains('~\\x'), reason: 'redacted');
    final lifecycle = all.where((r) => r['event'] == 'app.lifecycle.changed').map((r) => (r['attrs'] as Map)['to']).toList();
    expect(lifecycle, ['inactive', 'hidden', 'paused']);
    expect(all.any((r) => r['event'] == 'app.crashed' && r['level'] == 'FATAL'), isTrue);
    final crash = Directory('${root.path}${Platform.pathSeparator}crash').listSync().single as File;
    expect(crash.readAsStringSync(), contains('engine boom'));
  });

  test('a detach writes app.stopping so a normal quit is not reported as unclean', () async {
    binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
    binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
    binding.handleAppLifecycleStateChanged(AppLifecycleState.detached);
    expect(Telemetry.instance, isNull, reason: 'shut down by the detach');
    final all = records(root);
    expect(all.last['event'], 'app.stopping');
    expect(all.map((r) => r['event']), contains('app.lifecycle.changed'));
    binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed); // later tests need frames
  });

  testWidgets('route views are recorded by name only', (tester) async {
    final nav = GlobalKey<NavigatorState>();
    await tester.pumpWidget(WidgetsApp(
      navigatorKey: nav,
      color: const Color(0xFF000000),
      navigatorObservers: [TelemetryFlutter.routeObserver],
      initialRoute: '/home',
      onGenerateRoute: (s) => PageRouteBuilder<void>(
        settings: s,
        pageBuilder: (_, __, ___) => Text('${s.name}', textDirection: TextDirection.ltr),
      ),
    ));
    nav.currentState!.pushNamed('/diagnostics', arguments: {'secret': 'x'});
    await tester.pumpAndSettle();
    await tester.runAsync(Telemetry.shutdown);
    final screens = records(root).where((r) => r['event'] == 'ui.screen.viewed').map((r) => (r['attrs'] as Map)['screen']);
    expect(screens, containsAllInOrder(['/home', '/diagnostics']));
    expect(records(root).any((r) => jsonEncode(r).contains('secret')), isFalse, reason: 'no route arguments');
  });
}
