/// Flutter hooks for `idr_telemetry` (docs/observability/01 §2.5). No UI widgets: the
/// "Report a problem" screen belongs to the app and uses `DiagnosticBundle`.
///
/// ```dart
/// Future<void> main() async {
///   WidgetsFlutterBinding.ensureInitialized();
///   await TelemetryFlutter.init(service: 'idr_target_app', serviceVersion: appVersion);
///   runGuarded(() => runApp(MyApp(navigatorObservers: [TelemetryFlutter.routeObserver])));
/// }
/// ```
library;

import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:idr_telemetry/idr_telemetry.dart' hide defaultLogRoot;
import 'package:idr_telemetry/idr_telemetry.dart' as idr show defaultLogRoot;
import 'package:path_provider/path_provider.dart';

const _log = IdrLog('idr_telemetry_flutter');

class TelemetryFlutter {
  TelemetryFlutter._();

  static bool _installed = false;
  static AppLifecycleListener? _lifecycle;
  static AppLifecycleState? _lastState;

  /// Records `ui.screen.viewed` with the route name (never route arguments).
  static final NavigatorObserver routeObserver = _RouteObserver();

  /// [Telemetry.init] with the platform log root (`<app support>/logs`, or `IDR_LOG_DIR`
  /// when set), then [install].
  static Future<Telemetry> init({
    required String service,
    required String serviceVersion,
    String? filter,
    String? logRoot,
    Level? stderrLevel,
  }) async {
    final root = logRoot ?? Platform.environment['IDR_LOG_DIR'] ?? await defaultLogRoot();
    final t = await Telemetry.init(TelemetryConfig(
      service: service,
      serviceVersion: serviceVersion,
      logRoot: root,
      filter: filter ?? Platform.environment['IDR_LOG'] ?? 'info',
      // Debug runs also print to the `flutter run` console; release builds write files only.
      stderrLevel: stderrLevel ?? (kDebugMode ? Level.info : null),
    ));
    install();
    return t;
  }

  /// The shared per-OS log root (Windows `%LOCALAPPDATA%\idr.to\logs`), so app, CLIs and agent
  /// write side by side; the application-support dir is only the fallback.
  static Future<String> defaultLogRoot() async {
    final shared = idr.defaultLogRoot();
    if (shared != null) return shared;
    final dir = await getApplicationSupportDirectory();
    return "${dir.path}${Platform.pathSeparator}logs";
  }

  /// Wires framework errors, uncaught platform errors and app lifecycle into telemetry.
  /// Requires an initialized [Telemetry] and a Flutter binding.
  /// Idempotent: a second call (hot restart, re-init) does not chain onto its own handlers.
  static void install() {
    if (!_installed) {
      _installed = true;
      final previousFlutter = FlutterError.onError;
      FlutterError.onError = (details) {
        _onFlutterError(details);
        previousFlutter?.call(details);
      };
      final previousPlatform = PlatformDispatcher.instance.onError;
      PlatformDispatcher.instance.onError = (error, stack) {
        Telemetry.instance?.recordCrash(error, stack, source: 'platform');
        return previousPlatform?.call(error, stack) ?? true;
      };
    }
    _lifecycle?.dispose();
    _lastState = null;
    _lifecycle = AppLifecycleListener(onStateChange: _onState);
  }

  static void _onFlutterError(FlutterErrorDetails d) {
    // Framework errors are not fatal (the widget shows an error box); fatal ones reach
    // PlatformDispatcher.onError / runGuarded as crash records.
    _log.error('ui.framework.error',
        errorType: 'flutter_${d.library?.replaceAll(RegExp('[^a-z0-9]+'), '_') ?? 'framework'}',
        error: d.exception,
        stack: d.stack,
        attrs: {'context': d.context?.toDescription() ?? ''});
  }

  static void _onState(AppLifecycleState s) {
    _log.info('app.lifecycle.changed', attrs: {'from': _lastState?.name ?? 'none', 'to': s.name});
    _lastState = s;
    // A Flutter app has no `finally` around its lifetime: without this every normal quit
    // would lack `app.stopping` and be reported as an unclean exit (04 §3.3).
    if (s == AppLifecycleState.detached) Telemetry.shutdown();
  }
}

class _RouteObserver extends NavigatorObserver {
  void _viewed(Route<dynamic>? r) {
    final name = r?.settings.name;
    if (name != null) _log.info('ui.screen.viewed', attrs: {'screen': name});
  }

  @override
  void didPush(Route<dynamic> route, Route<dynamic>? previousRoute) => _viewed(route);

  @override
  void didPop(Route<dynamic> route, Route<dynamic>? previousRoute) => _viewed(previousRoute);

  @override
  void didReplace({Route<dynamic>? newRoute, Route<dynamic>? oldRoute}) => _viewed(newRoute);
}
