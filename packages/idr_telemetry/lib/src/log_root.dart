import 'dart:io';

/// Per-OS default log root (docs/observability/04 §1.1): Windows `%LOCALAPPDATA%\IDR\logs`,
/// macOS `~/Library/Logs/IDR`, Linux `$XDG_STATE_HOME/idr/logs` (or `~/.local/state/idr/logs`).
/// `IDR_LOG_DIR` overrides it. Null when no home directory can be determined.
String? defaultLogRoot([Map<String, String>? environment]) {
  final env = environment ?? Platform.environment;
  final override = env['IDR_LOG_DIR'];
  if (override != null && override.isNotEmpty) return override;
  final sep = Platform.pathSeparator;
  String? at(String key) => (env[key] ?? '').isEmpty ? null : env[key];
  if (Platform.isWindows) {
    final base = at('LOCALAPPDATA');
    return base == null ? null : '$base${sep}IDR${sep}logs';
  }
  final home = at('HOME');
  if (Platform.isMacOS) return home == null ? null : '$home/Library/Logs/IDR';
  final state = at('XDG_STATE_HOME') ?? (home == null ? null : '$home/.local/state');
  return state == null ? null : '$state/idr/logs';
}
