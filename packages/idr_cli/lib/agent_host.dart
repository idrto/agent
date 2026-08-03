import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:idr_secure_storage/idr_secure_storage.dart';
import 'package:path/path.dart' as p;

/// Locates and drives the native `target-agent` / `source-agent` CLI.
class AgentHost {
  AgentHost({
    required this.store,
    String? agentBinary,
    String? configPath,
    String? identityPath,
  })  : agentBinary = agentBinary ?? _defaultBinaryHint(),
        configPath = configPath ?? _defaultConfigHint(),
        identityPath = identityPath ?? _defaultIdentityHint();

  final DpSecretStore store;

  String agentBinary;
  String configPath;
  String identityPath;

  Process? _running;
  final _logController = StreamController<String>.broadcast();

  Stream<String> get logs => _logController.stream;
  bool get isRunning => _running != null;

  static String _defaultBinaryHint() {
    const fromDefine = String.fromEnvironment('IDR_AGENT_BINARY');
    if (fromDefine.isNotEmpty) return fromDefine;
    final fromEnv = Platform.environment['IDR_AGENT_BINARY'];
    if (fromEnv != null && fromEnv.isNotEmpty) return fromEnv;
    final name = Platform.isWindows ? 'target-agent.exe' : 'target-agent';
    return p.normalize(p.join('..', '..', 'target', 'debug', name));
  }

  static String _defaultConfigHint() {
    const fromDefine = String.fromEnvironment('IDR_TARGET_CONFIG');
    if (fromDefine.isNotEmpty) return fromDefine;
    final fromEnv = Platform.environment['IDR_TARGET_CONFIG'];
    if (fromEnv != null && fromEnv.isNotEmpty) return fromEnv;
    return p.normalize(p.join('..', '..', 'config', 'target.local.toml'));
  }

  static String _defaultIdentityHint() {
    const fromDefine = String.fromEnvironment('IDR_IDENTITY');
    if (fromDefine.isNotEmpty) return fromDefine;
    final fromEnv = Platform.environment['IDR_IDENTITY'];
    if (fromEnv != null && fromEnv.isNotEmpty) return fromEnv;
    return 'identity.dp.json';
  }

  /// Prefer an existing binary among common monorepo / env locations.
  Future<String?> detectBinary() async {
    final name = Platform.isWindows ? 'target-agent.exe' : 'target-agent';
    final candidates = <String>[
      if (Platform.environment['IDR_AGENT_BINARY'] case final e?
          when e.isNotEmpty)
        e,
      agentBinary,
      p.join('..', '..', 'target', 'debug', name),
      p.join('..', '..', 'target', 'release', name),
      p.join('target', 'debug', name),
      p.join('target', 'release', name),
      name,
    ].map(p.normalize).toSet();

    for (final c in candidates) {
      if (await File(c).exists()) {
        agentBinary = c;
        return c;
      }
    }
    return null;
  }

  Future<bool> ensureConfigExists() async {
    final local = File(configPath);
    if (await local.exists()) return true;
    final example = File(
      p.normalize(p.join('..', '..', 'config', 'target.example.toml')),
    );
    if (!await example.exists()) {
      _log('config missing: $configPath (and no target.example.toml)');
      return false;
    }
    await local.parent.create(recursive: true);
    await example.copy(local.path);
    _log('created $configPath from target.example.toml');
    return true;
  }

  void _log(String line) {
    if (!_logController.isClosed) {
      _logController.add(line);
    }
  }

  Future<int> runCli(
    List<String> args, {
    bool attachIdentityFlag = true,
  }) async {
    final binary = await detectBinary();
    if (binary == null) {
      _log(
        'error: target-agent binary not found. Build it first:\n'
        '  cargo build -p target-agent\n'
        'Or set IDR_AGENT_BINARY / --dart-define=IDR_AGENT_BINARY=...',
      );
      return 127;
    }

    final fullArgs = <String>[];
    if (await File(configPath).exists()) {
      fullArgs.addAll(['--config', configPath]);
    }
    if (attachIdentityFlag && await File(identityPath).exists()) {
      fullArgs.addAll(['--identity', identityPath]);
    }
    fullArgs.addAll(args);

    _log('\$ $binary ${fullArgs.join(' ')}');
    final result = await Process.run(binary, fullArgs, runInShell: false);
    final out = result.stdout as String;
    final err = result.stderr as String;
    if (out.isNotEmpty) {
      for (final line in const LineSplitter().convert(out)) {
        _log(line);
      }
    }
    if (err.isNotEmpty) {
      for (final line in const LineSplitter().convert(err)) {
        _log(line);
      }
    }
    if (result.exitCode != 0) {
      _log('exit ${result.exitCode}');
    }
    return result.exitCode;
  }

  Future<int> doctor() => runCli(const ['doctor']);

  Future<int> version() => runCli(const ['version'], attachIdentityFlag: false);

  Future<int> identityInit({
    required String host,
    String role = 'target',
    String? entity,
  }) {
    final args = <String>[
      'identity',
      'init',
      '--role',
      role,
      '--host',
      host,
    ];
    if (entity != null && entity.isNotEmpty) {
      args.addAll(['--entity', entity]);
    }
    return runCli(args);
  }

  /// Write secure-storage identity to [identityPath] for the native agent.
  Future<bool> exportIdentityToFile() async {
    final id = await store.loadIdentity();
    if (id == null) {
      _log('no identity in secure storage to export');
      return false;
    }
    final file = File(identityPath);
    await file.parent.create(recursive: true);
    await file.writeAsString(
      const JsonEncoder.withIndent('  ').convert(id.toNativeJson()),
    );
    _log('exported ski=${id.ski} → ${file.path}');
    return true;
  }

  Future<bool> importIdentityFromFile({String? path}) async {
    final file = File(path ?? identityPath);
    if (!await file.exists()) {
      _log('identity file missing: ${file.path}');
      return false;
    }
    final map = jsonDecode(await file.readAsString()) as Map<String, dynamic>;
    await store.saveIdentity(
      ski: map['ski'] as String,
      privateJwk: map['private_jwk'] as Map<String, dynamic>,
      credential: map['credential'] as Map<String, dynamic>,
      publicJwk: map['public_jwk'] as Map<String, dynamic>?,
      fqhn: map['fqhn'] as String?,
      certPem: map['cert_pem'] as String?,
      chainPem: map['chain_pem'] as String?,
    );
    _log('imported ski=${map['ski']} into secure storage from ${file.path}');
    return true;
  }

  /// Start `target-agent run` (Presence/Relay service). Streams logs.
  Future<void> startTargetService() async {
    if (_running != null) {
      _log('already running (pid ${_running!.pid})');
      return;
    }
    await ensureConfigExists();
    final binary = await detectBinary();
    if (binary == null) {
      _log(
        'error: target-agent binary not found. Build with: cargo build -p target-agent',
      );
      return;
    }

    // Prefer freshly exported secure-storage identity when present.
    await exportIdentityToFile();

    final args = <String>['--config', configPath];
    if (await File(identityPath).exists()) {
      args.addAll(['--identity', identityPath]);
    }
    args.add('run');

    _log('\$ $binary ${args.join(' ')}');
    final process = await Process.start(
      binary,
      args,
      mode: ProcessStartMode.normal,
    );
    _running = process;

    void pipe(Stream<List<int>> stream, {String prefix = ''}) {
      stream
          .transform(utf8.decoder)
          .transform(const LineSplitter())
          .listen((line) => _log('$prefix$line'));
    }

    pipe(process.stdout);
    pipe(process.stderr);
    unawaited(process.exitCode.then((code) {
      _log('target-agent exited ($code)');
      _running = null;
    }));
  }

  Future<void> stopTargetService() async {
    final proc = _running;
    if (proc == null) {
      _log('not running');
      return;
    }
    _log('stopping target-agent (pid ${proc.pid})…');
    proc.kill(ProcessSignal.sigterm);
    try {
      await proc.exitCode.timeout(const Duration(seconds: 5));
    } on TimeoutException {
      proc.kill(ProcessSignal.sigkill);
    }
    _running = null;
  }

  Future<void> dispose() async {
    await stopTargetService();
    await _logController.close();
  }
}
