import 'dart:io';

import 'package:args/args.dart';
import 'package:flutter/widgets.dart';
import 'package:idr_cli/agent_host.dart';
import 'package:idr_client/idr_client.dart';
import 'package:idr_secure_storage/idr_secure_storage.dart';

/// Console entry: `dart run bin/idr_cli.dart <command>`.
/// Prefer `flutter run -d windows` for the Target Agent desktop host.
Future<void> main(List<String> args) async {
  WidgetsFlutterBinding.ensureInitialized();

  final parser = ArgParser()
    ..addCommand('version')
    ..addCommand('doctor')
    ..addCommand(
      'identity',
      ArgParser()
        ..addCommand('show')
        ..addCommand('clear')
        ..addOption('import',
            help: 'Import DeviceIdentity JSON file into secure storage')
        ..addCommand(
            'init',
            _nativeAgentParser()
              ..addOption('role',
                  allowed: ['target', 'source'],
                  defaultsTo: 'target',
                  help: 'Defaults to target for this desktop host')
              ..addOption('host',
                  mandatory: true,
                  help:
                      'Fully-qualified machine host, e.g. db1.us-east--acme')
              ..addOption('entity')
              ..addOption('common-name')
              ..addOption('pending',
                  help: 'Override pending-state file path'))
        ..addCommand(
            'enroll',
            _nativeAgentParser()
              ..addFlag('local',
                  defaultsTo: false,
                  help:
                      'Localhost instant path (sign locally + enroll-instant)')
              ..addOption('auth-url',
                  help:
                      'Better Auth base URL mounting delegate-permissions')
              ..addOption('entity')
              ..addOption('host')
              ..addOption('role', allowed: ['target', 'source'])
              ..addOption('common-name')
              ..addOption('cookie')
              ..addOption('bearer')
              ..addOption('pending')
              ..addOption('ca-key',
                  help: '--local: Entity CA key JSON (see cert init-ca)')
              ..addOption('ca-cert',
                  help: '--local: Entity CA self-signed cert PEM')
              ..addOption('issuer-ski',
                  help: '--local: SKI of the credential issuer')
              ..addOption('issuer-key',
                  help: '--local: issuer private_jwk JSON file')
              ..addOption('permissions',
                  help: '--local: CapabilitySet JSON file')
              ..addOption('paying-party-id')
              ..addOption('not-after-days'))
        ..addCommand(
            'pull',
            _nativeAgentParser()
              ..addOption('auth-url', mandatory: true)
              ..addOption('pending')),
    )
    ..addCommand(
      'run',
      ArgParser()
        ..addOption('agent-binary',
            defaultsTo: Platform.environment['IDR_AGENT_BINARY'],
            help: 'Path to target-agent (spawns native service)')
        ..addOption('config',
            defaultsTo: Platform.environment['IDR_TARGET_CONFIG'],
            help: 'target-agent TOML config')
        ..addOption('identity', help: 'DeviceIdentity JSON path')
        ..addFlag('target',
            defaultsTo: true,
            help: 'Run native target-agent (default)')
        ..addOption('library',
            help: 'Path to libidr_c_api (source mock path only)')
        ..addFlag('mock',
            defaultsTo: true, help: 'Source mock backend (if --no-target)'),
    )
    ..addCommand(
      'connect',
      ArgParser()
        ..addOption('target', abbr: 't', mandatory: true, help: 'Target FQHN')
        ..addOption('service', abbr: 's', help: 'Named service to open')
        ..addOption('library', help: 'Path to libidr_c_api shared library')
        ..addFlag('mock', defaultsTo: true),
    );

  final result = parser.parse(args);
  final store = DpSecretStore(
    store: FlutterSecureKvStore(),
    prefix: 'idr.dp',
  );

  final cmd = result.command;
  if (cmd == null) {
    stdout.writeln(parser.usage);
    stdout.writeln(
      '\nTip: flutter run -d windows  # Target Agent desktop host UI',
    );
    exit(64);
  }

  switch (cmd.name) {
    case 'version':
      final host = AgentHost(store: store);
      final code = await host.version();
      if (code != 0) {
        stdout.writeln('idr_cli 0.1.0 (native binary unavailable)');
        stdout.writeln('secrets: flutter_secure_storage (fl-start)');
      }
      break;
    case 'doctor':
      final host = AgentHost(store: store);
      host.logs.listen(stdout.writeln);
      final id = await store.loadIdentity();
      stdout.writeln('secure_storage=flutter_secure_storage');
      if (id == null) {
        stdout.writeln('identity=(none)');
      } else {
        stdout.writeln('identity_ski=${id.ski}');
        stdout.writeln('identity_fqhn=${id.fqhn ?? "(none)"}');
      }
      await host.doctor();
      break;
    case 'identity':
      await _identity(cmd, store);
      break;
    case 'run':
      if (cmd['target'] as bool) {
        final host = AgentHost(
          store: store,
          agentBinary: cmd['agent-binary'] as String?,
          configPath: cmd['config'] as String?,
          identityPath: cmd['identity'] as String?,
        );
        host.logs.listen(stdout.writeln);
        await host.startTargetService();
        await ProcessSignal.sigint.watch().first;
        await host.stopTargetService();
      } else {
        await _runSourceMock(cmd, store);
      }
      break;
    case 'connect':
      await _connect(cmd, store);
      break;
    default:
      stdout.writeln(parser.usage);
      exit(64);
  }
}

Future<void> _identity(ArgResults cmd, DpSecretStore store) async {
  final importPath = cmd['import'] as String?;
  if (importPath != null) {
    final host = AgentHost(store: store, identityPath: importPath);
    host.logs.listen(stdout.writeln);
    await host.importIdentityFromFile(path: importPath);
    return;
  }
  final sub = cmd.command;
  if (sub == null) {
    stdout.writeln(
        'usage: identity show|clear|init|enroll|pull|--import <file>');
    exit(64);
  }
  switch (sub.name) {
    case 'show':
      final id = await store.loadIdentity();
      if (id == null) {
        stdout.writeln('(none)');
      } else {
        stdout.writeln('ski=${id.ski}');
        stdout.writeln('fqhn=${id.fqhn}');
        stdout.writeln(
            'cert=${id.certPem == null ? "(none, dev/self-signed)" : "issued"}');
      }
      break;
    case 'clear':
      await store.clearIdentity();
      stdout.writeln('cleared');
      break;
    case 'init':
      await _runNativeAgent(sub, subcommand: const ['identity', 'init'], forward: const [
        _Opt.value('role'),
        _Opt.value('host'),
        _Opt.value('entity'),
        _Opt.value('common-name'),
        _Opt.value('pending'),
      ]);
      break;
    case 'enroll':
      final identityFile = _resolveIdentityFile(sub);
      await _runNativeAgent(sub, subcommand: const ['identity', 'enroll'], forward: const [
        _Opt.flag('local'),
        _Opt.value('auth-url'),
        _Opt.value('entity'),
        _Opt.value('host'),
        _Opt.value('role'),
        _Opt.value('common-name'),
        _Opt.value('cookie'),
        _Opt.value('bearer'),
        _Opt.value('pending'),
        _Opt.value('ca-key'),
        _Opt.value('ca-cert'),
        _Opt.value('issuer-ski'),
        _Opt.value('issuer-key'),
        _Opt.value('permissions'),
        _Opt.value('paying-party-id'),
        _Opt.value('not-after-days'),
      ]);
      if (sub['local'] as bool) {
        final host = AgentHost(store: store, identityPath: identityFile);
        host.logs.listen(stdout.writeln);
        await host.importIdentityFromFile();
      }
      break;
    case 'pull':
      final identityFile = _resolveIdentityFile(sub);
      await _runNativeAgent(sub, subcommand: const ['identity', 'pull'], forward: const [
        _Opt.value('auth-url'),
        _Opt.value('pending'),
      ]);
      final host = AgentHost(store: store, identityPath: identityFile);
      host.logs.listen(stdout.writeln);
      await host.importIdentityFromFile();
      break;
  }
}

ArgParser _nativeAgentParser() => ArgParser()
  ..addOption('agent-binary',
      defaultsTo: Platform.environment['IDR_AGENT_BINARY'],
      help: 'Path to the source-agent/target-agent executable '
          '(or set IDR_AGENT_BINARY)')
  ..addOption('identity',
      help: 'DeviceIdentity JSON path used by the native binary '
          '(default identity.dp.json); also the file imported into secure storage');

class _Opt {
  const _Opt.flag(this.name) : isFlag = true;
  const _Opt.value(this.name) : isFlag = false;
  final String name;
  final bool isFlag;
}

String _resolveIdentityFile(ArgResults cmd) =>
    (cmd['identity'] as String?) ?? 'identity.dp.json';

Future<void> _runNativeAgent(
  ArgResults cmd, {
  required List<String> subcommand,
  required List<_Opt> forward,
}) async {
  var binary = cmd['agent-binary'] as String?;
  if (binary == null || binary.isEmpty) {
    final host = AgentHost(store: DpSecretStore(store: MemoryKvStore()));
    binary = await host.detectBinary();
  }
  if (binary == null) {
    stderr.writeln(
        'error: --agent-binary <path> is required (or set IDR_AGENT_BINARY)');
    exit(64);
  }
  final args = <String>[];
  final identity = cmd['identity'] as String?;
  if (identity != null) {
    args.addAll(['--identity', identity]);
  }
  args.addAll(subcommand);
  for (final opt in forward) {
    if (opt.isFlag) {
      if (cmd[opt.name] as bool) {
        args.add('--${opt.name}');
      }
    } else {
      final value = cmd[opt.name] as String?;
      if (value != null) {
        args.addAll(['--${opt.name}', value]);
      }
    }
  }
  stdout.writeln('\$ $binary ${args.join(' ')}');
  final result = await Process.run(binary, args);
  if ((result.stdout as String).isNotEmpty) stdout.write(result.stdout);
  if ((result.stderr as String).isNotEmpty) stderr.write(result.stderr);
  if (result.exitCode != 0) {
    exit(result.exitCode);
  }
}

Future<void> _runSourceMock(ArgResults cmd, DpSecretStore store) async {
  final runtime = IdrRuntime.create(
    libraryPath: cmd['library'] as String?,
    useMock: cmd['mock'] as bool,
  );
  try {
    final id = await store.loadIdentity();
    if (id != null) {
      runtime.setDpIdentityMap(id.toNativeJson());
      stdout.writeln('loaded identity ski=${id.ski}');
    } else {
      stdout.writeln('warning: no DP identity in secure storage (anonymous)');
    }
    stdout.writeln('idr_cli source mock running (ctrl-c to stop)');
    await ProcessSignal.sigint.watch().first;
  } finally {
    runtime.dispose();
  }
}

Future<void> _connect(ArgResults cmd, DpSecretStore store) async {
  final runtime = IdrRuntime.create(
    libraryPath: cmd['library'] as String?,
    useMock: cmd['mock'] as bool,
  );
  try {
    final id = await store.loadIdentity();
    if (id != null) {
      runtime.setDpIdentityMap(id.toNativeJson());
    }
    final target = cmd['target'] as String;
    final session = await runtime.connect(target);
    stdout.writeln('connected $target');
    final service = cmd['service'] as String?;
    if (service != null) {
      final stream = await session.openStream(service);
      stdout.writeln('opened service=$service stream=${stream.id}');
      await stream.halfClose();
    }
    await session.close();
  } finally {
    runtime.dispose();
  }
}
