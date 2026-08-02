import 'dart:convert';
import 'dart:io';

import 'package:args/args.dart';
import 'package:flutter/widgets.dart';
import 'package:idr_client/idr_client.dart';
import 'package:idr_secure_storage/idr_secure_storage.dart';

/// Desktop CLI entry — secrets always go through [FlutterSecureKvStore].
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
        ..addOption('import', help: 'Import DeviceIdentity JSON file into secure storage'),
    )
    ..addCommand(
      'run',
      ArgParser()
        ..addOption('library', help: 'Path to libidr_c_api shared library')
        ..addFlag('mock', defaultsTo: true, help: 'Use mock WebRTC backend'),
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
    exit(64);
  }

  switch (cmd.name) {
    case 'version':
      stdout.writeln('idr_cli 0.1.0');
      stdout.writeln('secrets: flutter_secure_storage (fl-start)');
      stdout.writeln('pep: via native source-agent / idr_c_api (quic→wss)');
      break;
    case 'doctor':
      final id = await store.loadIdentity();
      stdout.writeln('secure_storage=flutter_secure_storage');
      if (id == null) {
        stdout.writeln('identity=(none)');
      } else {
        stdout.writeln('identity_ski=${id.ski}');
        stdout.writeln('identity_fqhn=${id.fqhn ?? "(none)"}');
      }
      break;
    case 'identity':
      await _identity(cmd, store);
      break;
    case 'run':
      await _run(cmd, store);
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
    final raw = await File(importPath).readAsString();
    final map = jsonDecode(raw) as Map<String, dynamic>;
    await store.saveIdentity(
      ski: map['ski'] as String,
      privateJwk: map['private_jwk'] as Map<String, dynamic>,
      credential: map['credential'] as Map<String, dynamic>,
      publicJwk: map['public_jwk'] as Map<String, dynamic>?,
      fqhn: map['fqhn'] as String?,
    );
    stdout.writeln('imported ski=${map['ski']}');
    return;
  }
  final sub = cmd.command;
  if (sub == null) {
    stdout.writeln('usage: identity show|clear|--import <file>');
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
      }
      break;
    case 'clear':
      await store.clearIdentity();
      stdout.writeln('cleared');
      break;
  }
}

Future<void> _run(ArgResults cmd, DpSecretStore store) async {
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
    stdout.writeln('idr_cli service running (ctrl-c to stop)');
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
