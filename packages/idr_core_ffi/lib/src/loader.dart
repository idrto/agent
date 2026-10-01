import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

import 'bindings.dart';

DynamicLibrary loadIdrLibrary({String? path}) {
  final resolved = _resolveLibraryPath(path);
  if (resolved != null) {
    if (Platform.isWindows) {
      _prepareWindowsDllSearch(resolved);
    }
    return DynamicLibrary.open(resolved);
  }
  if (Platform.isWindows) {
    return DynamicLibrary.open('idr_c_api.dll');
  }
  if (Platform.isMacOS) {
    return DynamicLibrary.open('libidr_c_api.dylib');
  }
  if (Platform.isIOS) {
    return DynamicLibrary.process();
  }
  if (Platform.isAndroid) {
    return DynamicLibrary.open('libidr_c_api.so');
  }
  return DynamicLibrary.open('libidr_c_api.so');
}

IdrBindings openIdrBindings({String? libraryPath}) {
  return IdrBindings(loadIdrLibrary(path: libraryPath));
}

String? _resolveLibraryPath(String? explicit) {
  final candidates = <String>[];
  if (explicit != null && explicit.trim().isNotEmpty) {
    candidates.add(explicit.trim());
  }
  for (final name in const ['IDR_C_API_LIB', 'IDR_SDK_LIB']) {
    final env = Platform.environment[name];
    if (env != null && env.trim().isNotEmpty) {
      candidates.add(env.trim());
    }
  }

  // Walk upward from cwd (then the executable) for
  // agents_engine/agent/target/{release,debug}/… (legacy agent/target too).
  final lib = Platform.isWindows
      ? 'idr_c_api.dll'
      : Platform.isMacOS
          ? 'libidr_c_api.dylib'
          : 'libidr_c_api.so';
  for (final start in [Directory.current, File(Platform.resolvedExecutable).parent]) {
    var dir = start;
    for (var i = 0; i < 8; i++) {
      for (final agent in const ['agents_engine/agent', 'agent']) {
        for (final profile in const ['release', 'debug']) {
          candidates.add(
            [dir.path, ...agent.split('/'), 'target', profile, lib]
                .join(Platform.pathSeparator),
          );
        }
      }
      final parent = dir.parent;
      if (parent.path == dir.path) break;
      dir = parent;
    }
  }

  for (final c in candidates) {
    if (File(c).existsSync()) return c;
  }
  return null;
}

/// Make OpenSSL (and other) deps next to `idr_c_api.dll` resolvable on Windows.
void _prepareWindowsDllSearch(String dllPath) {
  try {
    final dir = File(dllPath).parent.path;
    final kernel32 = DynamicLibrary.open('kernel32.dll');
    final setDllDirectory = kernel32.lookupFunction<
        Int32 Function(Pointer<Utf16>),
        int Function(Pointer<Utf16>)>('SetDllDirectoryW');
    final ptr = dir.toNativeUtf16();
    try {
      setDllDirectory(ptr);
    } finally {
      malloc.free(ptr);
    }
  } catch (_) {
    // Best-effort; DynamicLibrary.open may still succeed if deps are on PATH.
  }
}
