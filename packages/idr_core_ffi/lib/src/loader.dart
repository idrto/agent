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
  final env = Platform.environment['IDR_SDK_LIB'];
  if (env != null && env.trim().isNotEmpty) {
    candidates.add(env.trim());
  }

  if (Platform.isWindows) {
    candidates.addAll(const [
      r'C:\dev\idrto\agent\target\release\idr_c_api.dll',
      r'C:\dev\idrto\agent\target\debug\idr_c_api.dll',
    ]);
  } else if (Platform.isMacOS) {
    candidates.addAll(const [
      '/Users/Shared/idrto/agent/target/release/libidr_c_api.dylib',
    ]);
  } else if (Platform.isLinux) {
    candidates.addAll(const [
      '/opt/idrto/agent/target/release/libidr_c_api.so',
    ]);
  }

  // Walk upward from cwd looking for agent/target/{release,debug}/…
  var dir = Directory.current;
  for (var i = 0; i < 8; i++) {
    final release = _joinNativeLib(dir.path, 'release');
    final debug = _joinNativeLib(dir.path, 'debug');
    candidates.add(release);
    candidates.add(debug);
    final parent = dir.parent;
    if (parent.path == dir.path) break;
    dir = parent;
  }

  for (final c in candidates) {
    if (File(c).existsSync()) return c;
  }
  return null;
}

String _joinNativeLib(String root, String profile) {
  if (Platform.isWindows) {
    return '$root${Platform.pathSeparator}agent${Platform.pathSeparator}target'
        '${Platform.pathSeparator}$profile${Platform.pathSeparator}idr_c_api.dll';
  }
  if (Platform.isMacOS) {
    return '$root/agent/target/$profile/libidr_c_api.dylib';
  }
  return '$root/agent/target/$profile/libidr_c_api.so';
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
