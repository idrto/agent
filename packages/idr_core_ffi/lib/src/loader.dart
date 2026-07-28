import 'dart:ffi';
import 'dart:io';

import 'bindings.dart';

DynamicLibrary loadIdrLibrary({String? path}) {
  if (path != null) {
    return DynamicLibrary.open(path);
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
