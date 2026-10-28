import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

import 'crypto.dart';

typedef _FreeC = Void Function(Pointer<Utf8>);
typedef _FreeD = void Function(Pointer<Utf8>);
typedef _LastErrC = Pointer<Utf8> Function();
typedef _LastErrD = Pointer<Utf8> Function();
typedef _Out1C = Int32 Function(Pointer<Pointer<Utf8>>);
typedef _Out1D = int Function(Pointer<Pointer<Utf8>>);
typedef _In1Out1C = Int32 Function(Pointer<Utf8>, Pointer<Pointer<Utf8>>);
typedef _In1Out1D = int Function(Pointer<Utf8>, Pointer<Pointer<Utf8>>);
typedef _In2Out1C = Int32 Function(
    Pointer<Utf8>, Pointer<Utf8>, Pointer<Pointer<Utf8>>);
typedef _In2Out1D = int Function(
    Pointer<Utf8>, Pointer<Utf8>, Pointer<Pointer<Utf8>>);
typedef _SignC = Int32 Function(
    Pointer<Utf8>, Pointer<Uint8>, IntPtr, Pointer<Pointer<Utf8>>);
typedef _SignD = int Function(
    Pointer<Utf8>, Pointer<Uint8>, int, Pointer<Pointer<Utf8>>);
typedef _SignCsrC = Int32 Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>,
    Pointer<Utf8>, Pointer<Pointer<Utf8>>);
typedef _SignCsrD = int Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>,
    Pointer<Utf8>, Pointer<Pointer<Utf8>>);
typedef _SignCsrChainC = Int32 Function(Pointer<Utf8>, Pointer<Utf8>,
    Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Pointer<Utf8>>);
typedef _SignCsrChainD = int Function(Pointer<Utf8>, Pointer<Utf8>,
    Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Pointer<Utf8>>);
typedef _In4Out1C = Int32 Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>,
    Pointer<Utf8>, Pointer<Pointer<Utf8>>);
typedef _In4Out1D = int Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>,
    Pointer<Utf8>, Pointer<Pointer<Utf8>>);

/// [IdrCrypto] over the `idr_dp_*` C ABI.
class IdrDpCrypto implements IdrCrypto {
  IdrDpCrypto.fromLibrary(DynamicLibrary lib)
      : _lib = lib,
        _free = lib.lookupFunction<_FreeC, _FreeD>('idr_dp_string_free'),
        _lastError =
            lib.lookupFunction<_LastErrC, _LastErrD>('idr_dp_last_error'),
        _generate =
            lib.lookupFunction<_Out1C, _Out1D>('idr_dp_generate_ed25519'),
        _buildCsr =
            lib.lookupFunction<_In2Out1C, _In2Out1D>('idr_dp_build_csr'),
        _sign = lib.lookupFunction<_SignC, _SignD>('idr_dp_sign'),
        _signJson =
            lib.lookupFunction<_In2Out1C, _In2Out1D>('idr_dp_sign_json'),
        _ski = lib.lookupFunction<_In1Out1C, _In1Out1D>('idr_dp_ski'),
        _caCert = lib.lookupFunction<_In2Out1C, _In2Out1D>(
            'idr_dp_ca_cert_pem_from_jwk'),
        _signCsr = lib.lookupFunction<_SignCsrC, _SignCsrD>('idr_dp_sign_csr');

  /// Open `idr_dp` (or any library exporting `idr_dp_*`, e.g. `idr_c_api`).
  ///
  /// Resolution: [libraryPath] → `IDR_DP_LIB` env → next to the executable →
  /// walk up from cwd for `agents_engine/agent/target/{release,debug}`.
  factory IdrDpCrypto.open({String? libraryPath}) => IdrDpCrypto.fromLibrary(
      DynamicLibrary.open(resolveLibraryPath(libraryPath)));

  static String get defaultLibraryName => Platform.isWindows
      ? 'idr_dp.dll'
      : Platform.isMacOS
          ? 'libidr_dp.dylib'
          : 'libidr_dp.so';

  static String resolveLibraryPath(String? explicit) {
    final name = defaultLibraryName;
    final candidates = <String>[
      if (explicit != null && explicit.trim().isNotEmpty) explicit.trim(),
      if ((Platform.environment['IDR_DP_LIB'] ?? '').trim().isNotEmpty)
        Platform.environment['IDR_DP_LIB']!.trim(),
      '${File(Platform.resolvedExecutable).parent.path}${Platform.pathSeparator}$name',
    ];
    var dir = Directory.current;
    for (var i = 0; i < 8; i++) {
      for (final agent in const ['agents_engine/agent', 'agent']) {
        for (final profile in const ['release', 'debug']) {
          candidates.add(
            [dir.path, ...agent.split('/'), 'target', profile, name]
                .join(Platform.pathSeparator),
          );
        }
      }
      if (dir.parent.path == dir.path) break;
      dir = dir.parent;
    }
    for (final c in candidates) {
      if (File(c).existsSync()) return c;
    }
    // Fall back to the OS loader search path.
    return name;
  }

  final DynamicLibrary _lib;
  final _FreeD _free;
  final _LastErrD _lastError;

  // Zone signing symbols resolve on first use, so an older idr_dp without
  // them still loads for everything else.
  late final _SignCsrChainD _signCsrChain =
      _lib.lookupFunction<_SignCsrChainC, _SignCsrChainD>(
          'idr_dp_sign_csr_with_chain');
  late final _In4Out1D _signIntermediate =
      _lib.lookupFunction<_In4Out1C, _In4Out1D>('idr_dp_sign_intermediate_ca');
  final _Out1D _generate;
  final _In2Out1D _buildCsr;
  final _SignD _sign;
  final _In2Out1D _signJson;
  final _In1Out1D _ski;
  final _In2Out1D _caCert;
  final _SignCsrD _signCsr;

  @override
  Ed25519KeyMaterial generateEd25519() {
    final json = _call((out) => _generate(out));
    return Ed25519KeyMaterial.fromJson(
        Map<String, dynamic>.from(jsonDecode(json) as Map));
  }

  @override
  String ski(String publicB64url) =>
      _withUtf8(publicB64url, (p) => _call((out) => _ski(p, out)));

  @override
  String buildCsr(
          {required String privatePem, required String fqhn}) =>
      _withUtf8(
          privatePem,
          (pem) =>
              _withUtf8(fqhn, (h) => _call((out) => _buildCsr(pem, h, out))));

  @override
  String sign({required String privatePem, required List<int> message}) {
    final buf = calloc<Uint8>(message.length);
    try {
      buf.asTypedList(message.length).setAll(0, message);
      return _withUtf8(privatePem,
          (pem) => _call((out) => _sign(pem, buf, message.length, out)));
    } finally {
      calloc.free(buf);
    }
  }

  @override
  String signJson(
          {required String privatePem, required String json}) =>
      _withUtf8(
          privatePem,
          (pem) =>
              _withUtf8(json, (j) => _call((out) => _signJson(pem, j, out))));

  @override
  String caCertPemFromPrivateJwk({
    required Map<String, dynamic> privateJwk,
    required String commonName,
  }) =>
      _withUtf8(
          jsonEncode(privateJwk),
          (jwk) => _withUtf8(
              commonName, (cn) => _call((out) => _caCert(jwk, cn, out))));

  @override
  SignedLeaf signCsr({
    required String csrPem,
    required Map<String, dynamic> caPrivateJwk,
    required String issuerSki,
    String? host,
    String? issuerChainPem,
  }) {
    final hostPtr = host == null ? nullptr : host.toNativeUtf8();
    try {
      final json = _withUtf8(
          csrPem,
          (csr) => _withUtf8(
              jsonEncode(caPrivateJwk),
              (jwk) => _withUtf8(
                  issuerSki,
                  (iss) => issuerChainPem == null
                      ? _call((out) => _signCsr(csr, jwk, iss, hostPtr, out))
                      : _withUtf8(
                          issuerChainPem,
                          (chain) => _call((out) => _signCsrChain(
                              csr, jwk, iss, chain, hostPtr, out))))));
      final j = jsonDecode(json) as Map;
      return (
        leafPem: j['leaf_pem'] as String? ?? '',
        chainPem: j['chain_pem'] as String? ?? '',
      );
    } finally {
      if (hostPtr != nullptr) malloc.free(hostPtr);
    }
  }

  @override
  String signIntermediateCa({
    required Map<String, dynamic> childPublicJwk,
    required String childCommonName,
    required Map<String, dynamic> parentPrivateJwk,
    required String parentCommonName,
  }) =>
      _withUtf8(
          jsonEncode(childPublicJwk),
          (child) => _withUtf8(
              childCommonName,
              (childCn) => _withUtf8(
                  jsonEncode(parentPrivateJwk),
                  (parent) => _withUtf8(
                      parentCommonName,
                      (parentCn) => _call((out) => _signIntermediate(
                          child, childCn, parent, parentCn, out))))));

  T _withUtf8<T>(String s, T Function(Pointer<Utf8>) f) {
    final p = s.toNativeUtf8();
    try {
      return f(p);
    } finally {
      malloc.free(p);
    }
  }

  String _call(int Function(Pointer<Pointer<Utf8>> out) f) {
    final out = calloc<Pointer<Utf8>>();
    try {
      final rc = f(out);
      if (rc != 0) {
        final err = _lastError();
        throw IdrDpException(
            rc, err == nullptr ? 'native error $rc' : err.toDartString());
      }
      final ptr = out.value;
      try {
        return ptr.toDartString();
      } finally {
        _free(ptr);
      }
    } finally {
      calloc.free(out);
    }
  }
}
