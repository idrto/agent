import 'dart:convert';
import 'dart:typed_data';

/// 32-byte Ed25519 seed from a PKCS#8 PEM.
///
/// The seed is the privateKey OCTET STRING (RFC 8410), not the last 32 bytes.
/// OpenSSL appends the public key after that field; those trailing bytes are
/// not the seed.
Uint8List ed25519SeedFromPkcs8Pem(String pem) {
  final b64 = pem
      .split('\n')
      .map((l) => l.trim())
      .where((l) => l.isNotEmpty && !l.startsWith('-----'))
      .join();
  final der = base64Decode(b64);
  if (der.isEmpty || der[0] != 0x30) {
    throw const FormatException('not an Ed25519 PKCS#8 private key');
  }
  final seq = _derTlv(der, 0);
  var i = seq.start;
  i = _derTlv(der, i).next; // version
  i = _derTlv(der, i).next; // algorithm
  if (i >= der.length || der[i] != 0x04) {
    throw const FormatException('not an Ed25519 PKCS#8 private key');
  }
  final pk = _derTlv(der, i);
  final content = der.sublist(pk.start, pk.start + pk.len);
  if (content.length == 32) {
    return Uint8List.fromList(content);
  }
  // OpenSSL wraps the 32-byte seed in an inner OCTET STRING.
  if (content.length >= 34 && content[0] == 0x04 && content[1] == 0x20) {
    return Uint8List.fromList(content.sublist(2, 34));
  }
  throw const FormatException('not an Ed25519 PKCS#8 private key');
}

({int start, int len, int next}) _derTlv(Uint8List der, int i) {
  var p = i + 1;
  final first = der[p];
  late int len;
  if (first < 0x80) {
    len = first;
    p += 1;
  } else {
    final n = first & 0x7f;
    p += 1;
    len = 0;
    for (var k = 0; k < n; k++) {
      len = (len << 8) | der[p + k];
    }
    p += n;
  }
  return (start: p, len: len, next: p + len);
}

String _b64url(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');

/// PKCS#8 PEM for the Ed25519 seed in private JWK field `d`.
String ed25519Pkcs8PemFromPrivateJwk(Map<String, dynamic> jwk) {
  final raw = jwk['d'];
  if (raw is! String || raw.isEmpty) {
    throw ArgumentError.value(jwk, 'jwk', 'missing d');
  }
  final seed = base64Url.decode(base64Url.normalize(raw));
  if (seed.length != 32) {
    throw FormatException('Ed25519 seed must be 32 bytes');
  }
  final der = Uint8List(48);
  der.setAll(0, const [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
    0x04, 0x22, 0x04, 0x20,
  ]);
  der.setAll(16, seed);
  final b64 = base64Encode(der);
  return '-----BEGIN PRIVATE KEY-----\n$b64\n-----END PRIVATE KEY-----\n';
}

/// OKP private JWK `{kty, crv, x, d, alg}` from PEM + matching public JWK.
Map<String, dynamic> ed25519PrivateJwk({
  required String privatePem,
  required Map<String, dynamic> publicJwk,
}) {
  final x = publicJwk['x'] as String?;
  if (x == null || x.isEmpty) {
    throw ArgumentError.value(publicJwk, 'publicJwk', 'missing x');
  }
  return {
    'kty': 'OKP',
    'crv': 'Ed25519',
    'x': x,
    'd': _b64url(ed25519SeedFromPkcs8Pem(privatePem)),
    'alg': 'EdDSA',
  };
}
