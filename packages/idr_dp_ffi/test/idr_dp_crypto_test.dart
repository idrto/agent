import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:idr_dp_ffi/idr_dp_ffi.dart';
import 'package:test/test.dart';

void main() {
  final path = IdrDpCrypto.resolveLibraryPath(null);
  final available = File(path).existsSync();

  test('ed25519PrivateJwk derives d from PKCS#8 seed', () {
    // RFC 8410 example key: seed = 0xD4...
    const pem = '-----BEGIN PRIVATE KEY-----\n'
        'MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n'
        '-----END PRIVATE KEY-----';
    final seed = ed25519SeedFromPkcs8Pem(pem);
    expect(seed.length, 32);
    expect(seed.first, 0xD4);
    final jwk = ed25519PrivateJwk(privatePem: pem, publicJwk: {'x': 'AAAA'});
    expect(jwk['kty'], 'OKP');
    expect(jwk['d'], base64Url.encode(seed).replaceAll('=', ''));
  });

  test('seed is not the trailing public key', () {
    const pem = '-----BEGIN PRIVATE KEY-----\n'
        'MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n'
        '-----END PRIVATE KEY-----';
    final seed = ed25519SeedFromPkcs8Pem(pem);
    final pub = List<int>.filled(32, 0xab);
    final b64 = pem
        .split('\n')
        .map((l) => l.trim())
        .where((l) => l.isNotEmpty && !l.startsWith('-----'))
        .join();
    final der = base64Decode(b64);
    final withPub = Uint8List(der.length + 2 + 2 + 1 + pub.length);
    // Rebuild as SEQUENCE { original contents, [1] BIT STRING public }.
    final inner = BytesBuilder();
    inner.add(der.sublist(2)); // skip original sequence header (short form)
    inner.add([0xa1, 0x23, 0x03, 0x21, 0x00, ...pub]);
    final body = inner.toBytes();
    withPub[0] = 0x30;
    withPub[1] = body.length;
    withPub.setAll(2, body);
    final wrapped = '-----BEGIN PRIVATE KEY-----\n'
        '${base64Encode(withPub.sublist(0, 2 + body.length))}\n'
        '-----END PRIVATE KEY-----';
    final parsed = ed25519SeedFromPkcs8Pem(wrapped);
    expect(parsed, seed);
    expect(parsed, isNot(pub));
  });

  test('keygen → ski → csr → sign → ca cert → sign csr (native)', () {
    final crypto = IdrDpCrypto.open(libraryPath: path);
    final keys = crypto.generateEd25519();
    expect(keys.privatePem, contains('PRIVATE KEY'));
    expect(keys.publicJwk['crv'], 'Ed25519');
    expect(crypto.ski(keys.publicB64url), keys.ski);

    final csr = crypto.buildCsr(
      privatePem: keys.privatePem,
      fqhn: 'dev--user.example.com',
    );
    expect(csr, contains('CERTIFICATE REQUEST'));
    expect(crypto.sign(privatePem: keys.privatePem, message: 'hi'.codeUnits),
        isNotEmpty);
    expect(crypto.signJson(privatePem: keys.privatePem, json: '{"a":1}'),
        isNotEmpty);

    final ca = crypto.generateEd25519();
    final caJwk =
        ed25519PrivateJwk(privatePem: ca.privatePem, publicJwk: ca.publicJwk);
    final caPem =
        crypto.caCertPemFromPrivateJwk(privateJwk: caJwk, commonName: ca.ski);
    expect(caPem, contains('BEGIN CERTIFICATE'));

    final leaf = crypto.signCsr(
      csrPem: csr,
      caPrivateJwk: caJwk,
      issuerSki: ca.ski,
      host: 'dev--user.example.com',
    );
    expect(leaf.leafPem, contains('BEGIN CERTIFICATE'));
    expect(leaf.chainPem, contains(leaf.leafPem.trim()));
  }, skip: available ? false : 'build idr-dp-ffi first: $path');
}
