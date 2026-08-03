import 'dart:convert';

import 'dp_identity_bundle.dart';
import 'string_kv_store.dart';

/// Persist DP machine identity. Production hosts inject [FlutterSecureKvStore].
class DpSecretStore {
  DpSecretStore({
    required StringKvStore store,
    this.prefix = 'idr.dp',
  }) : _store = store;

  final StringKvStore _store;

  /// Key namespace so CLI / app / tenant do not collide (e.g. `idr.dp`).
  final String prefix;

  String _key(String name) => '$prefix.$name';

  Future<void> saveIdentity({
    required String ski,
    required Map<String, dynamic> privateJwk,
    required Map<String, dynamic> credential,
    Map<String, dynamic>? publicJwk,
    String? fqhn,
    String? certPem,
    String? chainPem,
  }) async {
    await _store.write(_key('ski'), ski);
    await _store.write(_key('private_jwk'), jsonEncode(privateJwk));
    await _store.write(_key('credential'), jsonEncode(credential));
    if (publicJwk != null) {
      await _store.write(_key('public_jwk'), jsonEncode(publicJwk));
    }
    if (fqhn != null) {
      await _store.write(_key('fqhn'), fqhn);
    }
    if (certPem != null) {
      await _store.write(_key('cert_pem'), certPem);
    }
    if (chainPem != null) {
      await _store.write(_key('chain_pem'), chainPem);
    }
  }

  Future<void> saveBundle(DpIdentityBundle bundle) => saveIdentity(
        ski: bundle.ski,
        privateJwk: bundle.privateJwk,
        credential: bundle.credential,
        publicJwk: bundle.publicJwk,
        fqhn: bundle.fqhn,
        certPem: bundle.certPem,
        chainPem: bundle.chainPem,
      );

  Future<DpIdentityBundle?> loadIdentity() async {
    final ski = await _store.read(_key('ski'));
    final privateRaw = await _store.read(_key('private_jwk'));
    final credentialRaw = await _store.read(_key('credential'));
    if (ski == null || privateRaw == null || credentialRaw == null) {
      return null;
    }
    final publicRaw = await _store.read(_key('public_jwk'));
    return DpIdentityBundle(
      ski: ski,
      privateJwk: jsonDecode(privateRaw) as Map<String, dynamic>,
      credential: jsonDecode(credentialRaw) as Map<String, dynamic>,
      publicJwk: publicRaw == null
          ? null
          : jsonDecode(publicRaw) as Map<String, dynamic>,
      fqhn: await _store.read(_key('fqhn')),
      certPem: await _store.read(_key('cert_pem')),
      chainPem: await _store.read(_key('chain_pem')),
    );
  }

  Future<void> clearIdentity() async {
    await _store.delete(_key('ski'));
    await _store.delete(_key('private_jwk'));
    await _store.delete(_key('public_jwk'));
    await _store.delete(_key('credential'));
    await _store.delete(_key('fqhn'));
    await _store.delete(_key('cert_pem'));
    await _store.delete(_key('chain_pem'));
  }
}
