import 'package:idr_secure_storage/idr_secure_storage.dart';
import 'package:test/test.dart';

void main() {
  test('DpSecretStore roundtrips identity via MemoryKvStore', () async {
    final store = DpSecretStore(store: MemoryKvStore(), prefix: 'idr.dp');
    await store.saveIdentity(
      ski: 'ski123',
      privateJwk: {
        'kty': 'OKP',
        'crv': 'Ed25519',
        'd': 'abc',
        'x': 'xyz',
      },
      credential: {
        'version': 1,
        'kind': 'machine',
        'entityId': 'acme.example',
        'ski': 'ski123',
      },
      fqhn: 'cam1.acme.idr.to',
      certPem: '-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----',
      chainPem: '-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----',
    );

    final loaded = await store.loadIdentity();
    expect(loaded, isNotNull);
    expect(loaded!.ski, 'ski123');
    expect(loaded.fqhn, 'cam1.acme.idr.to');
    expect(loaded.certPem, contains('leaf'));
    expect(loaded.chainPem, contains('chain'));
    expect(loaded.toNativeJson()['ski'], 'ski123');
    expect(loaded.toNativeJson()['cert_pem'], loaded.certPem);

    await store.clearIdentity();
    expect(await store.loadIdentity(), isNull);
  });
}
