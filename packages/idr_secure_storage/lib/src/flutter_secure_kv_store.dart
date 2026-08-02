import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'string_kv_store.dart';

/// Production adapter over fl-start [FlutterSecureStorage].
///
/// Desktop: uses platform keychain / DPAPI / libsecret. For Windows services set
/// [WindowsOptions.useLocalMachine] via [wOptions] when intentionally machine-scoped.
class FlutterSecureKvStore implements StringKvStore {
  FlutterSecureKvStore([
    FlutterSecureStorage? storage,
    this.accountName = 'idr.agent',
  ]) : _storage = storage ??
            FlutterSecureStorage(
              aOptions: const AndroidOptions(),
              iOptions: const IOSOptions(
                accessibility: KeychainAccessibility.first_unlock,
              ),
              mOptions: MacOsOptions(accountName: accountName),
              lOptions: LinuxOptions(accountName: accountName),
              wOptions: WindowsOptions(accountName: accountName),
            );

  final FlutterSecureStorage _storage;
  final String accountName;

  @override
  Future<String?> read(String key) => _storage.read(key: key);

  @override
  Future<void> write(String key, String value) =>
      _storage.write(key: key, value: value);

  @override
  Future<void> delete(String key) => _storage.delete(key: key);
}
