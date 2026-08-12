import 'runtime.dart';
import 'stream.dart';
import 'catalog.dart';

class IdrSession {
  IdrSession(this._runtime, this.id);

  final IdrRuntime _runtime;
  final int id;
  bool _closed = false;

  /// Open a named service stream (`http`, `https`, `tcp`, `ollama`, …).
  Future<IdrStream> openStream(String service) async {
    _ensureOpen();
    final streamId = await _runtime.openNamedStream(id, service);
    return IdrStream(_runtime, id, streamId);
  }

  /// Named services from Target (always refreshes catalog over the DataChannel).
  Future<List<String>> listNamedServices() async {
    _ensureOpen();
    return _runtime.listNamedServices(id);
  }

  /// Structured catalog (credential_mode, require_upstream_tls, …).
  Future<List<NamedServiceInfo>> listNamedServiceCatalog() async {
    _ensureOpen();
    return _runtime.listNamedServiceCatalog(id);
  }

  Future<void> close() async {
    if (_closed) {
      return;
    }
    _closed = true;
    await _runtime.disconnectSession(id);
  }

  void _ensureOpen() {
    if (_closed) {
      throw StateError('session closed');
    }
  }
}
