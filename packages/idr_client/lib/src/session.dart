import 'runtime.dart';
import 'stream.dart';

class IdrSession {
  IdrSession(this._runtime, this.id);

  final IdrRuntime _runtime;
  final int id;
  bool _closed = false;

  /// Open a named service stream (`http`, `https`, `tcp`).
  Future<IdrStream> openStream(String service) async {
    _ensureOpen();
    final streamId = _runtime.openNamedStream(id, service);
    return IdrStream(_runtime, id, streamId);
  }

  Future<void> close() async {
    if (_closed) {
      return;
    }
    _closed = true;
    _runtime.disconnectSession(id);
  }

  void _ensureOpen() {
    if (_closed) {
      throw StateError('session closed');
    }
  }
}
