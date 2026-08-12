import 'dart:typed_data';

import 'runtime.dart';

class IdrStream {
  IdrStream(this._runtime, this.sessionId, this.id);

  final IdrRuntime _runtime;
  final int sessionId;
  final int id;
  bool _closed = false;

  Future<int> write(Uint8List data) async {
    _ensureOpen();
    return _runtime.writeBytes(sessionId, id, data);
  }

  Future<Uint8List> read({int maxLen = 65536}) async {
    _ensureOpen();
    return _runtime.readBytes(sessionId, id, maxLen);
  }

  Future<void> halfClose() async {
    _ensureOpen();
    await _runtime.halfCloseStream(sessionId, id);
  }

  Future<void> reset({int reason = 0}) async {
    if (_closed) {
      return;
    }
    _closed = true;
    await _runtime.resetStream(sessionId, id, reason);
  }

  void _ensureOpen() {
    if (_closed) {
      throw StateError('stream closed');
    }
  }
}
