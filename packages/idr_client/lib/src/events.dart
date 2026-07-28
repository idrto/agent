import 'package:idr_core_ffi/idr_core_ffi.dart';

sealed class IdrEvent {
  const IdrEvent();
}

class ConnectedEvent extends IdrEvent {
  const ConnectedEvent(this.sessionId);
  final int sessionId;
}

class StreamOpenedEvent extends IdrEvent {
  const StreamOpenedEvent(this.sessionId, this.streamId);
  final int sessionId;
  final int streamId;
}

class BytesAvailableEvent extends IdrEvent {
  const BytesAvailableEvent(this.streamId, this.length);
  final int streamId;
  final int length;
}

class StreamClosedEvent extends IdrEvent {
  const StreamClosedEvent(this.streamId);
  final int streamId;
}

class ErrorEvent extends IdrEvent {
  const ErrorEvent(this.code, this.length);
  final int code;
  final int length;
}

IdrEvent? mapNativeEvent(int kind, int sessionId, int streamId, int code, int len) {
  switch (kind) {
    case idrEventConnected:
      return ConnectedEvent(sessionId);
    case idrEventStreamOpened:
      return StreamOpenedEvent(sessionId, streamId);
    case idrEventBytesAvailable:
      return BytesAvailableEvent(streamId, len);
    case idrEventStreamClosed:
      return StreamClosedEvent(streamId);
    case idrEventError:
      return ErrorEvent(code, len);
    default:
      return null;
  }
}
