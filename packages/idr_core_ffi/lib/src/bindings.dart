import 'dart:ffi';

import 'package:ffi/ffi.dart';

import 'types.dart';

final class IdrEngineConfigNative extends Struct {
  @Uint32()
  external int abiVersion;

  @Uint32()
  external int structSize;

  @Uint32()
  external int useMock;

  external Pointer<Utf8> sourceId;

  external Pointer<Utf8> sourceRegion;

  external Pointer<Utf8> authToken;

  @Uint32()
  external int authMode;

  external Pointer<Utf8> discoveryUrl;

  external Pointer<Utf8> discoveryKey;

  @Uint32()
  external int insecureDev;
}

final class IdrEventNative extends Struct {
  @Uint32()
  external int kind;

  @Uint64()
  external int sessionId;

  @Uint64()
  external int streamId;

  @Uint32()
  external int code;

  @Uint32()
  external int len;
}

typedef AbiVersionC = Uint32 Function();
typedef AbiVersionDart = int Function();

typedef EngineCreateC = Pointer<Void> Function(Pointer<IdrEngineConfigNative>);
typedef EngineCreateDart = Pointer<Void> Function(Pointer<IdrEngineConfigNative>);

typedef EngineDestroyC = Void Function(Pointer<Void>);
typedef EngineDestroyDart = void Function(Pointer<Void>);

typedef ConnectC = Int32 Function(
  Pointer<Void>,
  Pointer<Utf8>,
  Pointer<Uint64>,
);
typedef ConnectDart = int Function(
  Pointer<Void>,
  Pointer<Utf8>,
  Pointer<Uint64>,
);

typedef DisconnectC = Int32 Function(Pointer<Void>, Uint64);
typedef DisconnectDart = int Function(Pointer<Void>, int);

typedef SessionNamedServicesC = Int32 Function(
  Pointer<Void>,
  Uint64,
  Pointer<Utf8>,
  IntPtr,
);
typedef SessionNamedServicesDart = int Function(
  Pointer<Void>,
  int,
  Pointer<Utf8>,
  int,
);

typedef OpenStreamC = Int32 Function(
  Pointer<Void>,
  Uint64,
  Pointer<Utf8>,
  Pointer<Uint64>,
);
typedef OpenStreamDart = int Function(
  Pointer<Void>,
  int,
  Pointer<Utf8>,
  Pointer<Uint64>,
);

typedef StreamWriteC = Int32 Function(
  Pointer<Void>,
  Uint64,
  Uint64,
  Pointer<Uint8>,
  IntPtr,
  Pointer<IntPtr>,
);
typedef StreamWriteDart = int Function(
  Pointer<Void>,
  int,
  int,
  Pointer<Uint8>,
  int,
  Pointer<IntPtr>,
);

typedef StreamReadC = Int32 Function(
  Pointer<Void>,
  Uint64,
  Uint64,
  Pointer<Uint8>,
  IntPtr,
  Pointer<IntPtr>,
);
typedef StreamReadDart = int Function(
  Pointer<Void>,
  int,
  int,
  Pointer<Uint8>,
  int,
  Pointer<IntPtr>,
);

typedef StreamHalfCloseC = Int32 Function(Pointer<Void>, Uint64, Uint64);
typedef StreamHalfCloseDart = int Function(Pointer<Void>, int, int);

typedef StreamResetC = Int32 Function(Pointer<Void>, Uint64, Uint64, Uint16);
typedef StreamResetDart = int Function(Pointer<Void>, int, int, int);

typedef PollEventsC = Int32 Function(
  Pointer<Void>,
  Pointer<IdrEventNative>,
  IntPtr,
  Pointer<IntPtr>,
);
typedef PollEventsDart = int Function(
  Pointer<Void>,
  Pointer<IdrEventNative>,
  int,
  Pointer<IntPtr>,
);

typedef SetDpIdentityC = Int32 Function(Pointer<Void>, Pointer<Utf8>);
typedef SetDpIdentityDart = int Function(Pointer<Void>, Pointer<Utf8>);

typedef LastErrorCodeC = Uint32 Function();
typedef LastErrorCodeDart = int Function();

typedef LastErrorMessageC = Int32 Function(Pointer<Utf8>, IntPtr);
typedef LastErrorMessageDart = int Function(Pointer<Utf8>, int);

/// Lookup table for `libidr_c_api` symbols.
class IdrBindings {
  IdrBindings(DynamicLibrary lib)
      : abiVersion = lib.lookupFunction<AbiVersionC, AbiVersionDart>('idr_abi_version'),
        engineCreate =
            lib.lookupFunction<EngineCreateC, EngineCreateDart>('idr_engine_create'),
        engineDestroy =
            lib.lookupFunction<EngineDestroyC, EngineDestroyDart>('idr_engine_destroy'),
        connect = lib.lookupFunction<ConnectC, ConnectDart>('idr_connect'),
        disconnect = lib.lookupFunction<DisconnectC, DisconnectDart>('idr_disconnect'),
        sessionNamedServices = lib.lookupFunction<SessionNamedServicesC,
            SessionNamedServicesDart>('idr_session_named_services'),
        sessionNamedServiceCatalog = lib.lookupFunction<SessionNamedServicesC,
            SessionNamedServicesDart>('idr_session_named_service_catalog'),
        openStream = lib.lookupFunction<OpenStreamC, OpenStreamDart>('idr_open_stream'),
        streamWrite = lib.lookupFunction<StreamWriteC, StreamWriteDart>('idr_stream_write'),
        streamRead = lib.lookupFunction<StreamReadC, StreamReadDart>('idr_stream_read'),
        streamHalfClose =
            lib.lookupFunction<StreamHalfCloseC, StreamHalfCloseDart>('idr_stream_half_close'),
        streamReset = lib.lookupFunction<StreamResetC, StreamResetDart>('idr_stream_reset'),
        pollEvents = lib.lookupFunction<PollEventsC, PollEventsDart>('idr_poll_events'),
        setDpIdentity =
            lib.lookupFunction<SetDpIdentityC, SetDpIdentityDart>('idr_engine_set_dp_identity'),
        lastErrorCode =
            lib.lookupFunction<LastErrorCodeC, LastErrorCodeDart>('idr_last_error_code'),
        lastErrorMessage =
            lib.lookupFunction<LastErrorMessageC, LastErrorMessageDart>('idr_last_error_message');

  final AbiVersionDart abiVersion;
  final EngineCreateDart engineCreate;
  final EngineDestroyDart engineDestroy;
  final ConnectDart connect;
  final DisconnectDart disconnect;
  final SessionNamedServicesDart sessionNamedServices;
  final SessionNamedServicesDart sessionNamedServiceCatalog;
  final OpenStreamDart openStream;
  final StreamWriteDart streamWrite;
  final StreamReadDart streamRead;
  final StreamHalfCloseDart streamHalfClose;
  final StreamResetDart streamReset;
  final PollEventsDart pollEvents;
  final SetDpIdentityDart setDpIdentity;
  final LastErrorCodeDart lastErrorCode;
  final LastErrorMessageDart lastErrorMessage;

  void ensureAbiCompatible() {
    final v = abiVersion();
    if (v != idrAbiVersion) {
      throw StateError('ABI mismatch: native=$v dart=$idrAbiVersion');
    }
  }
}
