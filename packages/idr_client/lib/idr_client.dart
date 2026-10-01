/// Thin Dart Source Agent API — no localhost proxy required.
library idr_client;

export 'package:idr_core_ffi/idr_core_ffi.dart'
    show idrAuthBearer, idrAuthDeviceToken, idrAuthMtls;

export 'src/catalog.dart';
export 'src/errors.dart';
export 'src/events.dart';
export 'src/runtime.dart';
export 'src/session.dart';
export 'src/stream.dart';
