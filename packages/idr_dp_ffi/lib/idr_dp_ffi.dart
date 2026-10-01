/// Dart bindings for the `idr_dp_*` crypto C ABI (`idr-dp-ffi` crate).
///
/// Load from the standalone `idr_dp` library or from `idr_c_api`, which
/// re-exports the same symbols so Source ships a single native library.
library idr_dp_ffi;

export 'src/crypto.dart';
export 'src/idr_dp_crypto.dart';
export 'src/jwk.dart';
