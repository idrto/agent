/// Deprecated entrypoint — desktop crypto lives in `package:idr_target`.
///
/// Prefer: `import 'package:idr_target/idr_target.dart';` then [IdrDpCrypto].
library idr_dp_ffi;

export 'package:idr_target/idr_target.dart' show IdrDpCrypto, IdrCrypto, Ed25519KeyMaterial;
