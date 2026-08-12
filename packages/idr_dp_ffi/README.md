# idr_dp_ffi (deprecated)

`IdrDpCrypto` now lives in [`idr_target`](../../../idr_target). Depend on that package instead:

```dart
import 'package:idr_target/idr_target.dart';

final target = IdrTarget(config: config); // uses IdrDpCrypto by default
```

This package only re-exports `IdrDpCrypto` for older imports.

Build native lib: `cargo build -p idr-dp-ffi --release` in `agent/`.
