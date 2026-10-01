# idr_dp_ffi

Dart FFI over the `idr_dp_*` C ABI (`crates/idr-dp-ffi`). One crypto surface
(`IdrCrypto`) for Source and Target: Ed25519 keygen, SKI, PKCS#10 CSR, PoP
signatures, CA cert rebuild, CSR signing.

```bash
cargo build -p idr-dp-ffi --release            # standalone idr_dp.{dll,so,dylib}
cargo build -p idr-c-api --release --features native   # also exports idr_dp_* (Source)
```

```dart
final crypto = IdrDpCrypto.open();             // IDR_DP_LIB / exe dir / target/
final crypto = IdrDpCrypto.fromLibrary(lib);   // reuse an already-open idr_c_api
```
