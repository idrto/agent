# idr-dp-ffi

C ABI for Target desktop crypto (`IdrCrypto` via Dart `idr_dp_ffi`).

## Build (desktop)

```bash
cd agent
cargo build -p idr-dp-ffi --release
```

| Platform | Artifact |
|----------|----------|
| Windows | `target/release/idr_dp.dll` |
| macOS | `target/release/libidr_dp.dylib` |
| Linux | `target/release/libidr_dp.so` |

Header: [`include/idr_dp.h`](include/idr_dp.h).

## Symbols

- `idr_dp_generate_ed25519` → JSON key material
- `idr_dp_build_csr` → CSR PEM
- `idr_dp_sign` / `idr_dp_sign_json` → base64url signature
- `idr_dp_ski` → subject key id
- `idr_dp_sign_csr` → JSON `{leaf_pem, chain_pem}` (CSR + CA private JWK + issuer SKI)
- `idr_dp_string_free` / `idr_dp_last_error`
