# idr-c-api — stable C ABI for the Source Agent

Header: [`include/idr.h`](include/idr.h)

## Design

- Opaque `idr_engine_t`
- Config carries `abi_version` + `struct_size`
- Batched `idr_poll_events` (no per-packet Dart callbacks)
- Thread-local last error via `idr_last_error_code` / `idr_last_error_message`
- **`auth_token` required** (Bearer / device token). Anonymous is not a product mode.

## Mock vs native

| `use_mock` | Behavior |
|------------|----------|
| `1` | Unit/FFI test mock only (still requires `auth_token`) |
| `0` | Native libdatachannel offerer + Presence QUIC (`--features native`) |

```bash
cargo test -p idr-c-api
cargo build -p idr-c-api --release
cargo build -p idr-c-api --release --features native   # needs cmake + libdatachannel
# → target/release/libidr_c_api.{so,dylib,a} / idr_c_api.dll
```
