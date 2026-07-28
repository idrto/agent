# idr-c-api — stable C ABI for the Source Agent

Header: [`include/idr.h`](include/idr.h)

## Design

- Opaque `idr_engine_t`
- Config carries `abi_version` + `struct_size`
- Batched `idr_poll_events` (no per-packet Dart callbacks)
- Thread-local last error via `idr_last_error_code` / `idr_last_error_message`

## Mock vs native

| `use_mock` | Behavior |
|------------|----------|
| `1` | In-process mock signaling + echo peer (CI / Dart integration) |
| `0` | Reserved for native WebRTC offerer (not linked yet) |

```bash
cargo test -p idr-c-api
cargo build -p idr-c-api --release
# → target/release/libidr_c_api.{so,dylib,a} / idr_c_api.dll
```
