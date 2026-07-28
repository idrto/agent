# Stream mux test vectors

Hex encodings are length-prefixed frames (`u32 BE len || postcard`).

Generated and checked by `idr_protocol::stream_mux` tests / `tests/stream_vectors.rs`.

| File | Frame |
|------|-------|
| `open_tls.hex` | Open stream_id=1 TlsPassthrough |
| `data_hello.hex` | Data stream_id=1 bytes=`hello` |
| `open_ok.hex` | OpenOk stream_id=1 window=262144 |
| `window_update.hex` | WindowUpdate stream_id=1 credit=4096 |
| `ping.hex` | Ping opaque=1 |
| `pong.hex` | Pong opaque=1 |

Regenerate:

```bash
cargo test -p idr-protocol write_stream_vectors -- --ignored
```
