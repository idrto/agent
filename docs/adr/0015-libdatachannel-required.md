# ADR-0015: libdatachannel required for Source WebRTC

## Status

Accepted

## Context

C ABI defaulted to `use_mock=1` / `AutoOkPeer`. Native `use_mock=0` was rejected. This was fine for FFI unit tests but not a product data plane.

## Decision

1. Product Source path uses **libdatachannel** via `idr-webrtc` `NativePeer` (`PeerTransport` offerer).
2. Target answerer remains libdatachannel (`--features webrtc`).
3. `use_mock=1` is **unit/FFI test only** — not a product SDK mode. Dart defaults `useMock: false`.
4. CI builds native with cmake/ninja (extend `webrtc` job to `idr-c-api --features native`).

## Consequences

Mobile/desktop embeds must ship a cmake-built native library. In-process mocks stay under test features only.
