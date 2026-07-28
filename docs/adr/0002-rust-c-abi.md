# ADR-0002: Rust core with stable C ABI (later)

## Context
Mobile embeds (Flutter/Dart) need a stable native boundary without exposing Rust layouts.

## Decision
Implement logic in Rust crates (`idr-core`, `idr-source`, …). Add `idr-c-api` opaque handles in Phase 5. Error categories live in `idr-core::IdrErrorKind` now for ABI mapping.

## Alternatives
- Pure Dart WebRTC
- C++ core

## Consequences
FFI copying first; batched events; abi_version/struct_size on config structs.

## Migration impact
`crates/idr-c-api` + `packages/idr_core_ffi` / `idr_client` land in Phase 5 (mock backend first).

## Unresolved
Exact ABI surface for metrics and admin IPC; native `use_mock=0` wiring.
