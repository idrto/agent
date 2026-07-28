# ADR-0001: Single agent monorepo

## Context
Source and Target agents share protocol, WebRTC mux, and auth concepts. Code lived in `target-quic` with Presence/Relay as siblings.

## Decision
Use `idrto/agent` as the Source+Target monorepo. Presence and Relay remain separate service repos; sync `idr-protocol` until they depend on it.

## Alternatives
- Keep Target-only repo + separate Source repo
- Absorb Presence/Relay into the monorepo

## Consequences
Shared CI and crates; clearer Source/Target boundaries via crate deps.

## Migration impact
Phase 1 port from `target-quic`; **Phase 6 cutover complete** — donor archived; `idrto/agent` is sole agent monorepo.

## Unresolved
When Presence/Relay switch from copied `src/protocol/` to a path/git dependency on `idr-protocol`.
