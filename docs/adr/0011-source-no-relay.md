# ADR-0011: Source never uses Relay edge for application data

## Context
Relay provides browser/`*.idr.to` edge. Source Agents should be P2P.

## Decision
Source data plane is WebRTC only. Signaling via Presence only. `idr-source` must not depend on `idr-target` (enforced in CI).

## Alternatives
- Source HTTP via Relay
- Dual-path Source with automatic fallback to Relay HTTP

## Consequences
TURN may still relay ICE; that is not the idr Relay edge.

## Migration impact
Phase 3 crate split + dependency check.

## Unresolved
Optional future “Relay data plane” product mode (out of scope).
