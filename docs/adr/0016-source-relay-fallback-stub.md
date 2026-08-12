# ADR-0016: Future Source Relay data-plane fallback (stub)

## Status

Proposed (not implemented)

## Context

[ADR-0011](0011-source-no-relay.md) forbids Source→Relay for application data in v1. Some environments may later need a Relay edge when P2P/TURN cannot establish.

## Decision (deferred)

v1 ships **WebRTC/TURN only**. A future ADR may introduce an optional Source Relay data plane behind explicit entitlement and UX, without reopening free/anonymous routes.

## Consequences

No Relay fallback code in `idr-source` / Dart SDK until that ADR is accepted. `scripts/check-source-no-relay.sh` remains green.
