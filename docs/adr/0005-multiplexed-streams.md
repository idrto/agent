# ADR-0005: Multiplexed logical streams

## Context
Need many TCP-like flows over one DC.

## Decision
Continue `[u32 BE][postcard(StreamFrame)]` mux (`idr-stream-v1`). Source uses odd stream ids. Extend frames in Phase 4 (OPEN_OK, WINDOW_UPDATE, …).

## Alternatives
- New TLV framing from scratch
- One DC per stream

## Consequences
Must stay wire-compatible with Target/Presence copies during rollout.

## Migration impact
Phase 4 protocol evolution with bridge.

## Unresolved
Control channel vs payload channel split.
