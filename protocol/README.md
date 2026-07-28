# Protocol specifications

| Spec | Path |
|------|------|
| Stream mux v1 | [`idr-stream-v1.md`](./idr-stream-v1.md) |
| Test vectors | [`test-vectors/`](./test-vectors/) |

Signaling / auth markdown specs land in later phases. Until then, JSON signaling types live in `crates/idr-protocol` and are duplicated in presence/relay.

Wire formats of record:

- `agent/crates/idr-protocol` (canonical)
- `presence/src/protocol/` and `relay/src/protocol/` (synced copies)
