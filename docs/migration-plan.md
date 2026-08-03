# Migration plan

**Date:** 2026-07-28  
**Destination:** `idrto/agent` monorepo  
**Donor:** `idrto/target-quic` (**deprecated / archived** after Phase 6 cutover)  

---

## Goals

1. Make `agent` the Source + Target agent monorepo.
2. Port working Target functionality from `target-quic`.
3. Add a **minimal, mobile-first Source** that uses **WebRTC only** (Presence signaling, P2P/TURN data).
4. Keep Relay as a **Target/browser** path only.
5. Evolve protocol/mux incrementally; keep presence/relay wire-compatible during transition.

---

## Phase 0 — Assessment (current)

- [x] Inspect empty `agent` and donor `target-quic`
- [x] Document inventory + classifications → [current-implementation-assessment.md](./current-implementation-assessment.md)
- [x] Gap analysis → [architecture-gap-analysis.md](./architecture-gap-analysis.md)
- [x] Security / threat stubs → [security-model.md](./security-model.md), [threat-model.md](./threat-model.md)
- [x] Attempt baseline build/test; record failures and environment limits
- [ ] Binary size / idle memory — **blocked** until first green release build (Phase 1)

**Exit:** Docs merged in `agent`; stakeholders agree on locked rules (WebRTC-only Source, TLS modes).

---

## Phase 1 — Port Target into `agent` workspace

1. Create root `Cargo.toml` workspace.
2. Move/adapt:
   - `crates/idr-protocol` ← `src/protocol`
   - `crates/idr-target` ← remaining library modules
   - `services/target-agent` ← `main.rs` binary
   - config, migrations, docs (Target-relevant), CI, deny.toml, scripts
3. Fix compile errors present on donor tree (Debug/Default/Clone/async lifetime).
4. Make Windows `.cargo` CC overrides **Windows-only** so Linux/WSL builds are not poisoned.
5. Prove: `cargo test --workspace`, release build default + `--features webrtc` (Linux CI).
6. Record binary sizes in `docs/baselines.md`.
7. Keep `target-quic` repo intact (mirror / dual-track).

**Status (2026-07-28):** Complete for default features.

- [x] Workspace + crates/services laid out
- [x] Protocol extracted; `WebRtcSessionOffer::verify_presence_signature` lives in `idr-protocol`
- [x] Donor compile fixes applied in the port
- [x] `.cargo` no longer forces Windows Clang on Linux/WSL
- [x] `cargo test --workspace --all-targets` green (WSL aarch64)
- [x] `cargo build --workspace --release` green; sizes in [baselines.md](./baselines.md)
- [ ] `--features webrtc` release build — blocked here by missing `cmake`; expected to pass on CI with native deps
- [x] `target-quic` left untouched for dual-track

**Exit:** Target agent runs from `agent` with equivalent config semantics.

---

## Phase 2 — Interfaces without behavior break

1. `PeerTransport` + session/stream/connector traits.
2. Adapters around existing WebRTC answerer and Relay tunnel bridges.
3. ADRs under `docs/adr/` for monorepo, libdatachannel, persistent PC, mux, named services, Source-no-Relay, mTLS vs LE, Leg 2 QUIC (ADR-0012), no Source MITM, flow control.
4. Error category enum shared by future C ABI.

**Status (2026-07-28):** Complete.

- [x] `idr-core` — `IdrErrorKind`, `PeerSession`/`LogicalStream`, `Connector`/`ConnectorRegistry`, `BoundedQueue`
- [x] `idr-webrtc` — `PeerTransport` + mock/recording transports
- [x] `NginxBridgeConnector` adapter in `idr-target`
- [x] ADRs 0001–0012 under `docs/adr/`

**Exit:** Same Target runtime behavior; clearer crate boundaries.

---

## Phase 3 — Minimal Source (mobile-first)

1. `idr-signaling` + `idr-webrtc` + `idr-source`.
2. Flow: discovery → Presence ephemeral WebRTC session request → DC open → mux OPEN to service.
3. **Hard invariant:** Source crates must not depend on Relay QUIC / ACME / edge tunnel code (CI check).
4. Public Rust API kept small: connect, open_stream(service), read/write/half-close/reset.
5. Feature flags strip desktop-only code for mobile builds.
6. Unit tests with mock Presence + codec vectors.

**Status (2026-07-28):** Complete for mock-backed path.

- [x] `idr-signaling` — discovery HTTP client + ephemeral signaling traits + mock
- [x] `idr-source` — `SourceRuntime` / `SourceSession` (WebRTC-only)
- [x] CI `scripts/check-source-no-relay.sh`
- [x] Tests: mux OPEN frame on `open_named_stream`, unknown service error
- [ ] Real Presence QUIC ephemeral client + native offerer — Phase 4/5 follow-on when cmake/libdatachannel available for Source builds

**Exit:** Source can open a logical stream against mock signaling/transport in controlled tests.

---

## Phase 4 — Stream protocol + flow control

1. Write `protocol/idr-stream-v1.md` documenting **evolution of** current mux (not a silent break).
2. Add OPEN_OK / OPEN_ERROR, WINDOW_UPDATE, PING/PONG, GOAWAY, version negotiation, odd/even stream IDs.
3. Compatibility bridge for peers that only speak Open/Data/HalfClose/Reset.
4. Bounded queues + windows on Source and Target.
5. Sync `idr-protocol` into presence/relay (path dep or copy update).

**Status (2026-07-28):** Complete.

- [x] Spec: [`protocol/idr-stream-v1.md`](../protocol/idr-stream-v1.md)
- [x] Hex vectors under `protocol/test-vectors/`
- [x] Extended `StreamFrame` (append-only discriminants); `MuxProfile::{Legacy,FlowControlV1}`
- [x] `idr_core::FlowController` + Source write backpressure
- [x] Target answerer sends `OpenOk`, handles Ping/WindowUpdate/Hello
- [x] Source waits briefly for `OpenOk` then falls back to legacy
- [x] Synced `stream_mux.rs` into presence + relay copies

**Exit:** Interop vectors + tests; no unbounded buffering on DC path.

---

## Phase 5 — ABI, Dart, optional proxies

1. `idr-c-api` opaque handles + batched event drain.
2. Dart `idr_client` direct streams (+ thin HTTP helper); Melos when packages exist.
3. Optional HTTP CONNECT / SOCKS adapters and embedded loopback proxy (**desktop / third-party**).
4. Thin Source desktop service + admin IPC (later than embedded).

**Status (2026-07-28):** Complete for mock-backed embed path (native WebRTC backend still deferred).

- [x] `crates/idr-c-api` — opaque engine, session/stream ids, `abi_version`/`struct_size`, batched `idr_poll_events`, last-error
- [x] Mock backend (feature `mock`) for CI / Dart without cmake+libdatachannel
- [x] `packages/idr_core_ffi` + `packages/idr_client` (Runtime / Session / Stream)
- [x] Optional `packages/idr_http` thin tunnel helper (not a full HttpClient)
- [x] Melos workspace (`melos.yaml`); **proxies not in default SDK**
- [ ] Native libdatachannel offerer behind `use_mock=0` — Phase 5 follow-up / cmake hosts
- [ ] Desktop HTTP CONNECT / SOCKS / admin IPC — deferred

**Exit:** Flutter/Dart can move bytes via C ABI without a localhost proxy (mock-backed until native WebRTC is linked).

---

## Phase 6 — Cut over

1. Update presence/relay docs and links to `idrto/agent`.
2. Tag `agent` release.
3. **User confirmation** → archive/delete `target-quic`.
4. CI cache native libdatachannel artifacts.

**Status (2026-07-28):** Complete.

- [x] Presence + Relay docs/README/CONTRIBUTING point at `agent/crates/idr-protocol`
- [x] `target-quic` marked deprecated (`README.md`, `DEPRECATED.md`); deprecation commit on `main`
- [x] GitHub **archive** of `idrto/target-quic` confirmed (`isArchived: true`, 2026-07-28)
- [x] `agent` tagged + GitHub Release `v0.1.0`
- [x] CI `webrtc` job installs cmake and uses `Swatinem/rust-cache` (caches libdatachannel native build outputs under `target/`)
- [x] Agent README is sole-monorepo banner; donor called out as deprecated/archived

**Exit:** `target-quic` deprecated; `agent` is sole agent monorepo.

---

## Compatibility and risk notes

| Risk | Mitigation |
|------|------------|
| Protocol drift during extract | Automated `diff` job until presence/relay consume crate |
| Breaking WebRTC mux | Version bit / capability negotiation; bridge |
| Source accidentally linking Relay | Separate crate + forbidden dependency lint |
| Mobile binary size (libdatachannel) | Feature flags; measure after Phase 3/5 |
| Donor compile breakage | Fix in Phase 1 before declaring port complete |
| Dual-repo confusion | README banners; stop merging features into `target-quic` after Phase 1 |

---

## First code change after this document

**Phase 1 port** — workspace scaffolding + move Target + fix build. No Source proxies, no Melos, no framing rewrite in that PR set.
