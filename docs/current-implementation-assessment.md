# Current implementation assessment

**Date:** 2026-07-28  
**Assessor scope:** Donor tree `idrto/target-quic` + empty monorepo `idrto/agent`  
**Sibling services (not moved):** `idrto/presence`, `idrto/relay`

This is Phase 0 of the agent monorepo migration. No application code has been ported into `agent` yet.

---

## 1. Current repository structure

### `idrto/agent` (this repo)

| Item | Status |
|------|--------|
| Working tree | Empty except Phase 0 docs / `protocol/` placeholder |
| Git remote | `https://github.com/idrto/agent.git` (description: “Source Agent lib”) |
| Commits | None on `main` at assessment start |
| Cargo / Melos / src | Absent |

### `idrto/target-quic` (donor — Target Agent)

Single-crate Rust project (not a workspace):

```text
target-quic/
├── Cargo.toml                 # package target-quic + bins target-quic, mock-presence
├── rust-toolchain.toml        # stable
├── .cargo/config.toml         # Windows ARM Clang CC/CXX overrides
├── deny.toml
├── config/target.example.toml
├── migrations/                # 001_initial.sql, 002_webrtc.sql
├── src/
│   ├── main.rs                # Target agent entry
│   ├── lib.rs                 # library modules
│   ├── bin/mock_presence.rs
│   ├── protocol/              # duplicated across presence + relay
│   ├── presence/              # discovery, QUIC/WSS clients, registration
│   ├── quic/                  # Target→Relay Quinn client
│   ├── relay/                 # connection table, idle, readiness
│   ├── tunnel/                # Relay→nginx bridge
│   ├── acme/                  # custom-domain Let's Encrypt
│   ├── webrtc/                # answerer, mux, bridge (feature-gated peer)
│   ├── storage/, telemetry/, identity, config, shutdown, network
├── tests/                     # 5 integration suites
├── benches/
├── docs/                      # ARCHITECTURE, PROTOCOL, WEBRTC, TLS_PASSTHROUGH
├── scripts/
└── .github/workflows/ci.yml
```

**Scale:** ~67 Rust source files under `src/`, ~8.8k lines; 15 protocol files; 10 WebRTC module files.

---

## 2. Languages, frameworks, and build systems

| Layer | Choice |
|-------|--------|
| Language | Rust 2021 (`rust-version = "1.76"`; local toolchain 1.96) |
| Async | Tokio (full) |
| QUIC | Quinn 0.11 + rustls (aws-lc-rs) |
| Presence WSS | tokio-tungstenite |
| Serialization | serde_json (signaling), postcard (QUIC control, tunnels, DC mux) |
| Crypto | ed25519-dalek, sha2, rcgen |
| Storage | rusqlite (bundled) + WAL |
| ACME | instant-acme |
| WebRTC | optional `datachannel` from `github.com/idrto/datachannel-rs` @ `519a790` (`--features webrtc`, vendored) |
| Metrics | prometheus |
| Build | Cargo single package; release: thin LTO, `codegen-units = 1` |
| CI | GitHub Actions: fmt, clippy `--all-features`, test, doc, release, cargo-deny |
| Dart / Melos / CMake app tree | None |
| Packaging (deb/msi/apk) | None in-repo |

---

## 3. Current Source-Agent implementation

**None in `agent` or `target-quic`.**

Protocol types reference Source agents (`SourceAgentIdentity`, `SourceAuthMode::{Mtls, Anonymous}`, WebRTC session request messages). Docs describe Source as external “Browser/Desktop/Mobile SDKs using libdatachannel.”

**Classification:** *missing — implement in `agent` as new minimal Source crates (Phase 3+).*

---

## 4. Current Target-Agent implementation

**Entire `target-quic` crate is the Target Agent.**

Responsibilities today:

1. Load TOML config (`IDR_CONFIG`), Ed25519 target identity, billing party pair.
2. Fetch/verify signed Presence discovery; dual-mod placement → primary/secondary Presence (`N >= 2`).
3. Register over Presence QUIC (`idr-presence-v1`) with WSS fallback; advertise WebRTC caps only if feature compiled + enabled.
4. On `ensure_relay_connection`: dial Relay QUIC (`idr-relay-v1`), auth with short-lived token, maintain connection table.
5. Accept Relay-opened tunnel bi-streams → bridge to local nginx (`tls_upstream` / `http_upstream`).
6. Optional ACME HTTP-01 for **custom domains only** (not `*.idr.to`).
7. Optional WebRTC **answerer**: Presence-signed offer → libdatachannel → DataChannel `idr-stream-v1` mux → nginx / TcpConnect.

**Classification:**

| Component | Classification |
|-----------|----------------|
| Presence client + registration | retain with adaptation → `idr-target` / `idr-signaling` |
| Relay QUIC client + table | retain with adaptation → Target-only (Source must not depend) |
| Tunnel → nginx | retain with adaptation → `idr-target-connectors` |
| ACME custom domains | retain with adaptation |
| WebRTC answerer | retain with adaptation → shared `idr-webrtc` + Target host |
| `mock-presence` bin | retain for tests |
| Single-crate layout | replace gradually with Cargo workspace in `agent` |

---

## 5. WebRTC, ICE, STUN, TURN, DTLS, SCTP, signaling

| Piece | Location | Status |
|-------|----------|--------|
| WebRTC signaling JSON types | `src/protocol/webrtc_signaling.rs` | Done; synced with presence/relay |
| ICE / DC label+protocol constants | `src/protocol/webrtc_ice.rs` | `idr-stream-v1` / `idr.stream/1` |
| Stream mux | `src/protocol/stream_mux.rs` | Open/Data/HalfClose/Reset; postcard + u32 BE length |
| Session manager / ICE inbox | `src/webrtc/session_manager.rs` | Done |
| Native peer (libdatachannel) | `src/webrtc/peer.rs` | Feature `webrtc` |
| Responder session loop | `src/webrtc/session.rs` | Done |
| Offer handler | `src/webrtc/signaling_handler.rs` | Verifies Presence-signed offers |
| Bridge to TCP | `src/webrtc/bridge.rs` | nginx + policy TcpConnect |
| TURN probe | `src/webrtc/probe/` | STUN binding / probe reports |
| Modes | config `platform` / `byor` / `hybrid` | Done |

**Not present:** PeerTransport trait; control vs bulk DataChannels; OPEN_OK / WINDOW_UPDATE; Source offerer; DTLS fingerprint binding in app handshake.

**Classification:** retain with adaptation; wrap peer behind transport trait; extend mux (do not discard).

---

## 6. HTTP or SOCKS proxy implementations

**None** (no HTTP CONNECT / SOCKS4/4a/5 client proxies).

nginx `proxy_pass` appears only in ACME/nginx config examples for apps behind Target.

**Classification:** missing — Source desktop adapters later (`idr-proxy-http` / `idr-proxy-socks`); not required for mobile-first Source.

---

## 7. Dart or Flutter packages

**None.**

**Classification:** missing — add under `packages/` after C ABI (Phase 5); mobile-first `idr_client`.

---

## 8. C / C++ / Rust / Dart / Kotlin / Swift bindings

| Binding | Status |
|---------|--------|
| Rust public lib `target_quic` | Exists (internal modules; not a stable API) |
| C ABI / cdylib | None |
| Dart FFI | None |
| Kotlin / Swift | None |
| C++ | Only via libdatachannel inside optional native peer |

**Classification:** missing ABI — add `idr-c-api` for mobile; keep unsafe isolated.

---

## 9. Public APIs and ABI boundaries

Today the “API” is:

- Binary + TOML config
- Prometheus `/metrics`
- Wire protocols shared with Presence/Relay (JSON signaling, postcard frames)

No versioned Rust semver API, no C ABI, no Dart package.

**Classification:** wrap behind new interfaces during workspace split; deprecate ad-hoc `target_quic::` re-exports gradually.

---

## 10. Protocol definitions

Documented in `target-quic/docs/PROTOCOL.md` (+ WEBRTC, TLS_PASSTHROUGH).

| Plane | Framing | Notes |
|-------|---------|-------|
| Presence signaling | JSON (QUIC length-prefixed or WSS text) | Register, ensure_relay, WebRTC offer/answer/ICE |
| Relay QUIC control | `[u32 BE][postcard]` | ClientHello / ServerHello / … |
| Edge tunnel | TunnelOpen then raw bytes | TlsPassthrough / HttpPassthrough |
| WebRTC DC mux | `[u32 BE][postcard(StreamFrame)]` | Open/Data/HalfClose/Reset |

**Hard constraint:** `src/protocol/` must match presence and relay byte-for-byte until they consume a shared `idr-protocol` crate.

**Classification:** retain with adaptation → `crates/idr-protocol`; evolve mux frames with compatibility bridge.

---

## 11. Authentication and authorization

| Mechanism | Role |
|-----------|------|
| Ed25519 Target identity | Registration + answer signatures |
| Pinned discovery key | Verify `idr-presence.json` |
| Relay-signed ensure + connection token | Target→Relay QUIC auth |
| Presence-signed WebRTC offers | Target verifies before answering |
| Billing `(using_party, paying_party)` | Forwarded on registration; Presence gates entitlements |
| WebRTC TcpConnect policy | `deny_private_ips`, suffix allowlist |
| Source auth modes in types | Mtls / Anonymous — Source runtime not implemented |
| Target CA roots (Presence) | Reserved; not fully enforced on Target yet |

**Classification:** retain with adaptation; extend for entity CA-Root mTLS (personal/enterprise) and DC-level handshake; do not treat Presence connectivity alone as service auth.

---

## 12. Connection pooling, multiplexing, backpressure, retry

| Area | Behavior |
|------|----------|
| Relay connections | `get_or_connect` per `relay_id`; open-addressing table; idle timeout; retry backoff |
| QUIC streams | Native multi-stream; Relay opens tunnels |
| WebRTC | One DC multiplexed logical streams |
| Backpressure | Bounded event queue on native peer callbacks (`try_send`); **no** per-stream WINDOW_UPDATE / connection windows yet |
| Presence reconnect | Exponential backoff |

**Classification:** retain pooling/retry; wrap mux; **add** explicit flow-control (gap).

---

## 13. Tests and CI

**Integration tests:** `duplicate_signaling`, `presence_placement`, `relay_table`, `tls_passthrough`, `webrtc_signaling`  
**Unit tests:** embedded in modules (e.g. stream_mux encode/decode)  
**Benches:** relay_table, signaling_dedup, idle_scheduler  
**CI:** fmt, clippy `-D warnings` all-features, test, doc, release, cargo-deny  

**Baseline run (2026-07-28):** see §16 — **could not produce green binaries** on this workstation; compile errors in current working tree.

**Classification:** retain and adapt to workspace CI; add protocol-vector / Source tests later.

---

## 14. Packaging for Windows, macOS, Linux, Android, iOS

| Platform | Status |
|----------|--------|
| Linux | Primary CI target; `scripts/check-native-linux.sh` for WebRTC |
| Windows | `.cargo/config.toml` Clang for aws-lc; IMPLEMENTATION_REPORT notes ARM needs LLVM+MSVC libs |
| macOS | Not packaged; expected to build via Cargo |
| Android / iOS | None |

**Classification:** desktop service packaging later; mobile via embedded FFI first.

---

## 15. Technical debt, duplication, conflicts, missing abstractions

1. **Protocol triplication** across target-quic / presence / relay.
2. **Dual data planes** (Relay QUIC vs WebRTC) without a shared stream/connector abstraction.
3. **No Source implementation** while types assume one.
4. **Mux protocol incomplete** vs target architecture (no OPEN_OK, flow control, version negotiation).
5. **Named services absent** — fixed nginx upstreams + optional TcpConnect host:port.
6. **TLS story docs** still emphasize Relay terminate for `*.idr.to`; product direction adds mTLS (personal/enterprise) and Source-WebRTC-only paths.
7. **Working-tree compile failures** (see baseline) — must fix during or before Phase 1 port.
8. **Windows `.cargo` CC env** breaks WSL builds that share the tree unless `CC`/`CXX` overridden.
9. **No stable API boundary** for embedding Target in apps.

---

## 16. Baseline build / test results (2026-07-28)

| Environment | Command | Result |
|-------------|---------|--------|
| Windows ARM64 MSVC | `cargo test` / `cargo build --release` | **Fail** — `aws-lc-sys` cannot link (`libcmt.lib` / `oldnames.lib` missing; Clang without full VS libs) |
| WSL2 Ubuntu aarch64 | `CARGO_TARGET_DIR=/tmp/... CC=cc cargo test` | **Fail** — lib/libtest compile errors (see below) |
| WSL2 | `CC=cc cargo build --release` | **Fail** — 4 lib errors |
| Docker | — | Daemon not running |
| Binary size / idle RSS | — | **Not measured** (no successful release artifact) |

**WSL host:** aarch64, 8 CPUs, ~7.5 GiB RAM, rustc 1.96.0.

**Release lib errors observed:**

1. `E0373` — async block borrows `code` (lifetime) — location in ACME or related path from prior diagnostics.
2. `WebRtcPolicyConfig: Default` not satisfied (2 sites).
3. `AtomicU64: Clone` via `#[derive(Clone)]` on probe state (`src/webrtc/probe/mod.rs`).

**Test-only additional error:** `AcmeManager` missing `Debug` for `unwrap_err` in unit test.

**Implication for Phase 1:** Port must include fixing these compile breaks (or port a known-good revision). Record binary sizes immediately after first green release build in `agent`.

---

## Component classification summary

| Component | Action |
|-----------|--------|
| Presence discovery/register/QUIC/WSS | retain with adaptation |
| Relay QUIC path | retain with adaptation (Target-only) |
| Tunnel/nginx bridge | retain with adaptation → connectors |
| ACME custom domain | retain with adaptation |
| WebRTC answerer + libdatachannel | retain with adaptation; wrap trait |
| stream_mux v1 frames | retain with adaptation; extend |
| Protocol module copy | wrap → `idr-protocol`; sync then publish |
| SQLite / metrics / shutdown | retain with adaptation |
| mock-presence | retain |
| Source Agent | implement new (minimal, mobile-first) |
| HTTP/SOCKS proxies | implement later (optional desktop) |
| C ABI / Dart | implement after Source core |
| Monorepo Melos tree | introduce incrementally; not day-one |
| target-quic repo | deprecate after successful port + user confirmation |

**Do not delete** Relay QUIC or Presence registration when adding Source WebRTC — browsers and non-Source clients still need the edge path.
