# 08: Implementation Plan

## Release scope

| Release | Phases | Delivers |
|---|---|---|
| **V1** | 1 + 2 | Shared spec and libraries. All clients migrated: local JSONL, rotation, the flight recorder, crash capture and recovery, **local diagnostic bundle export**. In-machine context propagation (Dart ↔ isolates ↔ FFI ↔ spawned agents ↔ IPC). HTTP `traceparent` to Billing plus `x-request-id` capture. Security fixes. Servers: structured JSON to stdout, event and level cleanup, IP truncation, error responses with `trace_id`. Cross-machine correlation by `connection_id`, `transfer_id`, `target.fqhn` and time. |
| **V2** | 3 | Wire `telemetry` on 4 signaling messages (distributed traces). `diag-ingest` upload with consent and the display code. Alloy + Loki + Grafana, dashboards, alerts. Optional Billing `traceparent`. Scenario replay against a staging stack. |

Task IDs are referenced from other documents. Sizes: S ≤ 1 day, M ≤ 3 days, L ≤ 1–2 weeks (one engineer). **Phase 1 started 2026-11-23.**

## Progress (uncommitted, awaiting review)

| Task | State | Notes |
|---|---|---|
| P1-00 | done 2026-11-23 | Docs moved to `agents_engine/agent/docs/observability/`; ADR-0019; `AGENTS.md` + `CLAUDE.md` pointers in the agent, apps, dp-sdk, presence, relay, turn and dns-server repos |
| P1-01 | done 2026-11-23 | `spec/telemetry/`: schema, `events.yaml`, `attributes.yaml`, vectors `ids`, `ctx`, `redaction` (20 cases), `records` (3 golden lines) |
| P1-02 | done 2026-11-23 | `crates/idr-telemetry` `types`: `new_id`, `TraceContext`, `LocalContext`, `Secret<T>`, `redact`, `fields`. 5 vector tests |
| P1-03 | done 2026-11-23 | `subscriber`: layer, record, pipeline + drain, files (run locks, retention, recovery, disk guard), panic hook, `ffi_guard`, `init_from_env`. 12 tests: storage ownership, exit recovery, drain R2-3a/b/c, memory caps, FFI poisoning. Clippy clean. **Not yet measured:** performance budgets (04 §6) — needs a bench (add with P1-23). |
| P1-04 | done 2026-11-23 | `packages/idr_telemetry` (pure Dart, no dependencies): `IdrLog`, Zone spans and correlation IDs, `withIds`/`withContext`/`currentContextJson`, the pipeline and drain (same semantics as Rust), run-locked rotating files, retention, recovery, async disk guard, `runGuarded` + isolate error listener crash records, worker-isolate link (one `app_session_id` per process), `DiagnosticBundle` local zip export. 22 tests (the same shared vectors plus behaviour, a second-process lock holder, drain R2-3a/b/c). Analyzer clean. Found and fixed: the email rule was quadratic in Dart's regex engine (now a linear scan, with a perf test in both languages); retention now manages only its own producer's runs (POSIX lock primitives differ between Rust and Dart), mirrored in Rust. |
| P1-05 | done 2026-11-23 | `packages/idr_telemetry_flutter`: `TelemetryFlutter.init/install` (idempotent), `FlutterError.onError` → `ui.framework.error`, `PlatformDispatcher.onError` → crash record, `AppLifecycleListener` → `app.lifecycle.changed`, `routeObserver` → `ui.screen.viewed` (name only), `path_provider` log root. 2 tests. |
| P1-06 | done 2026-11-23 | `packages/idr_diag`: `validate` (an evaluator for the JSON Schema keywords the record schema uses, plus the registries and a redaction no-op check), `merge [--id]`, `tree --trace`, `open <bundle>`, `lint`. 5 tests, including real Dart output (spans, drain, crash, recovery) validated against the spec. Real Rust output is validated in CI via `examples/sample.rs`. |
| P1-07 | done 2026-11-23 | `scripts/check-telemetry.sh` + the `telemetry` CI job: fmt/clippy `-D warnings`/tests (Rust), analyze `--fatal-infos`/tests (Dart, Flutter), schema validation of real Rust output, lints (registry, banned APIs, secret `Debug`, subscriber and dp-sdk dependency rules). Gate scope in `spec/telemetry/lint.yaml`. The secrets lint found 33 `derive(Debug)` structs: 30 real exposures, allow-listed for P1-10, and 3 public discovery keys. Script passes locally (exit 0). **Note:** the existing workspace `cargo fmt --all --check` step already fails on pre-existing code in other crates (`idr-c-api`, …); `idr-telemetry` itself is formatted. |
| P1-10 | done 2026-11-23 | **Agent:** `Secret<T>` on 11 fields (protocol tokens and credentials, `idr-dp` private PEM/JWK, `idr-target` config and descriptor); `idr-telemetry` `regex` is now optional (feature `redact`) so `idr-protocol` stays light, and wasm builds. Golden test `idr-protocol/tests/secret_wire_golden.rs` proves JSON and postcard bytes are unchanged and that signatures over old-format bytes still verify; it was red before the change. **dp-sdk:** a hand-written redacting `Debug` (`redacted_debug!`) on 16 structs, with no telemetry dependency, plus a test. The secrets allow-list keeps only 3 public discovery keys. |
| P1-11 | done 2026-11-23 | **dp-sdk:** `Error::Http` `Display` shows `HTTP <status>: <code>` only, with a test. **Apps:** `httpFailure()` in `idr_session` replaces 22 raw-body messages in `idr_target`/`idr_source` (code + server message kept for classification; the raw body never appears); 3 new tests; `revoke_test` updated to the new format. `idr_target` passes all 74 tests under `flutter test`. |
| P1-12 | done 2026-11-23 | **New code:** `IdrErrorKind::Panic = 20` (`IDR_ERR_PANIC (-20)` in `idr.h`, `IdrErrorCode.panic` in `idr_core_ffi`, `'panic'` in `idr_client`). **Wrapped:** all 29 `idr-c-api` exports (`guarded!` = `ffi_guard` plus last error `Panic`; `caught!` = `ffi_catch` with no fail-fast, for `idr_last_error_*`, `idr_abi_version`, `idr_engine_destroy`) and all 11 `idr-dp-ffi` exports (`dp_guarded!`/`dp_caught!`, `IDR_DP_ERR_PANIC = -4`). `idr-telemetry::ffi_catch` added. **Test:** `idr-c-api/tests/ffi_panic.rs` (feature `test-hooks`, hidden `idr_test_panic`) proves `-20` is returned, the last error is 20 with a message, a crash record is written, later calls fail fast, and the diagnostics still answer; wired into `check-telemetry.sh`. ABI version unchanged (only a new error code; P1-21 bumps it). **Not covered:** an end-to-end Dart-host test with the built native library (lands with P1-30). |
| P1-20 | done 2026-11-23 | `target-agent`, `source-agent` and `mock-presence` call `idr_telemetry::init_binary` (`IDR_LOG` > `RUST_LOG` (deprecated, with an event) > the config's level; stdout pretty on a TTY, else JSON or off when files are written; files under `IDR_LOG_DIR` or the per-OS default root). `idr-target`'s `init_tracing` and its `tracing-subscriber` dependency are deleted; `IDR_LOG_FILE` truncation is gone. `idr_telemetry::exit` replaces `process::exit` so a run still ends with `app.stopping`. The lint allow-list for `tracing-subscriber` is now only `idr-telemetry`. Smoke-tested: two runs produce schema-valid files, the first one claimed by recovery. |
| P1-21 | done 2026-11-23 | **ABI 4.** `idr_connect`, `idr_open_stream`, `idr_transfer_send`, `idr_transfer_send_selection`, `idr_transfer_resume` take a trailing nullable `ctx_json`; each opens an `ffi.call` span parented from it. New `idr_telemetry_init/flush/shutdown` (the engine writes the `rust.jsonl` producer of the host's run, same `app_session_id`, into the host's directory). `ffi.handle.bound{ffi.handle, connection_id}` is logged on connect. Dart: `idr_core_ffi` bindings and `idrAbiVersion = 4`; `idr_client` adds `ctx` to every isolate request (`currentContextJson`), inits engine telemetry on create, shuts it down on dispose, and replaces `developer.log` with `IdrLog` and the `source.connect.attempt` span (D19). **Proven end to end** (`idr_client/test/telemetry_e2e_test.dart`): the Dart trace and `session_id` continue into the engine's `ffi.call` span with the correct parent and the same `app_session_id`. Rust: `ffi_telemetry.rs`. Not yet: `idr_client` events for `connection.established`/`failed` (P1-23). |
| P1-22 | done 2026-11-23 | The Rust field for the wire `session_id` is `connection_id` on 14 message structs (`#[serde(rename = "session_id")]`); the signed-body helper structs keep the `session_id` JSON key. 45 call sites fixed from compiler diagnostics. **Proven:** the golden wire tests (JSON and postcard bytes, signatures over old-format bytes) pass unchanged, and `connection_id_wire_name.rs` fails if any renamed field loses its serde rename. `SourceProof`/`BindContext` keep `session_id` (signed content). **Still to do:** the same rename in the Presence and Relay protocol copies (P2-02/P2-04). |
| P1-23 | done 2026-11-23 | `idr-source` (connect path in `runtime.rs`, session loop in `agent.rs`, `mux_session.rs`), `idr-signaling` (`discovery.rs`, `pep/client.rs`, `pep/wss.rs`) and `idr-webrtc` (`native.rs`) are fully structured: 0 unstructured calls left. Events are registered; `connection.established{transport.selected,setup_ms}`, `session.state_changed{from,to,reason}`, `stream.opened` replace the old per-step chatter; `connection.attempt.failed` is emitted once at the C ABI boundary. The four crates are under the event-registry lint. **Not done:** `persist_start` spans on the Rust side (the Dart `source.connect.attempt` has one); `idr-target` is P1-24 |
| P1-24 | done 2026-11-23 | `idr-target`: 131 tracing calls became registered events (generated names `<domain>.<slug>`, domain = directory, else `target`); field `error` became `error.message`; crate is in the event-registry lint. `idr-target` tests: only the 2 known idle-timer failures. **Not done:** hand-pick better event names, spans (WebRTC answerer, relay connector) |

| P1-25 | done 2026-11-23 (stall watchdog not added) | `idr-transfer`: all 11 log calls structured. One helper `log_outcome` turns every `Outcome` into a registered event (`transfer.completed`/`completed_with_errors`/`failed`/`cancelled`/`rejected`/`interrupted`) with `transfer_id` as a hyphenated UUID (was hex); tested. A stalled or disconnected transfer already ends as `Interrupted(Stalled\|Timeout)` (60 s `stall_timeout`), so it appears as `transfer.interrupted{error.type=stalled}`. **Not done:** an early `transfer.stalled` warning before that timeout, progress sampling events, and removing the CLI `println!` from the library (`native/control.rs`, it is user output, so it should move to the agent binaries) |
| P1-26 | skipped by decision 2026-11-23 | `idr-wasm` is left as it is (it still builds for `wasm32`) |
| P1-30 | done 2026-11-23 | `idr_client` (see P1-21): `IdrLog`, `ctx` through the FFI isolate to native, trace and `session_id` continuity proven in `telemetry_e2e_test.dart` and in the CI gate script. |
| P1-31 | not started | `idr_session`/`idr_source`: `session_id` ownership and the `source.connect` root span (the continuity test creates them by hand), HTTP `traceparent`, `http.request_id` capture. `httpFailure` (P1-11) is done. |
| P1-32 | partial 2026-11-23 | `idrLog`/`idrTimed` now emit `target.sdk.note{msg}` and `target.phase.completed{phase,duration_ms,outcome}` through idr_telemetry (stdout fallback without Telemetry); the agent process gets `IDR_LOG_DIR` and `TRACEPARENT`. **Not done:** the 38 free-text sites are not yet named events, redacted stderr tail, IPC `ctx`, `HealthMonitor` events |

| P1-33 | partial 2026-11-23 | `runCliWithTelemetry` (`idr_cli_core`) wraps both `idrs` and `idr`: files under `IDR_LOG_DIR` or the per-OS default root (`defaultLogRoot()`), `-v` adds a DEBUG+ stderr sink, `ui.command.invoked/completed{command,exit_code,duration_ms}` (first non-flag word only, never argument values), stray async errors become crash records, the run always ends with `app.stopping`, and telemetry failure never stops the CLI. 3 tests, and a real `idrs` run validates with `idr_diag` (0 problems). **Not done:** `diag report` command, removing the `[idr_` zone `print` hook (needs P1-32 first), the pre-runner `stderr.writeln` sites, `source_agent.dart` hostname |
| P1-34 | partial 2026-11-23 | `idr_target_app`: `main` initializes telemetry (`TelemetryFlutter.init`), runs under `runGuarded`, attaches the route observer; `idr_telemetry_flutter` now writes `app.stopping` when the app detaches (otherwise every normal quit would look unclean; tested). App tests pass (11). **Not done:** the "Report a problem" screen, the unclean-exit banner, and `ui.gate.shown` events (the app navigates by gate state, not named routes, so the route observer records little) |
| P1-35 | not started | Depends on P1-32 (the startup timing events it will read). |
| P1-36 | done 2026-11-23 | `presenceSourceId()`: the Source sends the enrolled device's `ski` (else the constant `dart`), never the user's email. 3 tests; `idr_source` passes all 11. **Open:** `source_agent.dart:91` still sends `Platform.localHostname` as `source_id` (hostname is a `personal`-class value, 04 §5.1); change it with P1-33. Presence also overrides `source_id` with the verified SKI, so the email mattered only before verification and for anonymous Sources. |
| Pre-existing failures (not from this work) | — | Verified on unmodified HEAD: `idr-protocol` `platform_without_turn_is_stun_only` (MissingTurn); `idr-target` `relay::idle` 2 timer tests; `idr-wasm` does not compile for the host target; `idr_session` `state_dir` tests (a `.dart-tool` dir in the temp home); workspace `cargo fmt --check` diffs in other crates; `source-agent` `daemon` e2e tests are timing-flaky (a different test fails per run, on HEAD too). |

## Phase 0: Audit, design, documentation, approval

| ID | Task | Output | Status |
|---|---|---|---|
| P0-01 | Audit all repos | [00](00-current-state-audit.md) | done |
| P0-02 | Architecture, IDs, schema, storage, privacy, migration, rules | [01](01-architecture.md)–[07](07-rules-and-enforcement.md) | done |
| P0-03 | External design review (9 findings) incorporated; V1/V2 scope and the upgrade-together policy decided | [09](09-decisions-risks-approval.md) | done (2026-11-23) |
| P0-04 | Resolve the remaining owner decisions (D1, D7, D9, D10) | [09 §1](09-decisions-risks-approval.md) | done (2026-11-23) |
| P0-05 | Per-repository owner sign-off | [Approval checklist](09-decisions-risks-approval.md#approval-checklist) | **open** |

**Exit:** the checklist is signed. Implementation then starts with Phase 1.

## Phase 1 (V1): Clients, shared libraries, engine, crypto

### 1a. Foundations

| ID | Task | Size | Acceptance |
|---|---|---|---|
| P1-00 | Move these docs to `agents_engine/agent/docs/observability`; ADR-0019; add `CLAUDE.md`/`AGENTS.md` pointers in every repo to [07](07-rules-and-enforcement.md) | S | The docs and ADR are in place; the pointers are merged |
| P1-01 | `spec/`: JSON Schema, `events.yaml` (with `persist_start`), `attributes.yaml`, vectors (IDs, `ctx_json`, redaction, records) | M | The schema validates the golden records |
| P1-02 | `idr-telemetry` crate, `types` feature: field constants, `Secret<T>` (serde-transparent, redacting, not a field, `expose()`), `TraceContext`, `new_id` | M | Vectors pass; `Secret` round-trip + Debug tests |
| P1-03 | `idr-telemetry` `subscriber` feature: span-ID layer, filter split (global DEBUG while the recorder is on, sinks at their own level), **redaction of all strings before any sink**, JSON formatter with per-producer `seq`, byte-capped queue (drop incoming) and ring (evict oldest), **writer-controlled recorder drain (persisted flag + watermark split, active/pending follow-up drains, bundle completion)**, 8 KiB record cap, rotating writer **with a per-run lifetime lock, provably-closed-only retention, per-run exit recovery with the `.ended` claim**, disk guard, panic hook, `ffi_guard`, `init_from_env` | L | Conformance, context, storage-ownership, exit-recovery, recorder-drain, redaction-coverage, memory-cap, crash and performance tests ([07 §2](07-rules-and-enforcement.md)) |
| P1-04 | `idr_telemetry` Dart: the same feature set + Zone spans/IDs, `currentContextJson`, `runGuarded`, redactor (moved from `idr_cli_core`), `DiagnosticBundle` (local export) | L | The same tests; 100-way concurrency test |
| P1-05 | `idr_telemetry_flutter`: hooks, lifecycle, log dir | S | Widget test: `FlutterError` → crash record |
| P1-06 | `idr_diag` CLI: `validate`, `lint-events`, `merge` (orders by `ts`/producer/`seq`), `tree --trace`, `open <bundle>` (lists runs, sessions, connections, transfers, open operations) | M | Used in CI from P1-07 on |
| P1-07 | CI gates from [07 §3](07-rules-and-enforcement.md), enabled per package as each one migrates | M | A gate fails on a seeded violation |

### 1b. Security fixes (independent; can start first)

| ID | Task | Size | Acceptance |
|---|---|---|---|
| P1-10 | Redacting `Debug` on dp-sdk and agent key holders (C2); `Secret<String>` on protocol tokens (C3) | S | The Debug-on-secrets lint is clean; **wire bytes and signatures unchanged** (golden) |
| P1-11 | `dp-rust-sdk::Error::Http` `Display` without the body (C4); Dart HTTP clients stop embedding bodies (D7) | S | Tests assert there is no body in messages |
| P1-12 | `ffi_guard` on every `idr-c-api` / `idr-dp-ffi` export; `IDR_ERR_PANIC`; poisoned engine (R5) | M | Injected panic: the Dart host survives |

### 1c. Rust engine migration

| ID | Task | Size | Acceptance |
|---|---|---|---|
| P1-20 | Binaries `target-agent`, `source-agent`, `mock-presence` → `init_from_env`; remove `init_tracing` and `idr-target`'s `tracing-subscriber` dependency; unified env vars (R1–R3, R19, R20) | M | One subscriber implementation in the tree |
| P1-21 | `idr-c-api` ABI: `idr_telemetry_init`, `idr_telemetry_flush`, trailing `ctx_json` on `idr_connect`, `idr_open_stream`, `idr_transfer_send`, `idr_transfer_send_selection`, `idr_transfer_resume`; `ffi.handle.bound`; error event fields (R4, R6); `idr.h` updated, **`ABI_VERSION` bumped** (exact match kept) | M | The Dart FFI test sees Rust records in `*.rust.jsonl` with the same `app_session_id`, the parent span **and** `session_id`; a mismatched pair fails fast |
| P1-22 | Protocol: serde rename of the wire `session_id` → Rust field `connection_id` in the agent copy (R7). **No `telemetry` field in V1.** | S | Byte-identity and signature tests |
| P1-23 | Spans and events in `idr-source`, `idr-signaling`, `idr-webrtc` (R9–R14, R17), with `persist_start` on long-lived spans | L | Connect scenario: required events from [03 §4.4](03-log-schema-and-events.md) present; 25 INFO records or fewer |
| P1-24 | Spans and events in `idr-target` (Presence client, WebRTC answerer, relay connector, gateway) | L | Same; also the Relay wake path |
| P1-25 | `idr-transfer`: `transfer_id` as UUID, stall watchdog, progress sampling (per-chunk detail = TRACE), remove the library `println!` (R15, R18) | M | Stall test → `transfer.stalled` with the required attributes |
| P1-26 | `idr-wasm` init (ring + console) | S | |

### 1d. Dart SDKs and apps migration

| ID | Task | Size | Acceptance |
|---|---|---|---|
| P1-30 | `idr_client` (agent repo): `IdrLog`, `ctx` to the FFI isolate → `ctx_json`, call `idr_telemetry_init` (D19) | M | Trace **and `session_id`** continuity Dart → Rust in a test |
| P1-31 | `idr_session`, `idr_source`: sessions (`session_id` ownership), connect spans, HTTP `traceparent`, `http.request_id` capture | M | Source scenario events emitted |
| P1-32 | `idr_target`: replace `idrLog`/`idrTimed` (D1–D9); process env, redacted stderr tail, no stdout parsing (D10–D12); IPC `ctx` (D24); `HealthMonitor` events (D22) | L | 0 `idrLog`; the agent start trace spans Dart → agent |
| P1-33 | `idr_cli_core`, `idrs`, `idr`: init, `runGuarded`, `-v` sink, remove the zone hook, `diag report` (D13–D17) | M | `idrs -v` shows the same records as the file; two concurrent `idrs` runs keep both files |
| P1-34 | `idr_target_app`: init, Flutter hooks, "Report a problem" (local export + show in folder), unclean-exit banner (D21, D23) | M | Widget test; bundle builds and opens in `idr_diag` |
| P1-35 | `benchmark-startup.mjs` reads JSONL ([06 §1](06-migration.md)) | S | The benchmark runs green |
| P1-36 | D9: replace `sourceId=email` (D20), coordinated with Presence (P2-02) | S–M | No email in Presence, TURN or client logs (scanner) |

**Phase 1 exit:**
- All client components meet the [06 §6](06-migration.md) done criteria.
- A local e2e run (CLI Source ↔ Target agent ↔ local Presence) produces schema-valid files, correlated in-machine by trace and across machines by `connection_id`.
- A bundle can be exported and opened with `idr_diag`.

## Phase 2 (V1): Backend services logging

| ID | Task | Size | Acceptance |
|---|---|---|---|
| P2-01 | Presence: `init_from_env`, JSON default, remove `RUST_LOG` from the unit (P1) | S | |
| P2-02 | Presence: events and levels (P2–P9), truncated IPs, error responses with `error.type` + `trace_id`, serde rename (P8); Billing headers (P10) | L | Presence volume ≤ 5 INFO records per session |
| P2-04 | Relay: `init_from_env`, the `relay.edge.connection` span replacing `request_id` (L1–L7), serde rename (L6) | L | |
| P2-05 | Relay: the 502 body with the ref, Billing headers (L5, L8) | S | |
| P2-06 | usage-reporter JSON `log()` (U1); DNS updater formatter (N1) | S | Schema validation passes |
| P2-09 | Every server: `app.started` / `app.stopping`, panic hook | S | |

**Phase 2 exit (V1 done):**
- Every server emits schema-valid JSON.
- A developer can follow the failed-connect, stalled-transfer, Relay, auth and crash scenarios in [05](05-investigation-scenarios.md) from a local bundle plus the server logs, using the V1 paths.

## Phase 3 (V2): Distributed tracing, central diagnostics, validation

| ID | Task | Size | Acceptance |
|---|---|---|---|
| P3-01 | Wire `telemetry` object (R8, P11, L9) in **all three protocol copies**: `WebRtcSessionRequest`, `WebRtcSessionOffer` (Presence copies it from the request and signs without it), `TargetRegistration`, `EnsureRelayConnectionCommand`. Every signer and verifier clears it before canonicalization. | L | Golden vectors for 4 messages with and without the field; old-verifier × new-signer tests in both directions; offer-copy test |
| P3-02 | Deploy every verifier (Presence, Relay, Target agents) before any signer sends it; then turn on `IDR_WIRE_TELEMETRY=1` (internal → beta → all) | S | Cross-machine trace trees in `idr_diag tree` |
| P3-03 | Deploy Alloy + Loki + Grafana (D5); labels and metadata per [04 §7](04-storage-crash-diagnostics-privacy.md); keep `flushed=true` DEBUG records; retention | M | Server records queryable by every ID |
| P3-04 | `diag-ingest` (D4): authenticated upload, object storage, manifest index, display code from random bits with a collision check; client upload and consent UX | M | Upload from the GUI and CLI; lookup by display code |
| P3-05 | Grafana: "Investigate report", "Trace timeline", "Target health"; metrics → logs links | M | |
| P3-06 | Alerts ([04 §7.5](04-storage-crash-diagnostics-privacy.md)) | S | |
| P3-07 | Optional: Billing `traceparent` in pino; API `x-request-id` (B1–B2) | S | |
| P3-08 | coturn: Alloy parsing rules (T1) | S | coturn lines carry `service=turn` + `connection_id` |
| P3-09 | Scenario replay suite with fault injection against staging, nightly | L | Each scenario diagnosed from the logs alone |
| P3-10 | Performance validation at 1 Gbps transfer, 100 concurrent sessions on Presence | M | Budgets met |
| P3-11 | Remove the deprecated compatibility (`RUST_LOG`, the `redact` re-export); update [00](00-current-state-audit.md) to "as built"; record deviations as ADRs | S | |

## Sequencing

```text
P0 sign-off ─► P1-00..07 ─┬─► P1-1x security fixes (parallel, first)
                          ├─► P1-2x Rust ─► P1-30 idr_client ─► P1-31..36 Dart ─┐
                          └─► P2-0x servers (after P1-03; P1-36 ↔ P2-02 together) ─┴─► V1 release
V1 ─► P3-01 wire field ─► P3-02 (all verifiers deployed, then flag on) ─► P3-03..11 ─► V2 release
```
