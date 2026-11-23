# 00: Current-State Audit (November 2026)

This audit was read-only and covered every repository in scope. Paths are relative to each repository. Nothing in this document is assumed to be correct or standard. It exists to show what must be **replaced, improved, or removed**. The per-item decisions are in [06-migration.md](06-migration.md).

## Summary

| Area | Logging mechanism | Correlation IDs | Crash handling | Persistent log | Format |
|---|---|---|---|---|---|
| Flutter Target app (`apps/idr_target_app`) | none (0 calls) | none | none | **none** (release Windows has no console) | n/a |
| Target SDK (`apps/sdks/idr_target`) | `idrLog` → `print('[idr_target] …')`, `idrTimed` | none | none | none | free text, loose `k=v` |
| Source SDK (`apps/sdks/idr_source`) + `idr_client` | `developer.log(name:'idr_client')` (~6 sites) | none | none | none | free text |
| CLIs `idrs` / `idr` (`idr_cli_core`) | `Ui` class (user-facing output) plus a zone `print` hook that reroutes `[idr_` lines into `-v` debug | none | per-command catch, exit codes | none | text, or `--json` result envelopes |
| Rust `target-agent` | `tracing` + `init_tracing` (`idr-target/src/telemetry/tracing.rs:4-22`) | none (wire UUIDs only) | none | none (stdout piped into Dart) | text or JSON (`IDR_LOG_JSON`) |
| Rust `source-agent` | its own subscriber (`services/source-agent/src/main.rs:267-275`) | none | none | `IDR_LOG_FILE`, truncated on each start, no rotation | text |
| Rust in-process (`idr-c-api`, `idr-dp-ffi`, `idr-wasm`) | **no subscriber, so events are dropped** | none | **none: a panic across `extern "C"` aborts the Flutter host** | none | n/a |
| dp-sdk | none (0 calls); CLIs `println!` | none | none | none | n/a |
| Presence | `tracing`, JSON capable but `log_json=false` in every config | client-sent `session_id`, `message_id` | none | stdout | text |
| Relay | `tracing`, JSON capable, no env switch | `request_id` (UUID v4 per TCP accept, passed as a parameter) | none | stdout | text |
| TURN (coturn) | `verbose`, `simple-log`, stdout | coturn username embeds `session_id:source_id` | n/a | stdout | coturn text |
| usage-reporter (Node) | `console.*`, partly JSON | `idempotency_key` | n/a | stdout | mixed |
| DNS server | Python `logging` text; PowerDNS query logs off | none | n/a | journald | text |
| Billing (`Auth_repo/billing`) | pino + pino-http | **echoes `x-request-id`** | n/a | stdout + `logs/*.log` (no rotation) | JSON |

Nothing anywhere creates or propagates a trace ID or correlation ID. Nothing uses OpenTelemetry. There are no tracing spans in any Rust crate: 0 `#[instrument]` and 0 `*_span!`.

## 1. Dart / Flutter (`applications/apps`, plus Dart packages in `agents_engine/agent/packages`)

### Inventory

- **Packages and apps:**
  - `idr_cli_core`
  - `idr_sources_cli` (`idrs`)
  - `idr_target_cli` (`idr`)
  - `idr_target_app` (Flutter)
  - `sdks/idr_session`
  - `sdks/idr_source`, with sub-packages `idr_service_http`, `idr_ollama`, `idr_huggingface`
  - `sdks/idr_target`
  - `idr_dart_sdk` (unused by apps)
  - `idr_ui_views` (unused)
- **Workspace and repo layout:** there is no melos and no pub workspace; packages use `path:` dependencies. External packages come from the agent repo: `idr_client`, `idr_core_ffi`, `idr_dp_ffi`, `idr_secure_storage`.
- **Separate git repos:**
  - `applications/apps`
  - `agents_engine/agent`
  - `agents_engine/dp-sdk`
  - one per server
  - The workspace root `C:\dev\idrto` is **not** a repo.

### Mechanisms and counts

- **Target SDK `idrLog` / `idrTimed`** (`sdks/idr_target/lib/src/internal/logging.dart:2-19`):
  - 38 + 7 call sites.
  - No level, no timestamp, no redaction, no stack traces.
  - `idr_target.dart:645` duplicates the `idrTimed` startup line by hand.
  - About ten free-form `start: stop — …` / `continue: stop — …` variants (`idr_target.dart:597,609,1194,1207,1231,1339-1347`).
- **`Ui` in `idr_cli_core`** (`idr_cli_core.dart:111-331`):
  - 205 call sites across both CLIs.
  - This is **user-facing terminal output**, not logging, and must stay separate.
  - It has a good `redact()` at `:67-106`.
- **Zone `print` hook** (`idr_cli_core.dart:621-625`): string-prefix routing of `[idr_` lines.
- **Raw output:** about 14 raw `stderr.writeln` and 16 `stdout.write` calls outside `Ui`. Pre-runner errors in `bin/idrs.dart:14` and `bin/idr.dart:14` bypass JSON mode and redaction.
- **`idr_client`** (`agents_engine/agent/packages/idr_client/lib/src/runtime.dart:13`) uses `developer.log`, which the CLI hook cannot see. **Its logs are lost.**

### Rust ↔ Dart

- **Target:** `ProcessManager.start` merges the agent's stdout and stderr without line splitting and without a stream tag (`process_manager.dart:63-64`). `AgentRuntime` re-prints each chunk as `[idr_target] agent: <rust line>` (`agent_runtime.dart:158-162`). The Rust level is lost, lines can split, and the GUI drops everything. `RUST_LOG=info` is hard-coded (`process_manager.dart:42-44`).
- **Source:** the agent is spawned detached with `IDR_LOG_FILE` (`source_agent.dart:30,154-156`). Dart reads the last 6 lines to build error hints.
- **FFI** (`idr_core_ffi`, `idr_client`, `idr_dp_ffi`) uses `lookupFunction` on a background isolate.
  - There are no callbacks; events are polled every 200 ms (`ffi_isolate.dart:310`).
  - There is no log forwarding.
  - `IDR_EVENT_ERROR` carries no message and has `session_id = 0` (`idr-c-api/src/ffi.rs:367-373`).
- **IPC:** newline-delimited JSON over a Unix socket or named pipe, with **no request ID** (`sdks/idr_target/lib/src/transfer/agent_ipc.dart`).
- **De facto contract:** `apps/tools/benchmark-startup.mjs:36-41` regex-parses `timing phase=`, `start failed:`, `"agentRunning"` and `"controlPlane"` from stdout. This must be migrated, not broken.

### Identifiers

- No UUID package, no request or trace IDs, no app-instance ID.
- `idr_source.dart:283` sends the **user's email** as the Presence `sourceId`. `source_agent.dart:91` uses the hostname.
- The FFI `session_id` and `stream_id` are `u64` counters that are never mapped to the wire UUIDs.

### Crash handling

- None: 0 `FlutterError.onError`, `PlatformDispatcher.onError`, `runZonedGuarded`, `Isolate.addErrorListener`, Sentry or Crashlytics.
- No "send logs" feature exists. The GUI `DiagnosticsSection` (`home_screen.dart:566-660`) only runs reachability checks.

### Sensitive data

- **Email logged:** `idr_target.dart:618-621`.
- **Raw HTTP response bodies inside exceptions**, then logged: about 10 sites, e.g. `agent_token_client.dart:92` and `enroll_client.dart:53,83,184,401`.
- **Config paths, SKIs and entity IDs:** `enrollment_manager.dart:124,469`.
- **Agent stdout is forwarded unredacted** in the GUI path.

## 2. Rust agent engine (`agents_engine/agent`)

### Crates

- **Libraries:**
  - `idr-protocol`
  - `idr-core`
  - `idr-webrtc`
  - `idr-signaling`
  - `idr-dp`
  - `idr-dp-ffi` (cdylib `idr_dp`)
  - `idr-transfer`
  - `idr-source`
  - `idr-target`
  - `idr-c-api` (cdylib, `include/idr.h`)
  - `idr-wasm`
- **Binaries:** `target-agent`, `source-agent`, `mock-presence`.

### Logging stack

- `tracing` 0.1 only.
- **Three subscriber setups that disagree:**

| Binary | Filter env | Format | Output |
|---|---|---|---|
| `target-agent` | `RUST_LOG` > `IDR_LOG_LEVEL` | text or JSON (`IDR_LOG_JSON`) | stdout |
| `source-agent` | `IDR_LOG` / `--log-level` (`RUST_LOG` ignored) | text only | stdout, or `IDR_LOG_FILE` (truncated, no rotation) |
| `mock-presence` | `RUST_LOG` | text | stdout |
| `idr-c-api` / `idr-wasm` | — | — | **dropped** |

- **libdatachannel logging is never enabled.** `datachannel::configure_logging` is never called.

### Call sites

- About 205 tracing macros and 32 `println!`/`eprintln!` in `src/`.

| Crate | info | warn | error | debug |
|---|---|---|---|---|
| idr-target | 40 | 56 | 8 | 30 |
| idr-source | 12 | 11 | 0 | 0 |
| idr-transfer | 4 | 7 | 0 | 0 |

- 0 `trace!`.
- `idr-transfer/src/native/control.rs:167-213` mixes CLI `println!` into library code.

### Wire identifiers (from `idr-protocol`)

- **Signaling `session_id: Uuid`** (v4). It is minted **per WebRTC negotiation** at `idr-source/src/runtime.rs:274` and is **bound into `SourceProof`** (`webrtc_signaling.rs:147`, `peer_bind.rs:57`). A reconnect creates a new one, so its semantics are *connection attempt*, not *logical session*.
- **`message_id: Uuid`:** per message.
- **`command_id: Uuid`:** relay ensure.
- **`ClientHello`:** carries `session_id`, `connection_epoch` and `relay_id` (postcard, `quic_control.rs:20-40`).
- **`StreamFrame` `stream_id: u32`.**
- **`TransferId = [u8;16]`** (UUID v4 bytes). It is **reused by `resume(id)`** (`idr-transfer/src/native/manager.rs:378`), so its semantics already match a logical transfer.

### FFI

- No callbacks; events are polled.
- There is a thread-local last error, which is fragile if the calling isolate migrates threads.
- **0 `catch_unwind`.** A panic in any `extern "C"` export aborts the host app.
- 0 panic hooks, except `console_error_panic_hook` in wasm.

### Field drift

- `fqhn` vs `target_fqhn`
- `transfer` vs `id` for the transfer ID
- `presence_id` vs `presence`
- errors logged four different ways: `error = %e`, `error = %err`, `?e`, bare `%err`
- **Env vars:** `RUST_LOG`, `IDR_LOG`, `IDR_LOG_LEVEL`, `IDR_LOG_JSON`, `IDR_LOG_FILE`

### Noise at INFO

- every Presence push (`presence/websocket.rs:506`)
- dedup paths (`:555,560`)
- about 6 lines per WebRTC handshake
- one line per opened stream (`idr-source/src/runtime.rs:827`)

### Exposure

- `debug!(%url)` with the query string (`idr-target/src/adapters/gateway.rs:246`)
- the Relay IP at info (`presence/websocket.rs:523-530`)
- file paths

### Docs

- No logging ADR.
- `docs/security-model.md:74-82` and `docs/threat-model.md:39` list what must never be logged. These rules are kept and enforced by the new design.

## 3. Crypto library (`agents_engine/dp-sdk`)

- No logging in `dp-rust`, `dp-rust-mtls`, `dp-rust-sdk` or `2key_core`. **That is correct and must stay so.**
- **Risk: `#[derive(Debug)]` on private-key holders.** One `{:?}` anywhere would leak them:
  - `DeviceIdentity.private_jwk` (`dp-rust-mtls/src/lib.rs:35-45`)
  - `MtlsClientMaterial.key_pem` (`:48`)
  - `LoadedClientAuth.key` (`:60`)
  - `GeneratedKeyAndCsr` (`:210`)
  - `SelfSignedCa` (`:219`)
  - `GeneratedEd25519` (`:364`)
  - in the agent, `idr-dp/src/identity.rs:17-21`
- **Risk:** `dp-rust-sdk::Error::Http{status, body}` puts the whole HTTP body into `Display` (`error.rs:7`).
- **Risk:** private PEM/JWK cross the FFI as C strings that are not zeroized on free (`idr-dp-ffi/src/lib.rs:70-85`).

## 4. Servers

### Presence (Rust, quinn + tokio-tungstenite)

- `tracing` with JSON support, but **`log_json = false` in every config**.
- `deploy/idr-presence.service` sets `RUST_LOG=info`, which overrides the config level.
- **Volume and noise:**
  - About 79 sites: 34 info, 35 warn, 10 debug, **0 error**.
  - Info is logged per frame, including every ICE candidate (`wss/mod.rs:262,476`, `quic/mod.rs:380`).
  - The WSS and QUIC paths are near-duplicates.
- **Field names drift:** the address is `peer` vs `remote`.
- **Exposure:**
  - A 120-character JSON `preview` at info (`quic/mod.rs:347`).
  - Client IPs at info.
  - `e.to_string()` returned to clients in `presence_error`.
- **Wire constraint:** signed messages are verified by re-serializing the *typed* struct (`signaling.rs:157-171`). An unknown field added by a signer **breaks verification** on an old verifier.
- **Metrics:** Prometheus on `127.0.0.1:9092`.

### Relay (Rust, quinn, rustls, rusqlite)

- `tracing` as in Presence; `IDR_LOG_LEVEL` exists but there is no JSON env switch.
- **`request_id` (UUID v4 per edge TCP accept):**
  - It is threaded through as a function argument with a `stage=` field.
  - It is not echoed to the client and not sent to Presence or the Target.
- **Wire correlation:**
  - `session_id` and `command_id` are minted in `dispatch_and_wait` (`registry/mod.rs:222-223`).
  - They travel to Presence and the Target and come back in `ClientHello.session_id`.
  - This is the only cross-service join today.
- **Postcard frames to the Target** need a `protocol_version` bump to add fields.
- **Protocol copies:** `src/protocol/*` is a **diverged copy** (10 files differ from Presence and agent).
- **Logging gaps:**
  - The raw error goes into the 502 body (`edge/passthrough.rs:160`).
  - QUIC handshake failures are debug-only.
- **Metrics:** Prometheus on `127.0.0.1:9090`.

### TURN (coturn 4.6.2)

- Plain text with `verbose`.
- The username is `"{expiry}:{session_id}:{source_id}"` (`presence/src/turn/credentials.rs:30`). Because `source_id` is the user's **email** (see §1), coturn logs email addresses.
- The `TURN_METRICS_PORT` env var is never applied.
- **usage-reporter** (Node):
  - 12 `console.*` calls, mixed JSON and plain strings.
  - It logs full billing error bodies.

### DNS server (PowerDNS, dnsdist, Python updater)

- Python text logs in the updater.
- Query logging is off, which is correct.
- Textfile metrics.

### Billing (`Auth_repo/billing`)

- pino with redact paths.
- `x-request-id` is accepted, minted with `randomUUID` if absent, and **echoed**.
- No `traceparent`.
- `Auth_repo/api` (Fastify) uses sequential `req-N` IDs.

### Deployment

- No log driver config in any compose file.
- No Loki, Promtail, Vector, ELK, Grafana or OTel collector anywhere.
- **Stray but gitignored files:**
  - `presence-debug.out` / `.err`
  - `relay.db*`
  - `config/presence.prod.toml`, which holds a plaintext `session_policy_token`

## 5. Assets worth reusing (only where semantics match)

| Asset | Reuse as |
|---|---|
| Wire signaling `session_id` (UUID, signed, end-to-end, also in the TURN username) | **`connection_id`** for WebRTC sessions (renamed in Rust code via `#[serde(rename)]`; the wire name is unchanged) |
| Relay-minted `session_id` in `EnsureRelayConnectionCommand` / `ClientHello` | **`connection_id`** for Relay tunnels |
| `TransferId` (16 bytes, kept across resume) | **`transfer_id`**, logged as a hyphenated UUID instead of hex |
| `redact()` in `idr_cli_core` | Moves into `idr_telemetry` as the base redactor |
| Billing `x-request-id` echo | Kept; clients log the returned value as `http.request_id` |
| Prometheus endpoints on all servers | Kept unchanged; metrics are out of scope except for links from logs |
| `tracing` crate everywhere in Rust | Kept as the instrumentation API |
| `HealthMonitor` agent-restart budget | Emits `agent.process.restarted` / `agent.process.crash_budget_exceeded` |

## 6. Not reused (semantics don't match)

- **Relay `request_id`** is replaced by `connection_id` plus a span; `stage=` fields become span events.
- **`message_id`** stays a protocol field, logged at DEBUG only. It is not a correlation key.
- **FFI `u64` handles** are not IDs. They are logged once, at creation, mapped to `connection_id`.
- **`[idr_target]` prefixes and the `[idr_` zone routing** are deleted.
- **Every subscriber setup** is replaced by `idr_telemetry::init`.
