# 06: Migration of Existing Logging

**Actions used in the tables:**
- **REPLACE:** move to the new API, with a registered event.
- **IMPROVE:** keep the call site, but fix its level, fields or redaction.
- **REMOVE:** delete.
- **KEEP:** not logging; leave as is.

A rule that applies everywhere: nothing is preserved just because it exists.

## 1. Strategy

1. **Libraries first, then call sites.**
   - First, land `idr-telemetry` and `idr_telemetry` with the spec and conformance tests (P1-01…P1-04).
   - Then migrate component by component.
2. **Migrate per component, completely, in one PR.**
   - For each component: init, every call site, the tests, and a CI gate switched on for that package.
   - **Half-migrated packages are not allowed**, because two styles would coexist.
3. **Use `events.yaml` as the checklist.**
   - Every new event that a component emits is registered in that PR.
   - Every old call site either maps to a registered event or is deleted.
4. **Bridge period.**
   - While the Target SDK is migrated but the GUI still reads agent stdout, the agent keeps its stdout text output (`IDR_LOG_FORMAT=pretty`). The Dart side stops *parsing* that output as logs in the same PR that adds `IDR_LOG_DIR`.
   - There is no dual-write into files.
5. **De facto contracts are migrated, not broken.** `apps/tools/benchmark-startup.mjs` switches from regexes on stdout to reading `app.startup.completed` / `agent.process.started` from the JSONL file, in the same PR that removes `timing phase=`.
6. **Wire telemetry is V2.**
   - V1 makes **no signaling wire change** except the Rust-only serde rename (R7), which leaves the bytes identical.
   - V2 adds the `telemetry` object. Verifiers learn to clear it first, then signers send it ([09 R2](09-decisions-risks-approval.md)).
   - V1 code must not pre-build the field "for later".

## 2. Dart / Flutter

| # | Existing | Location | Action | Becomes |
|---|---|---|---|---|
| D1 | `idrLog` / `idrTimed` helpers | `sdks/idr_target/lib/src/internal/logging.dart:2-19` | REMOVE file | `IdrLog` + `span()` from `idr_telemetry` |
| D2 | 38 `idrLog` call sites | `idr_target.dart` (24), `agent_runtime` (5), `enrollment_manager` (5), `registration_manager` (2), `process_manager`, `certificate_manager` | REPLACE | Registered events. Each site maps to one of: an INFO lifecycle event, a span, or deletion (if it only narrates a step that the span already records). |
| D3 | `idrTimed` (7 sites) | `agent_runtime.dart:120,149,165`; `idr_target.dart:595,605,607,630` | REPLACE | Spans `target.agent.start`, `target.agent.config_write`, …; `app.startup.completed` with `phase.*_ms` |
| D4 | Manual duplicate `timing phase=startup` | `idr_target.dart:645` | REMOVE | (covered by D3) |
| D5 | ~10 variants of `start: stop — …` / `continue: stop — …` | `idr_target.dart:597,609,1194,1207,1231,1339-1347` | REPLACE | One event `target.agent.start_skipped{reason}`, with `reason` an enum (`not_signed_in`, `no_registration`, `no_entitlement`, `already_running`, …) |
| D6 | `start: fqhn=… email=…` | `idr_target.dart:618-621` | REPLACE + privacy | `target.agent.start_requested{target.fqhn}`; email removed |
| D7 | `idrLog('… failed: $e')` with raw HTTP bodies | `idr_target.dart:770,844,1248`; `enrollment_manager.dart:136,720` | REPLACE | `*.failed` ERROR/WARN with `error.type`, `http.response.status_code`, `http.request_id`. HTTP clients stop putting bodies into exception messages (`agent_token_client.dart:92`, `enroll_client.dart:53,83,184,401`, `registration_client.dart:78,117,211`). |
| D8 | Log + `_setAttention` duplicate | `idr_target.dart:636-643` | IMPROVE | Log once at the boundary, with the stack; the attention state is UI state, not a log |
| D9 | Paths, SKI and entity logs | `idr_target.dart:584-588`; `agent_runtime.dart:84,151-154`; `enrollment_manager.dart:124,469` | IMPROVE | Paths → `~`-relative, at DEBUG only; SKI → `device.ski` (pseudonymous); entity → `entity.id` |
| D10 | Forwarding agent stdout into `idrLog('agent: …')` | `agent_runtime.dart:158-162`; `process_manager.dart:63-64` | REMOVE | The agent writes its own file. `ProcessManager` keeps a **line-split ring of the last 20 stderr lines** only, for `agent.process.exited.stderr_tail`, which is redacted like every other string. |
| D11 | Hard-coded `RUST_LOG=info` | `process_manager.dart:42-44` | REPLACE | Pass `IDR_LOG`, `IDR_LOG_DIR`, `IDR_PARENT_APP_SESSION_ID`, `TRACEPARENT`, and `IDR_LOG_FORMAT=off` |
| D12 | Source agent `IDR_LOG_FILE` + reading 6 tail lines | `source_agent.dart:30,154-169`; `transfer.dart:75` | REPLACE | `IDR_LOG_DIR`. The error hint shows the last `ERROR` record from the agent's file (parsed JSON) and the bundle command. |
| D13 | Zone `print` hook routing `[idr_` | `idr_cli_core.dart:621-625` (applied at 524, 586) | REMOVE (after D1–D2) | The CLI `-v` maps to the `idr_telemetry` stderr sink at DEBUG |
| D14 | `Ui.debug` | `idr_cli_core.dart:149-151` | IMPROVE | It writes a DEBUG record **and**, when `-v` is set, prints to stderr. `Ui.info`/`success`/`warn`/`_error` stay as user output (KEEP), but `_error` also logs `ui.command.completed{exit_code, error.type}`. |
| D15 | `redact()` | `idr_cli_core.dart:67-106` | MOVE | To `idr_telemetry` (extended with emails, IPs, paths, ICE). `idr_cli_core` re-exports it for one release. |
| D16 | Pre-runner `stderr.writeln('error: $e')` | `bin/idrs.dart:14`; `bin/idr.dart:14` | IMPROVE | Wrap `main` in `runGuarded`. Errors go through `Ui` (JSON mode plus redaction) and a FATAL record. |
| D17 | `chat_repl.dart` `stderr.writeln(redact(…))` | `idr_sources_cli/.../chat_repl.dart:43,57,64,102` | REPLACE | `ui.warn`, plus a `stream.*` event |
| D18 | `stdout.write` for streamed chat | `idr_sources_cli` (13) | KEEP | This is product output, not logging |
| D19 | `idr_client` `developer.log` | `agents_engine/agent/packages/idr_client/lib/src/runtime.dart:13` (~6 sites) | REPLACE | `IdrLog('idr_client')`. Stop logging `sourceId` and the discovery URL (`:42,77`). The FFI isolate receives `ctx` and passes `ctx_json` to the operation calls. |
| D20 | `sourceId = email` | `idr_source.dart:283` | **Product change, flagged** | `device.ski`, or an opaque ID ([09 D9](09-decisions-risks-approval.md)). This also removes the email from TURN usernames and coturn logs. |
| D21 | No crash hooks; `idr_target_app/main.dart:12-15` | — | ADD | `Telemetry.init` + `TelemetryFlutter.install` + `runGuarded` |
| D22 | `HealthMonitor` restart and budget | `health_monitor.dart:30` | IMPROVE | Emit `agent.process.restarted` / `crash_budget_exceeded` |
| D23 | GUI `DiagnosticsSection` | `home_screen.dart:566-660` | IMPROVE | Add a "Report an issue" entry; reachability results go into `checks/doctor.json` |
| D24 | Agent IPC without request IDs | `agent_ipc.dart:40-50` | IMPROVE | Add the `ctx` field (full local context); span `agent.ipc.request` |
| D25 | Demo and example prints | `idr_target/example/main.dart`; `idr_dart_sdk/example` (in-memory list) | KEEP (examples) but remove `auth: ${s.data}` (`example/main.dart:137,271`) | — |
| D26 | `idr_dart_sdk`, `idr_ui_views` | — | none | No logging today. They are unused by the apps; migrate only if they come back into use. |

## 3. Rust agent engine

| # | Existing | Location | Action | Becomes |
|---|---|---|---|---|
| R1 | `init_tracing` (target-agent) | `idr-target/src/telemetry/tracing.rs:4-22`; call at `services/target-agent/src/main.rs:246` | REMOVE + REPLACE | `idr_telemetry::init_from_env("target-agent", …)` in `main.rs`. **Library crates must not own subscriber code**, so `idr-target` drops its `tracing-subscriber` dependency. |
| R2 | source-agent subscriber + `IDR_LOG_FILE` truncation | `services/source-agent/src/main.rs:267-275` | REPLACE | `init_from_env` |
| R3 | mock-presence subscriber | `services/mock-presence/src/main.rs:28-30` | REPLACE | `init_from_env` |
| R4 | No subscriber in `idr-c-api` / `idr-wasm` | — | ADD | New ABI `idr_telemetry_init(const char* json)` and `idr_telemetry_flush()`; a trailing nullable `const char* ctx_json` on `idr_connect`, `idr_open_stream`, `idr_transfer_send`, `idr_transfer_send_selection` and `idr_transfer_resume` ([01 §4.2](01-architecture.md)); wasm feature init. **Bump `ABI_VERSION`.** The exact-match check (`engine.rs:48`, `bindings.dart:210`) stays: the app and its native library ship together ([09 D14](09-decisions-risks-approval.md)). |
| R5 | No `catch_unwind` in exports | all `extern "C"` in `idr-c-api`, `idr-dp-ffi` | ADD | `ffi_guard` wrapper on every export, plus the `IDR_ERR_PANIC` code and the poisoned-engine state |
| R6 | `IDR_EVENT_ERROR` without message or session | `idr-c-api/src/ffi.rs:367-373` | IMPROVE | Populate the FFI `session_id`; the error text is retrievable through `idr_last_error_message`; the Rust side logs the full error with IDs |
| R7 | Wire `session_id` struct fields | `idr-protocol/src/webrtc_signaling.rs:204-360`, `quic_control.rs:20-40`, `signaling.rs:62-90` | IMPROVE | Rename the Rust field to `connection_id` with `#[serde(rename = "session_id")]`, so the wire bytes and signatures are unchanged. A test proves the bytes and signatures are identical. |
| R8 | **V2:** add `telemetry: Option<TelemetryContext>` | `WebRtcSessionRequest`, **`WebRtcSessionOffer`** (Presence-built and Presence-signed), `TargetRegistration`, `EnsureRelayConnectionCommand` | ADD in V2 | Excluded from canonical signing by every signer and verifier; Presence copies it from the request into the offer. Not sent until `IDR_WIRE_TELEMETRY=1`. |
| R9 | ~205 tracing macros (no spans) | all crates | REPLACE | Spans around operations (`source.connect.attempt`, `signaling.session_request`, `webrtc.ice`, `transfer.send`, `presence.register`, …), with events from the registry. Interpolated messages (`"WebRTC connected via {via}"`, `session.rs:208`) become `connection.established{transport.selected}`. |
| R10 | Field drift: `fqhn`/`target_fqhn`, `transfer`/`id`, `presence_id`/`presence`, the four error styles | see audit | REPLACE | `fields::*` constants; errors always `error.type` + `error.message` through one helper `record_error(&e)` |
| R11 | Noisy INFO: every Presence push, dedup paths, ~6 lines per handshake, per-stream open | `presence/websocket.rs:506,555,560`; `signaling_handler.rs`; `session.rs`; `idr-source/src/runtime.rs:827` | IMPROVE | DEBUG (flight recorder). The handshake collapses into one span plus `connection.established`. |
| R12 | Duplicate "presence connected" block (QUIC vs WSS); duplicate queue-overflow warns | `websocket.rs:239,328`; `idr-webrtc/src/native.rs:594`; `idr-target/src/webrtc/peer.rs:383` | REPLACE | One event `signaling.transport.connected{network.transport}`; one `webrtc.callback_queue.overflow` |
| R13 | `debug!(%url)` with the query string | `idr-target/src/adapters/gateway.rs:246` | IMPROVE | `url.path` only |
| R14 | Relay IP at info, Presence URL, ICE server URLs | `presence/websocket.rs:523-530`; `pep/wss.rs:48`; `peer.rs:286` | IMPROVE | `server.address` (hostname) at INFO; the IP at DEBUG; ICE URLs as host only |
| R15 | `println!` in a library (`idr-transfer/src/native/control.rs:167-213`) | | REMOVE | Return data; the `target-agent`/`source-agent` CLI prints it |
| R16 | `println!` in binaries (CLI output) | `source-agent` (14), `target-agent` (11) | KEEP | This is user output. It must not be used for diagnostics; diagnostics go through events. |
| R17 | libdatachannel logging never enabled | `datachannel-rs/src/lib.rs:64-76` | ADD | Call `configure_logging(Warning)` at init, mapped into `tracing` under component `libdatachannel`; DEBUG through the filter. Fix `unreachable!()` in the callback (`lib.rs:37`) → map unknown levels to DEBUG. |
| R18 | Transfer ID logged as hex | `idr-transfer/src/native/manager.rs:271,723` | REPLACE | `transfer_id` as a UUID string (span field) |
| R19 | Env vars `RUST_LOG`/`IDR_LOG`/`IDR_LOG_LEVEL`/`IDR_LOG_JSON`/`IDR_LOG_FILE` | `target-agent/config.rs:797-801`; `source-agent/main.rs:37` | REPLACE | `IDR_LOG`, `IDR_LOG_FORMAT`, `IDR_LOG_DIR`; `RUST_LOG` deprecated for one release |
| R20 | `telemetry.log_level` / `log_json` in the agent TOML | `idr-target` config | IMPROVE | Keep the keys, mapped to `IDR_LOG` / `IDR_LOG_FORMAT`; the env var wins |
| R21 | Prometheus metrics in `idr-target` | `telemetry/metrics.rs` | KEEP | Unchanged; moves out of the `telemetry` module name to `metrics` to avoid confusion |

## 4. Crypto library (`dp-sdk`) and secret-bearing types

| # | Existing | Action |
|---|---|---|
| C1 | No logging | KEEP. Rule: dp-sdk crates never depend on `tracing` or `idr-telemetry` ([07 R-PRIV-4](07-rules-and-enforcement.md)). |
| C2 | `#[derive(Debug)]` on key holders: `DeviceIdentity`, `MtlsClientMaterial`, `LoadedClientAuth`, `GeneratedKeyAndCsr`, `SelfSignedCa`, `GeneratedEd25519` (`dp-rust-mtls/src/lib.rs:35-364`); `idr-dp/src/identity.rs:17-21` | Hand-written `Debug` that prints `[REDACTED]` for key fields. **Security fix: do early in Phase 1.** |
| C3 | Protocol structs with tokens deriving Debug: `ClientHello.connection_token`, `WebRtcSessionOffer.session_token`, `SourceAgentIdentity.auth_token`, `ByorIceServer.credential` | Wrap in `Secret<String>`. Per the contract in [01 §2.3](01-architecture.md), serde is transparent, so the wire bytes and signatures are unchanged (golden test). `Debug` redacts, the value cannot be a log field, and code reads it with `.expose()`. |
| C4 | `dp-rust-sdk::Error::Http{body}` in `Display` | `Display` shows the status plus the parsed `code`; the body is available through an accessor, never in `Display` |
| C5 | Private PEM/JWK returned as C strings; `idr_dp_string_free` does not zeroize | Zeroize on free (the `zeroize` crate is already standard) — tracked as a security item, not logging |
| C6 | `dp-cli` prints the invite token (`commands/invite.rs:54`) | KEEP (an intentional CLI output), but add a `--quiet`; never log it |

## 5. Servers

### Presence

| # | Existing | Action |
|---|---|---|
| P1 | `init_tracing` (`main.rs:25-36`), `log_json=false` in every config, `RUST_LOG=info` in the systemd unit | REPLACE with `idr_telemetry::init_from_env("presence")`. The JSON default goes to stdout. Remove `RUST_LOG` from `deploy/idr-presence.service`. |
| P2 | Per-frame INFO, including each ICE candidate (`wss/mod.rs:262,476`; `quic/mod.rs:380`) | DEBUG `signaling.message.received{message.type}` |
| P3 | 120-character JSON `preview` at info (`quic/mod.rs:347`; `wss/mod.rs:448`) | REMOVE (on parse failure: `signaling.message.rejected{error.type=parse, bytes}`) |
| P4 | WSS/QUIC duplicate paths with a " (WSS)" suffix | REPLACE with one event plus `network.transport` (the code duplication itself is out of scope, but the log calls are shared helpers) |
| P5 | 0 ERROR-level logs | Reclassify per §2 of [03](03-log-schema-and-events.md): verification failures → WARN `signaling.message.rejected`; internal failures → ERROR |
| P6 | Client IPs at info under `peer` / `remote` | `client.address` truncated to /24 or /48; full address at DEBUG |
| P7 | `e.to_string()` returned in `presence_error` | Return `error.type` + `trace_id` |
| P8 | `session_id` logged (it is a wire per-negotiation ID) | Logged as `connection_id`, plus `session_id` from `telemetry.logical_session_id` when present |
| P9 | `?reply` from Billing at debug (`domain_alias_client.rs:154`) | IMPROVE: status + parsed code only |
| P10 | Outbound reqwest to Billing without request IDs | Send `traceparent` + `x-request-id`; log the response's `http.request_id` |
| P11 | **V2:** accept `telemetry` (the protocol copy in `src/protocol/*`) | Exclude it from signature canonicalization when verifying requests and registrations. **Copy it into the `WebRtcSessionOffer` built in `source/mod.rs:361`**, with `traceparent` set to the routing span; clear it before signing. Pass it through on forwarded raw JSON frames. |
| P12 | Stray `presence-debug.out` / `.err`; plaintext `session_policy_token` in `config/presence.prod.toml` | REMOVE the stray files; move the token to an env or secret file (a security note, outside logging) |

### Relay

| # | Existing | Action |
|---|---|---|
| L1 | `telemetry/tracing.rs:6-23`, no JSON env | REPLACE with `init_from_env("relay")` |
| L2 | `request_id` passed as a parameter with `stage=` | REPLACE with the span `relay.edge.connection` carrying `connection_id`; the stages become span events / child spans (`relay.target.resolve`, `relay.wake`, `relay.tunnel`) |
| L3 | ~8–10 info lines per browser connection | Reduce to the span record plus at most two events; the rest goes to DEBUG |
| L4 | QUIC handshake failures DEBUG-only (`acceptor.rs:58-100`) | WARN `connection.handshake_failed`, rate-limited |
| L5 | Raw error in the 502 body and in logs (`passthrough.rs:160,412`) | The 502 body shows `Error ref: <trace_id>`; the log carries `error.type` + a redacted message |
| L6 | Relay-minted `session_id` | Logged as `connection_id`; serde rename as R7 |
| L7 | Mixed `tracing::info!` / `info!`; field drift (`remote_addr`/`peer`/`addr`) | `fields::*` constants |
| L8 | Billing usage (`ureq`) without request IDs | Send `traceparent` + `x-request-id` |
| L9 | Diverged `src/protocol/*` copy | V1: the serde rename (L6) in all copies. V2: add `TelemetryContext` to all copies in one change set; record the divergence as risk R4. |
| L10 | Dockerfile `IDR_RELAY_SQLITE` (dead) | Out of scope; noted for the Relay owners |

### TURN, usage-reporter, DNS

| # | Existing | Action |
|---|---|---|
| T1 | coturn `verbose` + `simple-log` | KEEP the format; parse it in Alloy. Revisit `verbose` once D20 removes the email from usernames. |
| T2 | `TURN_METRICS_PORT` not applied | Out of scope; noted |
| U1 | `console.*` mixing JSON and strings; full Billing error bodies | REPLACE with the in-file `log()` (`idr.log/1`); status + code only; send `traceparent`/`x-request-id` |
| N1 | Python `basicConfig` text | REPLACE with the JSON formatter; event names `dns.relayset.*` |
| N2 | PowerDNS query logging off | KEEP (privacy) |

### Billing (`Auth_repo`), optional, V2

| # | Existing | Action |
|---|---|---|
| B1 | pino with `x-request-id` echo | KEEP; add `traceparent` parsing to pino-http `customProps` so Billing records carry the client's `trace_id` |
| B2 | Fastify `req-N` IDs (`api/src/index.ts`) | Set `genReqId` / `requestIdHeader: 'x-request-id'` |

## 6. Done criteria per component

A component counts as migrated only when all of these hold:

- No call site uses the old helpers. Lint: `print`/`println!`/`developer.log`/`idrLog` are banned in the package.
- Every emitted event and attribute is registered.
- The schema-validation test passes on the component's e2e output.
- The redaction vectors pass.
- **No INFO record per frame, packet or ICE candidate** (verified by a volume test: one connect produces 25 INFO records or fewer per side).
- The scenario walkthroughs in [05](05-investigation-scenarios.md) that involve the component have been replayed: V1 in the local e2e environment, V2 in the staging replay suite ([08 P3-09](08-implementation-plan.md)).
