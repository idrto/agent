# 03: Log Schema, Severity, Naming, and the Event Catalogue

## 1. Record schema `idr.log/1`

There is one JSON object per line, UTF-8, with no pretty-printing. The machine-readable definition is `spec/telemetry/log-record.schema.json` (agent repo).

### 1.1 Log record

```json
{
  "schema": "idr.log/1",
  "kind": "log",
  "ts": "2026-11-21T10:12:40.183512Z",
  "seq": 18233,
  "level": "WARN",
  "event": "connection.lost",
  "msg": "WebRTC connection lost; reconnecting",
  "service": "idrs",
  "service_version": "1.4.2+build.311",
  "component": "idr_source.connect",
  "app_session_id": "019372b0-11aa-7e01-8c1d-2f6a9b0c0001",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "span_id": "00f067aa0ba902b7",
  "session_id": "019372b4-6b1e-7cc2-9a59-0b5c9f0e2a11",
  "connection_id": "7f3e0c52-9a43-4b8e-8d0e-6a6f2b0f6e10",
  "attrs": {
    "reason": "ice_disconnected",
    "target.fqhn": "gpu--acme.idr.to",
    "webrtc.ice_state": "disconnected",
    "webrtc.candidate_pair.type": "relay",
    "connection.age_ms": 755210,
    "bytes.rx": 18822011, "bytes.tx": 220391
  }
}
```

### 1.2 Span record (emitted when the span ends)

```json
{
  "schema": "idr.log/1", "kind": "span",
  "ts": "2026-11-21T10:00:05.902100Z", "seq": 412, "level": "INFO",
  "event": "source.connect.attempt", "service": "idrs", "service_version": "1.4.2+build.311",
  "component": "idr_source.connect", "app_session_id": "…",
  "trace_id": "4bf9…4736", "span_id": "a1b2c3d4e5f60718", "parent_span_id": "00f067aa0ba902b7",
  "links": [{"trace_id": "…", "span_id": "…"}],
  "start_ts": "2026-11-21T10:00:05.101030Z", "duration_ms": 801.07,
  "status": "error", "error": {"type": "ice_failed", "message": "ICE failed after 3 candidate pairs"},
  "session_id": "…", "connection_id": "…",
  "attrs": {"retry.attempt": 1, "transport.selected": "none"}
}
```

### 1.3 Fields

| Field | Type | Req | Notes |
|---|---|---|---|
| `schema` | string | ✔ | `idr.log/1` |
| `kind` | `log` / `span` / `crash` | ✔ | |
| `ts` | RFC 3339 UTC, microseconds | ✔ | For a span: its end time |
| `seq` | u64 | ✔ | Monotonic counter **per producer**, where a producer is one log file stream: the Dart side and the in-process Rust side of one `app_session_id` each have their own. It orders records within a producer even if the wall clock jumps. Across producers, readers order by `ts`, then by producer (`service`, then file), then by `seq`. |
| `level` | enum | ✔ | See §2. A span takes its level from its status: `ok` → INFO (or DEBUG for spans registered as debug), `error` → ERROR or WARN as registered. |
| `event` | string | ✔ | The registered event or span name (§3) |
| `msg` | string | – | Short human sentence. It is **never parsed** and never contains IDs or values that belong in `attrs`. |
| `service` | string | ✔ | The process kind (`idr_target_app`, `idrs`, `idr`, `target-agent`, `source-agent`, `idr-c-api`, `presence`, `relay`, `turn`, `usage-reporter`, `dns-updater`) |
| `service_version` | string | ✔ | Semver plus build |
| `component` | string | ✔ | Dotted module (`idr_target.agent`, `idr_target::webrtc::session` → `idr_target.webrtc.session`) |
| `app_session_id` | uuid | ✔ | |
| `trace_id`, `span_id` | hex | when in a span | |
| `parent_span_id`, `links`, `start_ts`, `duration_ms`, `status` | | span only | |
| `session_id`, `connection_id`, `transfer_id`, `operation_id` | uuid | when in scope | Inherited from scope |
| `report_id` | uuid | diag only | |
| `error` | object | on failures | `{type, message, code?, stack?, cause?: error}`. `type` is a stable snake_case kind, e.g. `IdrErrorKind` mapped to snake_case. `message` is redacted. `stack` is present for ERROR and crash. |
| `attrs` | object | – | Registered attributes only (`attributes.yaml`); flat dotted keys. Values are string, number, bool, or an array of these. |
| `dropped` | u32 | – | Count of records dropped before this one, due to overload or rate limiting |

**Rules:**
- Key names are snake_case or dotted lowercase.
- No nested objects except `error`, `links` and `attrs`.
- **Size cap: 8 KiB per serialized record.**
  - Oversized records are reduced in this order: stack trimmed to 32 frames, then `stderr_tail` trimmed, then the longest string attribute truncated with `"…[truncated N]"`.
  - If the record is still too large, it is replaced by a `diag.record.oversized{event, bytes}` record.
  - Crash records are exempt, with their own 256 KiB cap.
- `flushed: true` marks records written from the flight recorder ([04 §2](04-storage-crash-diagnostics-privacy.md)).

### 1.4 Resource fields (written once, in `app.started`)

- `os.type`, `os.version`, `host.arch`
- `device.model` (mobile)
- `app.flavor` (personal, enterprise, …)
- `process.pid`
- `parent_app_session_id`
- `locale`
- `tz.offset_min`
- `build.commit`
- the `telemetry.schema_version` the library implements

These are not repeated on every record.

## 2. Severity levels

| Level | Meaning | Examples | Destination (client) | Destination (server) |
|---|---|---|---|---|
| **FATAL** | The process cannot continue. Written synchronously, just before exit or abort. | panic, unrecoverable init failure | file + crash record | stdout |
| **ERROR** | An operation failed **and** the user-visible goal was not met, or data integrity is at risk. It needs developer attention if repeated. | `connection.attempt.failed` when the final attempt fails, `transfer.failed`, `agent.process.crashed`, `auth.sign_in.failed` (non-user error) | file; **triggers a flight-recorder flush** | stdout |
| **WARN** | Something unexpected happened that was recovered or will be retried, or a degraded mode was entered. | reconnect scheduled, fallback to TURN or Relay, token near expiry, rate limit, `transfer.stalled` | file; flushes the recorder for `*.stalled` / `*.timeout` | stdout |
| **INFO** | A meaningful lifecycle fact: an operation started or ended, a state transition, a user intent, configuration effective at start. | `session.started`, `connection.established`, `session.state_changed`, `transfer.completed`, `app.started` | file | stdout |
| **DEBUG** | Step detail needed to explain a failure, but too voluminous to keep always. **Bounded per operation:** tens of records, not thousands. | each ICE candidate (type and protocol only), each signaling message type, each IPC command, retry timers | **flight recorder only**. DEBUG call sites stay enabled while the recorder is on; written to the file when `IDR_LOG=debug`. | recorder (in memory); stdout only when enabled per module |
| **TRACE** | Per-frame, per-message or per-chunk detail. Development only. **Never captured by the recorder.** | frame dumps (still redacted), per-chunk transfer events | off unless `IDR_LOG` enables it | off |

**Classification rules:**
- **Expected user errors are INFO, not ERROR.** Examples: wrong Target name, not enrolled, seat full. They become `outcome=denied` on the operation's span. The ERROR level is reserved for failures a developer might need to fix.
- **A failure is logged once, at the boundary that decides its outcome.** Intermediate layers attach context and return the error. They do not log and rethrow (see [07 R-LOG-5](07-rules-and-enforcement.md)).
- **Every ERROR or WARN has an `error.type`.** Free-text-only errors are rejected by the lint.

## 3. Naming

### 3.1 Events

- Format: `<domain>.<object>.<action>` or `<domain>.<action>`.
  - Lowercase.
  - Segments are `[a-z0-9_]+`.
  - 2–4 segments.
- Actions describe a **fact in the past tense**: `started`, `completed`, `failed`, `changed`, `lost`, `received`, `rejected`, `timed_out`, `stalled`, `skipped`.
- Use `state_changed` with `attrs.from` / `attrs.to` for state machines, rather than one event per state.
- **No IDs, hosts or values in names.**

**Domains (closed list; additions need approval):**

| Domain | Covers |
|---|---|
| `app` | Process lifecycle |
| `source` / `target` | Source- and Target-side operation spans (`source.connect`, `target.session.accept`, `target.agent.*`), already used throughout these docs |
| `telemetry` | Library self-diagnostics on received context and configuration (`telemetry.context.invalid`) |
| `ui` | Screens and user intents |
| `auth` | SSO, tokens, session restore |
| `billing` | Plans, seats, checkout |
| `enroll` | Device enrollment, approval |
| `entitlement` | Agent JWT |
| `registration` | Host name |
| `session` | Logical session |
| `connection` | Any connection lifecycle |
| `signaling` | Presence messages |
| `webrtc` | ICE, DTLS, data channel |
| `relay` | Relay edge, tunnel, wake |
| `turn` | Credentials, allocation |
| `presence` | Registration, routing, server-side |
| `stream` | Mux streams and services |
| `transfer` | File transfer |
| `agent` | Agent process management, IPC |
| `ffi` | ABI boundary |
| `crypto` | dp-sdk *callers* only: key generation, CSR, sign; outcome only, never material |
| `dns` | Relay set updates |
| `usage` | Metering reports |
| `diag` | Bundles, uploads, telemetry self-diagnostics |
| `config` | Effective configuration |

### 3.2 Spans

- Format: `<domain>.<operation>` or `<domain>.<operation>.<step>`, using a verb or noun phrase: `source.connect`, `source.connect.attempt`, `signaling.session_request`, `webrtc.ice`, `transfer.send`, `presence.session.route`, `relay.edge.connection`, `relay.wake`.
- A span name is the operation, not the outcome. The outcome goes in `status`, `error` and attributes.
- Span names are also registered in `events.yaml` (`kind: span`).
- **`persist_start: true`** in the registry makes the library write a `kind:"log"` record `<span name>.started` (INFO) when the span opens. This is required for spans that can stay open for a long time:
  - `source.connect`, `source.connect.attempt`
  - `transfer.send`, `transfer.receive`
  - `target.session.accept`
  - `agent.startup`
  - `relay.edge.connection`

  After an unclean exit, the operations that were open are the `.started` records without a matching span end record.

### 3.3 Attributes

- Use the OpenTelemetry semantic conventions name where one exists:
  - `error.type`
  - `server.address`, `server.port`
  - `network.transport` (`quic`, `tcp`, `udp`)
  - `network.protocol.name` (`wss`)
  - `http.request.method`, `http.response.status_code`, `url.path` (never `url.full` or the query string)
- IDR-specific names are dotted: `target.fqhn`, `device.ski`, `retry.attempt`, `retry.delay_ms`, `bytes.done`, `webrtc.candidate_pair.type`.
- Units go in the name suffix: `_ms`, `_bytes` (or the `bytes.` prefix), `_bps`.
- Every attribute is declared in `attributes.yaml` with its type and **privacy class** ([04 §5](04-storage-crash-diagnostics-privacy.md)). Undeclared attributes fail CI.

## 4. Required event catalogue (v1)

This is the minimum set that makes the scenarios in [05](05-investigation-scenarios.md) solvable. The full registry lives in `events.yaml`. Each entry there has: name, kind, level, required attributes, owner component, and the scenario it serves.

### 4.1 Process and app (all processes)

| Event | Level | Required attrs | Why |
|---|---|---|---|
| `app.started` | INFO | resource fields (§1.4), `config.effective` (redacted summary) | Establishes the run, versions, and config in effect |
| `app.startup.completed` | INFO | `duration_ms`, `phase.*_ms` | Startup performance (replaces `timing phase=`) |
| `app.lifecycle.changed` | INFO | `from`, `to` (resumed, paused, detached) | Mobile/desktop backgrounding explains drops |
| `app.network.changed` | INFO | `network.type` (wifi, cellular, none), `network.metered` | Explains disconnects |
| `app.stopping` | INFO | `reason` (user, signal, update, error) | Separates a clean exit from an **unclean exit**. A missing `app.stopping` means the run ended uncleanly: a crash, an OS kill, a power loss or a forced shutdown. Only a crash record proves a crash. |
| `app.clock.offset_measured` | INFO | `clock.offset_ms`, `source` (billing Date header) | Cross-host timeline alignment |
| `config.changed` | INFO | `key`, `from`, `to` (redacted) | |
| `diag.records.dropped` | WARN | `count`, `bytes`, `reason` (queue_full, rate_limited, oversized) | Telemetry self-health |
| `app.previous_exit_unclean` | WARN | `previous_app_session_id`, `crash_record` (bool), `open_operations` (started-not-ended span names) | Recovery hint on the next start |

### 4.2 UI and user intent (Flutter, CLI)

| Event | Level | Attrs |
|---|---|---|
| `ui.screen.viewed` | INFO | `screen` (route name) |
| `ui.action.invoked` | INFO | `action` (`connect`, `disconnect`, `retry`, `approve_device`, `start_agent`, `send_file`, …), `screen` |
| `ui.gate.shown` | INFO | `gate` (signed_out, no_seat, awaiting_admin, target_offline, stream_denied, …), `error.type` |
| `ui.error.shown` | INFO | `error.type`, `screen`. Links to the failing trace through scope. |
| CLI: `ui.command.invoked` / `ui.command.completed` | INFO | `command` (`connect`, `chat`, `transfer`, …; no argument values), `exit_code`, `duration_ms` |

### 4.3 Auth, billing, entitlement, enrollment, registration

| Event | Level | Attrs |
|---|---|---|
| `auth.session.restored` / `auth.session.restore_failed` | INFO / WARN | `error.type`, `auth.age_s` |
| `auth.sign_in.started` / `completed` / `failed` | INFO / INFO / ERROR or INFO (if `user_cancelled`) | `auth.method`, `error.type`, `http.response.status_code`, `http.request_id` |
| `auth.token.refreshed` / `refresh_failed` | DEBUG / WARN | `token.kind` (billing, entitlement), `token.expires_in_s` |
| `entitlement.token.minted` / `mint_failed` | INFO / ERROR | `token.expires_in_s`, `error.type`, `http.response.status_code` |
| `entitlement.token.rejected` (server says invalid) | ERROR | `rejected_by` (presence), `error.type` (expired, bad_audience, unknown_target_identity) |
| `billing.plan.checked` | INFO | `plan.code`, `seat.state` (available, full, none) |
| `enroll.request.submitted` / `enroll.state_changed` / `enroll.approved` / `enroll.rejected` | INFO | `operation_id`, `from`, `to` |
| `registration.host.registered` / `failed` | INFO / ERROR | `target.fqhn`, `error.type` |

### 4.4 Session, connection, signaling, WebRTC (Source, Target, Presence)

| Event | Level | Attrs | Emitted by |
|---|---|---|---|
| `session.started` | INFO | `target.fqhn`, `transport.preference` | Source |
| `session.state_changed` | INFO | `from`, `to` (connecting, connected, reconnecting, ended) | Source, Target |
| `session.ended` | INFO | `reason` (user, giving_up, signed_out, app_exit, target_ended), `attempts`, `duration_ms` | Source, Target |
| `connection.attempt.started` | INFO | `transport` (p2p, turn, relay), `retry.attempt` | Initiator |
| `connection.established` | INFO | `transport.selected`, `webrtc.candidate_pair.type` (host, srflx, prflx, relay), `rtt_ms`, `setup_ms` with `phase.signaling_ms`, `phase.ice_ms`, `phase.dtls_ms` | Both |
| `connection.attempt.failed` | WARN (ERROR if final) | `error.type` (signaling_timeout, target_offline, ice_failed, dtls_failed, denied, …), `phase` reached, `elapsed_ms`, `webrtc.ice_state`, `candidates.local.types`, `candidates.remote.types`, `turn.used` | Initiator |
| `connection.lost` | WARN | `reason`, `connection.age_ms`, `webrtc.ice_state`, `bytes.rx`, `bytes.tx`, `last_rx_ago_ms` | Both |
| `connection.closed` | INFO | `reason`, `connection.age_ms` | Both |
| `signaling.message.sent` / `received` | DEBUG, except ICE candidate messages, which are TRACE | `message.type`, `message.id`, `bytes` | Client, Presence |
| `signaling.message.rejected` | WARN | `message.type`, `error.type` (bad_signature, unknown_target, version) | Presence, Target |
| `signaling.transport.connected` / `disconnected` | INFO / WARN | `network.transport` (quic, wss), `server.address` (presence host), `presence.id`, `reason` | Agent |
| `webrtc.ice.candidate_gathered` | DEBUG | `candidate.type`, `candidate.protocol` (**no address**) | Both |
| `webrtc.ice.state_changed` | INFO (DEBUG for `checking`) | `from`, `to` | Both |
| `webrtc.datachannel.opened` / `closed` | INFO | `label` | Both |
| `turn.credentials.issued` | INFO | `turn.node_id`, `ttl_s` | Presence |
| `presence.target.registered` / `unregistered` | INFO | `target.fqhn`, `network.transport`, `presence.generation`, `reason` | Presence |
| `presence.session.routed` | INFO | `target.fqhn`, `route` (local, peer_presence) | Presence |
| `presence.session.route_failed` | WARN | `error.type` (target_offline, route_miss) | Presence |

### 4.5 Streams and transfers

| Event | Level | Attrs |
|---|---|---|
| `stream.opened` / `stream.closed` | INFO | `stream.id`, `service.name`, `reason`, `bytes.rx`, `bytes.tx`, `duration_ms` |
| `stream.open_failed` / `stream.denied` | WARN / INFO | `service.name`, `error.type` |
| `transfer.started` | INFO | `direction`, `entries`, `bytes.total` (no file names) |
| `transfer.progress` | DEBUG every 5 s; **INFO every 25 %**; per-chunk detail only at TRACE | `bytes.done`, `rate_bps` |
| `transfer.paused` / `resumed` | INFO | `reason`, `resume_points`, `bytes.done` |
| `transfer.stalled` | WARN (+ recorder flush) | `no_progress_ms`, `bytes.done`, `stream.state`, `buffered_amount`, `webrtc.ice_state`, `connection_id`, `peer.window` |
| `transfer.completed` | INFO | `bytes.total`, `duration_ms`, `avg_bps`, `retries` |
| `transfer.failed` | ERROR | `error.type` (`TransferErrorKind`), `entry.index`, `bytes.done` |
| `transfer.integrity.mismatch` | ERROR | `entry.index`, `expected_digest_prefix` (8 hex) |

### 4.6 Agent process, IPC, FFI

| Event | Level | Attrs |
|---|---|---|
| `agent.process.started` | INFO | `agent.kind`, `process.pid`, `child_app_session_id` (read back from the agent's ready line) |
| `agent.process.exited` | INFO (ERROR on non-zero or signal) | `exit_code`, `signal`, `uptime_ms`, `stderr_tail` (last 20 lines, redacted) |
| `agent.process.restarted` / `crash_budget_exceeded` | WARN / ERROR | `restart.count`, `backoff_ms` |
| `agent.ipc.request` (span) | DEBUG | `ipc.cmd`, `outcome` |
| `agent.ipc.failed` | WARN | `ipc.cmd`, `error.type` |
| `ffi.handle.bound` | INFO | `ffi.handle`, `connection_id` |
| `ffi.call.failed` | WARN | `ffi.fn`, `error.type`, `ffi.code` |
| `ffi.panic` | FATAL (crash record) | `ffi.fn`, `panic.message`, `panic.location` |

### 4.7 Relay

| Event | Level | Attrs |
|---|---|---|
| `relay.edge.connection` (span) | INFO | `connection_id`, `client.address` (truncated), `tls.sni` → `target.fqhn`, `outcome`, `bytes.*` |
| `relay.target.resolved` / `resolve_failed` | DEBUG / WARN | `target.fqhn`, `error.type` |
| `relay.wake.requested` / `acked` / `timed_out` | INFO / INFO / WARN | `relay.command_id`, `connection_id`, `wait_ms` |
| `relay.tunnel.opened` / `closed` | INFO | `connection_id`, `kind`, `bytes.*`, `duration_ms` |
| `relay.target.connected` / `disconnected` | INFO / WARN | `target.fqhn`, `connection.epoch`, `reason` |

### 4.8 Servers (generic)

| Event | Level | Attrs |
|---|---|---|
| `connection.accepted` | DEBUG (INFO for long-lived agent connections) | `network.transport`, `client.address` (truncated) |
| `connection.handshake_failed` | WARN, rate-limited | `network.transport`, `error.type` |
| `usage.report.sent` / `failed` | INFO / WARN | `usage.window_id`, `http.response.status_code`, `http.request_id` |
| `dns.relayset.updated` / `update_failed` | INFO / ERROR | `relay.count`, `error.type` |

## 5. Required context by failure class

Each failure class must carry the following, through the event itself or its enclosing span, so that a developer can find the cause without reproducing the problem.

| Failure | Must carry | Also flush |
|---|---|---|
| Connection failure | phase reached, `error.type`, `elapsed_ms`, ICE state, candidate *types* on both sides, TURN used, `retry.attempt`, network type, Presence transport and ID | flight recorder (signaling and ICE DEBUG) |
| Disconnection | reason, connection age, last-RX age, ICE state, bytes, network change in the preceding 30 s (from scope history) | recorder |
| Timeout | operation, configured timeout, elapsed, the last step completed (span events), the peer that did not answer | recorder |
| Stalled transfer | `no_progress_ms`, bytes, buffered amount, stream and peer window state, ICE state, CPU or disk-full indicators | recorder |
| Auth failure | stage (restore, sign-in, refresh, entitlement mint, Presence verify), HTTP status, `http.request_id`, server `error.type`, token kind and expiry delta (**never the token**), clock offset | — |
| Crash | stack, thread or isolate, the last 200 records from every in-process ring, open spans with their IDs, resource fields | (crash record) |
| Performance | span durations with per-phase breakdown, queue depths, `rate_bps` | — |
