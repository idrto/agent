# 02: Identifiers

## 1. Formats

| Kind | Format | Example | Standard |
|---|---|---|---|
| `trace_id` | 32 lowercase hex characters (16 random bytes, not all zero) | `4bf92f3577b34da6a3ce929d0e0e4736` | W3C Trace Context; OTel `TraceId` |
| `span_id` | 16 lowercase hex characters (8 random bytes, not all zero) | `00f067aa0ba902b7` | W3C; OTel `SpanId` |
| `traceparent` | `00-<trace_id>-<span_id>-<flags>` | `00-4bf9…4736-00f0…02b7-01` | W3C |
| All other IDs | lowercase hyphenated UUID, 36 characters. **Newly minted ones are UUIDv7** (time-ordered, which helps sorting and storage locality); IDs reused from the wire may be v4. | `019372b4-6b1e-7cc2-9a59-0b5c9f0e2a11` | RFC 9562 |

**Format rules:**
- **No prefixes and no type tags** on any ID. The JSON key says what the ID is.
- An ID is never re-encoded. For example, a transfer ID is never logged as hex; it is always the UUID string.
- IDs are generated **only** by `idr-telemetry` / `idr_telemetry` (`new_id()`, the span layer) or taken from a wire field listed below. Ad-hoc `Uuid::new_v4()` calls for logging purposes are forbidden ([07 R-ID-2](07-rules-and-enforcement.md)).
- **Randomness:** `trace_id` and `span_id` come from a CSPRNG (`Random.secure()` in Dart, `rand::rngs::OsRng` or `getrandom` in Rust). UUIDv7 random bits come from the same source.
- **Privacy:** none of these IDs contain or derive from user, device, or network data.

## 2. The ID catalogue

### `app_session_id`: one process execution

| | |
|---|---|
| **Purpose** | Groups everything one process did between start and exit. It is the first key a developer uses ("show me that run"). |
| **Owner** | `idr_telemetry` / `idr-telemetry` init in each process |
| **Created** | At logging init, as the first statement of `main` |
| **Lifetime** | Until the process exits. It is never persisted or reused. |
| **Embedded Rust** (`idr-c-api` inside the Flutter/Dart host) | **Adopts the host's ID.** It is the same process. |
| **Spawned child** (`target-agent`, `source-agent`) | Mints its own ID and records the parent's ID (from `IDR_PARENT_APP_SESSION_ID`) as `parent_app_session_id` in its `app.started` record |
| **Servers** | One per server process. Also exported as OTel resource attribute `service.instance.id`. |
| **On the wire** | **Never sent to servers.** A random process ID is low risk, but it is not needed: trace IDs give the join. |
| **Where it appears** | Every record (top-level field), file names, the bundle manifest |

### `session_id`: one logical Source–Target session

| | |
|---|---|
| **Purpose** | Groups every connection attempt, reconnect, stream and transfer that the user perceives as "being connected to Target X". |
| **Owner** | The Source side: `IdrSource` (Dart facade) for app/CLI connects, or `source-agent` for daemon connects. Exactly one owner per session. |
| **Created** | When the user (or a CLI command) asks to connect to a Target, **before** the first attempt |
| **Lifetime** | Ends on explicit disconnect, when the reconnect policy gives up (`session.ended{reason}`), on app or agent exit, or on sign-out. A reconnect after network loss **keeps** the `session_id`. A manual "Connect" after "Disconnect" is a new session. |
| **Propagation, V1** | Dart Zone → the FFI `ctx_json.session_id` argument (it cannot ride in `traceparent`) → the Rust span field `session_id`. The `source-agent` daemon owns its own sessions. |
| **Propagation, V2** | Additionally `telemetry.logical_session_id` on `WebRtcSessionRequest`. Presence copies it into the `WebRtcSessionOffer` it builds, and Presence and the Target log it. |
| **Target side** | V1: the Target does not see `session_id`. It correlates by `connection_id`. V2: the Target records the received `logical_session_id` as `session_id` on its per-session span. A Target never creates `session_id`. |
| **Reuse decision** | The existing wire field `session_id` is **not** this ID. It is per negotiation and becomes `connection_id`. |

### `connection_id`: one connection lifecycle

| | |
|---|---|
| **Purpose** | One network connection, from attempt to close: a WebRTC peer connection, a Relay tunnel, an agent→Presence transport connection, or a Relay edge TCP connection. |
| **WebRTC** | **The existing wire `WebRtcSessionRequest.session_id`.** It is minted by the Source per negotiation and is already signed, end-to-end, and embedded in the TURN username. In Rust code the field is renamed to `connection_id` with `#[serde(rename = "session_id")]`, so the wire bytes and signatures are unchanged ([06 §3](06-migration.md)). |
| **Relay tunnel** | **The existing Relay-minted `session_id`** in `EnsureRelayConnectionCommand` / `ClientHello`. It is renamed the same way. |
| **Transport connections** (agent ↔ Presence QUIC/WSS, Relay ↔ Presence, Relay edge TCP accept) | Each side mints its own with `new_id()` at connect or accept time. The two sides' IDs are **not** exchanged; they are joined through the trace of the operation that used the connection (`presence.register`). This avoids a wire change for every transport. |
| **Lifetime** | Starts at the attempt and ends at close, failure or timeout. It is never reused. Each retry is a new `connection_id`. |
| **Created by** | The initiator, for WebRTC and Relay tunnels. Each side, for transport connections. |
| **Replaces** | The Relay `request_id`, and the bare `peer` / `remote` addresses as a correlation key |

### `trace_id` and `span_id`: one operation and one step

| | |
|---|---|
| **Purpose** | `trace_id` is one complete operation or workflow; `span_id` is one instrumented step of it. |
| **Owner** | The span layer in each library. The root span of an operation mints the `trace_id`. |
| **Root operations (trace starts)** | User intents: `auth.sign_in`, `source.connect` (and each reconnect attempt), `stream.open`, `transfer.send`/`transfer.receive`, `target.agent.start`, `target.host.register`, `enroll.request`, `enroll.approve`, `diag.report.create`. Server-originated operations: `relay.edge.connection`, `presence.registration.expire`, the periodic `presence.target.sweep`. Background jobs: `entitlement.refresh`, `agent.health.check`. |
| **Lifetime** | Seconds to minutes. A trace must not stay open for longer than ~10 minutes; longer work uses `operation_id` plus linked traces. |
| **Propagation** | Within a process: Zone or `tracing` span scope. Across processes: `traceparent` (see [01 §4](01-architecture.md)). |
| **Sampling** | Always on. The flags byte is `01`. Volume is controlled by levels, not by sampling ([04 §6](04-storage-crash-diagnostics-privacy.md)). |
| **Inherited by** | Every log record emitted inside the span carries both IDs. |

### `transfer_id`: one logical transfer

| | |
|---|---|
| **Purpose** | One file or folder transfer, including retries, pause and resume, and reconnects |
| **Reuse decision** | **The existing `TransferId` ([u8;16], UUID v4 bytes).** It is already created once per transfer and reused by `resume(id)` (`idr-transfer/src/native/manager.rs:378`), so its semantics match. New transfers are minted with `new_id()` (v7); v4 stays valid. |
| **Owner** | The sender's `idr-transfer` manager |
| **Created** | When a transfer is requested, before the manifest is sent |
| **Lifetime** | Until completed, cancelled, or failed permanently. It is persisted in transfer state, so it survives restarts. |
| **Propagation** | Already on the wire in `StreamHeader.transfer_id`. The receiver logs the same value. |
| **Log format** | The hyphenated UUID string. The current `hex(id)` format is removed. |

### `operation_id`: long-running operations without a better ID

| | |
|---|---|
| **Purpose** | Groups multiple traces of one long or multi-step operation that outlives a single trace or process |
| **Used for (closed list; additions need approval)** | `enroll` (device enrollment awaiting admin approval: minutes to days), `host.registration` (host name registration and verification), `agent.install` / `app.update`, `diag.upload` (a bundle upload with retries), `entitlement.renewal` chains |
| **Not used for** | Anything that already has `session_id`, `connection_id` or `transfer_id`, or that fits in one trace |
| **Created** | When the operation starts. It is persisted alongside the operation's state (for example the pending enrollment record), so it survives restarts. |
| **Lifetime** | Until the operation reaches a terminal state |
| **Fields** | `operation_id`, plus `operation.kind` (from the list above) |

### `report_id`: one diagnostic report

| | |
|---|---|
| **Purpose** | Links a user-submitted report (or an automatically captured local bundle) to its contents and to server-side storage |
| **Created** | When the user opens "Report a problem", or when a crash or stall auto-capture runs |
| **Format** | UUIDv7. **V1** uses the full UUID everywhere: the bundle file name, `manifest.json`, and the text the user copies into a support message. |
| **Display code (V2, with uploads)** | A short code is needed only when users read it out to support. A UUIDv7 **prefix must not be used**, because its first 48 bits are the timestamp. The code is 10 Crockford-base32 characters built from **the 74 random bits** (`rand_a` + `rand_b`), formatted `XXXXX-XXXXX`. `diag-ingest` checks it for uniqueness on upload and returns a different code on collision. The stored key is always the full UUID. |
| **Lifetime** | As long as the bundle exists: 7 days locally, 30 days on the server (V2), or until the user deletes it |

### Existing protocol IDs that stay protocol IDs (not correlation keys)

| ID | Logged as | Level |
|---|---|---|
| `message_id` | `message.id` | DEBUG only |
| `command_id` (relay ensure) | `relay.command_id` | INFO on create and ack |
| `stream_id` (mux `u32`, QUIC `u64`) | `stream.id` | INFO on open and close |
| `connection_epoch`, `presence_generation` | `connection.epoch`, `presence.generation` | DEBUG |
| FFI handles (`u64` session/stream) | `ffi.handle` | logged **once**, in `ffi.handle.bound`, with the `connection_id` it maps to |
| IPC request counter | not logged; IPC requests use spans | — |
| `presence_id`, `relay_id`, `turn_node_id`, `tenant_id` | `presence.id`, `relay.id`, `turn.node_id`, `tenant.id` | INFO (infrastructure identity) |
| `target_fqhn` | `target.fqhn` (one name only; `fqhn` is removed) | INFO |
| SKI (device key ID) | `device.ski` | INFO. Pseudonymous; see [04 §5](04-storage-crash-diagnostics-privacy.md). |

## 3. Propagation matrix

|  | app_session | session | connection | trace / span | transfer | operation |
|---|---|---|---|---|---|---|
| Flutter ↔ Dart SDK | Zone (global) | Zone | Zone | Zone | Zone | Zone |
| Dart → FFI Rust | init arg | `ctx_json` | Rust logs `ffi.handle.bound` (no return to Dart) | `ctx_json.traceparent` | `ctx_json` + wire header | `ctx_json` |
| Dart → spawned agent | env (parent) | — (agent sessions are agent-owned) | — | env `TRACEPARENT` (start-up only) + IPC `ctx` | IPC `ctx` | IPC `ctx` |
| Agent → Presence | ✗ | V2: `telemetry.logical_session_id` | wire `session_id` (WebRTC) | V2: `telemetry.traceparent` | ✗ | ✗ |
| Presence → Target | ✗ | V2: copied into the new offer | wire `session_id` in the offer | V2: copied (child span) | ✗ | ✗ |
| Source ↔ Target data | ✗ | ✗ | implicit (same peer connection) | ✗ (link via IDs) | `StreamHeader` | ✗ |
| Relay ↔ Presence ↔ Target | ✗ | ✗ | Relay `session_id` | V2: `telemetry.traceparent` on ensure | ✗ | ✗ |
| Presence → TURN | ✗ | ✗ | in the TURN username | ✗ | ✗ | ✗ |
| Any → Billing HTTP | ✗ | ✗ | ✗ | `traceparent` header | ✗ | ✗ |

✗ = intentionally not propagated.

## 4. Lifecycle examples

### 4.1 Connect, drop, reconnect, disconnect

```text
app_session_id A  (idrs chat process starts 10:00:00)
│
├─ 10:00:05  user: idrs connect gpu--acme.idr.to
│   session_id S = 0193…a1  (session.started)
│   trace T1 root span source.connect
│     ├─ span source.connect.attempt   connection_id C1 = wire session_id 7f3e…
│     │    ├─ span signaling.session_request  (Presence: child span, Target: child span)
│     │    ├─ span webrtc.ice                 candidate_pair.type=relay
│     │    └─ event connection.established   (rtt_ms=48)
│     └─ span stream.open "ollama"  stream.id=1
│
├─ 10:12:40  network drop → event connection.lost {reason: ice_disconnected}  (C1, S)
│   session.state_changed {from: connected, to: reconnecting}
│   trace T2 (new root, LINK→T1) span source.reconnect.attempt  connection_id C2  attempt=1 → failed (timeout)
│   trace T3 (LINK→T2)           span source.reconnect.attempt  connection_id C3  attempt=2 → established
│   session.state_changed {from: reconnecting, to: connected}   (S unchanged)
│
└─ 10:30:00  user: disconnect → session.ended {reason: user, duration_ms: …, attempts: 3}  (S)
```

### 4.2 Transfer with a resume across a reconnect

```text
transfer_id X (minted at 10:05:00 under session S, connection C1, trace T4 transfer.send)
 10:05:00 transfer.started {entries: 120, bytes.total: 2.1 GB}
 10:12:40 transfer.paused {reason: connection_lost, bytes.done: 800 MB}    (C1)
 10:13:10 trace T5 (LINK→T4) span transfer.resume  (C3)
          transfer.resumed {resume_points: 3, bytes.done: 800 MB}
 10:19:55 transfer.completed {bytes.total: 2.1 GB, duration_ms: …, avg_bps: …}
Receiver (Target) logs the same transfer_id X with its own trace IDs; join on X.
```

### 4.3 Device enrollment awaiting admin approval

```text
operation_id E (operation.kind=enroll) persisted in enroll state file
 Day 1 09:00  trace T10 enroll.request → event enroll.request.submitted {device.ski: …}
 Day 1 09:00–17:00  poll traces (DEBUG; INFO only on change), each LINK→T10, operation_id E
 Day 1 17:05  app restart → new app_session_id; operation_id E reloaded → enroll.state.restored
 Day 2 08:10  trace T11 enroll.pull → event enroll.approved   (operation_id E)
 operation.ended {operation_id E, outcome: approved, duration_ms: …}
```

### 4.4 Target agent spawned by the Flutter app

```text
Flutter app_session_id G ── trace T20 target.agent.start
  spawn target-agent with env IDR_PARENT_APP_SESSION_ID=G, TRACEPARENT=00-T20-s5-01, IDR_LOG_DIR=…
target-agent app_session_id H:
  app.started {parent_app_session_id: G}
  span agent.startup (child of T20/s5) → presence.register (trace T20) → event app.startup.completed
  later Presence-initiated work: new root traces (V1); V2: parented from the offer's telemetry
```

## 5. ID test vectors (in `spec/telemetry/vectors/ids.json`)

Both libraries must pass the same vectors:
- `traceparent` parse/format, covering uppercase rejection, all-zero rejection, version `ff` rejection, and unknown future versions (accept the first 4 fields)
- UUIDv7 monotonicity within one millisecond
- `ctx_json` parse/format, including invalid-field handling
- the `#[serde(rename)]` round trip for `connection_id` (V1)
- V2 only:
  - the `report_id` display code, built from the random bits only
  - signature stability with and without `telemetry` on all four messages
