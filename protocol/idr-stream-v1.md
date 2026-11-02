# IDR Stream Multiplexing Protocol v1

**Status:** Evolving (Phase 4)  
**Wire label:** DataChannel `idr-stream-v1` / protocol `idr.stream/1`  
**Encoding:** `[u32 BE length][postcard(StreamFrame)]`  
**Canonical Rust:** `idr-protocol::stream_mux`

## Goals

- Many logical TCP-style streams over one reliable ordered DataChannel
- Explicit flow control and backpressure
- Forward-compatible evolution without breaking legacy Open/Data/HalfClose/Reset

## Stream identifiers

| Allocator | IDs |
|-----------|-----|
| Source-initiated | odd: 1, 3, 5, … |
| Target-initiated | even: 2, 4, 6, … (reserved; not required initially) |
| Connection-level | `stream_id = 0` on `WindowUpdate` |

## Framing

```text
+-------------+---------------------+
| len (u32 BE)| postcard(StreamFrame) |
+-------------+---------------------+
```

- `len` is the postcard payload size only (not including the 4-byte length).
- Maximum postcard payload: `MAX_FRAME_BYTES` (64 KiB).
- Malformed length / truncated body → `InvalidFrame`; reset affected stream or close session.
- JSON is **not** used for bulk DATA.

## Postcard variant ABI (stable prefix)

| Index | Variant | Legacy peer |
|------:|---------|-------------|
| 0 | `Open` | yes |
| 1 | `Data` | yes |
| 2 | `HalfClose` | yes |
| 3 | `Reset` | yes |
| 4 | `OpenOk` | no — do not send to legacy |
| 5 | `OpenError` | no |
| 6 | `WindowUpdate` | no |
| 7 | `Ping` | no |
| 8 | `Pong` | no |
| 9 | `GoAway` | no |
| 10 | `AuthRefresh` | no |
| 11 | `Hello` | no |
| 12 | `HelloAck` | no |
| 13 | `ServicesCatalogRequest` | no — Source→Target after DataChannel up |
| 14 | `ServicesCatalog` | no — Target→Source service names |
| 15 | `ServicesCatalogDetailed` | no — Target→Source structured entries (credential_mode, TLS) |

**Rule:** only **append** new variants. Never reorder or insert.

## Profiles

### Legacy

Only variants 0–3. `Open` implies the stream is ready (no `OpenOk`). Local receive queues must still be bounded.

### FlowControlV1

Feature tokens: `flow_control_v1`, `open_ack`, `ping`.

- After `Open`, peer must reply `OpenOk` or `OpenError` before DATA.
- Senders honor stream + connection windows; `WindowUpdate` returns credit.
- `Ping`/`Pong` for liveness; `GoAway` stops new streams.

Negotiation (preferred): advertise features in WebRTC signaling capabilities.  
Optional mux `Hello`/`HelloAck` may confirm windows; do **not** send `Hello` to unknown legacy Targets (decode failure).

### Credit flow control (`flow_credit_v1`)

Negotiated in-band: right after the DataChannel opens, the Source sends `Hello` with
`flow_control_v1`, `open_ack`, `ping`, `flow_credit_v1` and its connection receive window
(`CREDIT_CONN_WINDOW`, 4 MiB). A Target that supports it answers `HelloAck` listing
`flow_credit_v1` and its own connection receive window. Every Target that serves
`ServicesCatalogRequest` (which Sources already send on connect) decodes `Hello`.

When both sides list it:

- Each DATA frame costs `max(payload, MIN_DATA_CHARGE)` (8 KiB) against the stream window
  (initially 256 KiB, `OpenOk.initial_window` for Source→Target) **and** the connection window.
  The minimum charge bounds in-flight *messages*, so a full window always fits the receiver's
  DataChannel callback queue (`DC_EVENT_QUEUE_CAPACITY` = 1024 ≥ 4 MiB / 8 KiB + 512 control).
- Receivers return stream credit with `WindowUpdate { stream_id }` after the application consumes
  the data, and connection credit with `WindowUpdate { stream_id: 0 }` as soon as a frame leaves
  the DataChannel queue.
- A receiver never waits on one stream's reader. A peer that sends past a stream's window gets
  that stream `Reset { reason: RESET_FLOW_CONTROL }`; other streams are unaffected.
- Credit beyond `MAX_SEND_CREDIT` (64 MiB) is ignored.

Version skew: if either side doesn't list `flow_credit_v1` (older SDK or Target, or no
`HelloAck`), neither side enforces windows or relies on credit. That is the pre-credit behavior,
except that a new Source no longer stops at 256 KiB toward an old Target (which never returned
credit). Callback-queue overflow ends the session on both sides in every mode: a dropped message
is lost stream data.

### Target-initiated streams (`peer_open_v1`)

The Source lists `peer_open_v1` in `Hello` (only together with `flow_credit_v1`); the Target
echoes it in `HelloAck` and only then may send `Open` with an **even** stream id. The Source
answers `OpenOk { initial_window }` for services it has registered to accept, and
`OpenError` (`service_not_found`, `invalid_argument`, `resource_exhausted`) otherwise. Before
this feature, Sources ignored inbound `Open`.

### Scheduling and admission (implementation, not wire)

- Each side sends control frames (`WindowUpdate`, `Open*`, `Reset`, `Ping/Pong`, `Hello*`,
  catalog) before interactive stream data, and bulk data only while the DataChannel's
  `bufferedAmount` is below 256 KiB. A stream's `HalfClose` is queued behind its own data.
- The Target admits a Source `Open` only if the id is odd and unused, fewer than
  `MAX_STREAMS_PER_SESSION` (256) streams are open, fewer than 16 upstream connects are in
  flight, and the per-session open rate (32/s, burst 64) allows it; otherwise `OpenError
  resource_exhausted` / `invalid_argument`. Upstream connects run off the session loop; DATA for
  a stream still connecting is buffered within its window.

## Frame semantics

### Open

Source (or Target) requests a logical stream: `stream_id`, `StreamKind`, `StreamOpenMeta` (`target_fqhn`, optional `service_name` for ConnectorRegistry, optional `host`/`port` for TcpConnect).

### OpenOk

Peer accepted the open. Carries `initial_window` (send credit for this stream).

### OpenError

Peer refused; `code` uses `OpenErrorCode` (`service_not_found`, `unauthorized`, …).

### Data

Application bytes. Counts against send windows in FlowControlV1.

### WindowUpdate

`credit` bytes returned to the peer. `stream_id == 0` credits the connection window only.

### HalfClose / Reset

Graceful FIN vs abort. `Reset.reason` is implementation-defined u16.

### Ping / Pong

`opaque` echoed in `Pong`.

### GoAway

Sender will reject new opens; finish streams ≤ `last_stream_id` when possible.

### AuthRefresh

Optional token refresh blob (opaque).

### Hello / HelloAck

`version` (`STREAM_MUX_VERSION`), `features[]`, `conn_window`.

### ServicesCatalogRequest / ServicesCatalog / ServicesCatalogDetailed

After the DataChannel (or future relay pipe) is up, Source may request the Target's live `openStream` catalog. Target replies with:

1. `ServicesCatalog { services }` — name list (legacy Sources)
2. `ServicesCatalogDetailed { entries }` — structured metadata (`kind`, `credential_mode`, `require_upstream_tls`)

Presence is not involved — catalog rides the P2P/relay path only. New Sources prefer the detailed frame when present.

## Default windows

| Parameter | Default |
|-----------|---------|
| Initial stream window | 256 KiB |
| Connection window | 16 MiB |
| Suggested DATA payload | 16–64 KiB |
| WINDOW_UPDATE threshold | ~½ stream window consumed |

Values are configurable; implementations must not buffer unboundedly.

## Unknown / malformed frames

- Truncated or oversize frames → protocol error; close DC or reset streams.
- Unknown postcard variant (newer peer → older decoder) → decode error. **Prevention:** do not send extended variants until the peer profile is FlowControlV1.
- Future: optional outer type-length envelope for skippable unknown types (not in v1).

## Compatibility bridge

| Local | Remote | Behavior |
|-------|--------|----------|
| Legacy | Legacy | Open/Data/HalfClose/Reset only |
| FlowControlV1 | Legacy | Send only legacy frames; treat Open as immediately ready (no OpenOk wait beyond short timeout) |
| FlowControlV1 | FlowControlV1 | Full OpenOk + windows + ping |
| Legacy | FlowControlV1 | Remote should not send extended frames; if OpenOk arrives, legacy decoder fails — remote must detect legacy via signaling |

## Failure semantics

Transport loss resets logical streams; DATA is not automatically replayed. Idempotent retry belongs to HTTP/application layers.

## Test vectors

See [`test-vectors/`](./test-vectors/) and `idr-protocol` unit tests (`stream_mux` + vector snapshots).
