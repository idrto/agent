# IDR Unified Logging, Tracing and Diagnostics: Architecture Plan

**Status:** FINAL DESIGN, 2026-11-23. **Phase 1 implementation started 2026-11-23.**
- The external review findings are incorporated, and the V1/V2 scope and the upgrade-together policy are decided ([09](09-decisions-risks-approval.md)).
- Implementation progress is tracked in [08](08-implementation-plan.md).

**Scope:** every IDR component:

- Flutter GUI and Dart CLIs (`applications/apps`)
- the Rust agent engine (`agents_engine/agent`)
- the crypto library (`agents_engine/dp-sdk`)
- Presence, Relay, TURN, the TURN usage-reporter and the DNS server (`Servers/`)
- the HTTP touch points with Billing (`Auth_repo`)

## Why this exists

The design is for **root-cause analysis**, not for keeping a record that things worked. When a user says "it stopped connecting yesterday evening", a developer must be able to:

1. Find that user's application run, from a diagnostic report or from a time window plus device.
2. See every operation that run attempted, each one isolated in its own trace.
3. Follow each operation across processes and machines: Flutter → Dart SDK → Rust FFI or agent process → Presence → Target agent → Relay or TURN.
4. Read the state transitions and surrounding context that explain *why* it happened, even when no error was thrown.

Today none of this is possible. See the [audit](00-current-state-audit.md).

## Releases

| | V1: local-first (Phases 1–2) | V2: distributed and central (Phase 3) |
|---|---|---|
| Clients | Structured JSONL files, rotation with active-file locks, the flight recorder, crash capture, unclean-exit detection | — |
| Context | Within a machine: Zones/spans, `ctx_json` over FFI, isolates and IPC, `TRACEPARENT` to agents, `traceparent` to Billing | Across machines: `telemetry` on 4 signaling messages |
| Diagnostics | Local bundle export; the user attaches it to a support request | Consented upload to `diag-ingest`, display codes |
| Servers | JSON to stdout, cleaned-up events and levels, truncated IPs, error refs | Alloy → Loki → Grafana, dashboards, alerts |
| Cross-machine join | `connection_id`, `transfer_id`, `target.fqhn`, time | plus `trace_id` |

## Documents

| # | Document | Contents |
|---|---|---|
| 00 | [Current-state audit](00-current-state-audit.md) | What exists today, with file:line citations |
| 01 | [Architecture](01-architecture.md) | Principles, packages and APIs (including the `Secret<T>` contract), per-process integration, context carriers, flow diagrams |
| 02 | [Identifiers](02-identifiers.md) | Every ID: purpose, owner, format, lifetime, propagation, and lifecycle examples |
| 03 | [Log schema and events](03-log-schema-and-events.md) | The `idr.log/1` record, `seq` per producer, size caps, levels, naming, `persist_start`, the event catalogue |
| 04 | [Storage, crashes, diagnostics, privacy](04-storage-crash-diagnostics-privacy.md) | Files and ownership, retention, the recorder, crash and unclean exit, bundles, redaction of every string, byte-capped performance, central collection (V2) |
| 05 | [Investigation scenarios](05-investigation-scenarios.md) | Worked IDR cases, with V1 and V2 investigation paths |
| 06 | [Migration](06-migration.md) | Every existing log mechanism and what it becomes |
| 07 | [Rules and enforcement](07-rules-and-enforcement.md) | Mandatory rules for developers and AI agents, tests, CI gates, versioning, approvals |
| 08 | [Implementation plan](08-implementation-plan.md) | Phases 0–3 as tasks with acceptance criteria, mapped to V1 and V2 |
| 09 | [Decisions, review resolutions, risks, approval](09-decisions-risks-approval.md) | Decisions D1–D14, the review findings and their resolution, risks, compatibility, the checklist |

## The design on one page

- **One record format everywhere.**
  - JSON Lines with schema `idr.log/1`, using the same fields in Dart, Rust, Node and Python.
  - Spans are records too: they are written when they end, and long-lived spans also write a start record. Logs alone are enough to rebuild what happened.
- **Standard IDs.**
  - `trace_id` and `span_id` are W3C/OpenTelemetry-compatible hex values, with no prefixes.
  - Every other ID is a full hyphenated UUID; new ones are v7. A prefix is never used as an identifier.
- **Two shared libraries, one spec.** `idr-telemetry` (Rust) and `idr_telemetry` / `idr_telemetry_flutter` (Dart), plus a JSON Schema, an event registry and test vectors. dp-sdk stays logging-free.
- **Context flows with the work.**
  - Within a machine: Dart Zones, Rust spans, and `ctx_json` (trace plus session, operation and transfer IDs) across FFI, isolates and IPC.
  - Across machines in V2: a `telemetry` object, excluded from signatures, on `WebRtcSessionRequest`, `WebRtcSessionOffer`, `TargetRegistration` and `EnsureRelayConnectionCommand`.
- **Each producer owns its own run.** It holds a lifetime lock on the run; retention deletes only segments that are provably closed, and never deletes a run whose ownership is unknown. Unclean exits are detected per run. The recorder is drained by the writer, never through the queue. The logs live in one per-user directory. Stdout parsing between Dart and Rust stops.
- **Privacy first.**
  - Every string is redacted before it reaches memory, disk or a crash record.
  - `Secret<T>` keeps credentials on the wire but out of logs.
  - Nothing leaves the device without the user.
- **Bounded cost.**
  - Byte caps: queue 1 MiB, recorder 3 MiB, record 8 KiB.
  - DEBUG is kept in memory and flushed only on error, stall, crash or report. Per-frame detail is TRACE.
- **Native libraries ship with the app** (D14), so the ABI is bumped rather than negotiated.
- **Rules are enforced by CI:**
  - lints for `print` and `println!`
  - the event-registry check
  - schema validation of e2e output
  - redaction, storage and memory tests
  - an ADR for any architectural change
