# 09: Decisions, Review Resolutions, Risks, Compatibility, Approval

## 0. Release scope (DECIDED 2026-11-23)

- **V1** is local-first. It covers Phases 1 and 2 in [08](08-implementation-plan.md):
  - persistent structured logs on every client
  - the flight recorder
  - crash capture and recovery
  - **local diagnostic bundle export** (the user attaches it)
  - in-machine context propagation (Dart, isolates, FFI, agents, IPC)
  - structured JSON on every server
  - cross-machine correlation by `connection_id`, `transfer_id`, `target.fqhn` and time
- **V2** covers Phase 3:
  - wire `telemetry` (distributed traces across Source, Presence, Target and Relay)
  - `diag-ingest` uploads and display codes
  - Alloy, Loki and Grafana, with dashboards and alerts
- **V1 code must not pre-build V2 pieces** ([07](07-rules-and-enforcement.md); no scaffolding "for later").

## 1. Decisions

| ID | Decision | Status | Resolution / recommendation |
|---|---|---|---|
| **D1** | Where the shared libraries and spec live | **decided 2026-11-23** | Inside the agent monorepo (`agents_engine/agent`): `crates/idr-telemetry`, `packages/idr_telemetry`, `packages/idr_telemetry_flutter`, `packages/idr_diag`, `spec/telemetry/`. ADR-0019. Presence and Relay use a tagged git dependency. |
| **D2** | UUID version for new IDs | decided | v7. **Never use a prefix of a v7 UUID as an identifier**: its first 48 bits are the timestamp. Full UUIDs go in file names; display codes use the random bits. |
| **D3** | OpenTelemetry SDK vs in-house span layer | decided | In-house layer; spans are `idr.log/1` records with W3C IDs. OTLP export is an optional later sink. |
| **D4** | Diagnostic upload endpoint | **deferred to V2** | Recommended: a small `diag-ingest` service, authenticated with the Billing JWT. |
| **D5** | Central log stack | **deferred to V2** | Recommended: Grafana Alloy + Loki + Grafana. |
| **D6** | Native crash capture (minidumps) | decided for V1 | Not in V1. Native-crash evidence is **best effort**: parent detection, the redacted stderr tail, persisted `*.started` records. Revisit if native crashes appear in the field. |
| **D7** | Retention | **adopted 2026-11-23 (recommended values; privacy/legal may revise)** | client 7 d / 100 MiB of deletable segments; server INFO 14 d (V2 central), DEBUG 3 d; bundles 30 d (V2) |
| **D8** | `RUST_LOG` compatibility | decided | Honoured for one minor release, with a deprecation event |
| **D9** | `sourceId = email` on the wire (also in TURN usernames and coturn logs) | **adopted 2026-11-23** | `device.ski`. A product and protocol change, planned in V1 (P1-36 + P2-02). |
| **D10** | Server IP logging | **adopted 2026-11-23** | truncated at INFO; full only at DEBUG with a per-host opt-in |
| **D11** | Size-based rotation | decided | In-house writer in both languages. Each run holds a lifetime lock; retention deletes only segments that are provably closed, and never deletes a run whose ownership is unknown ([04 §1.3](04-storage-crash-diagnostics-privacy.md)) |
| **D12** | Wire `telemetry`: signed or excluded | decided (V2) | Excluded from canonicalization by every signer and verifier, the Presence-built offer included |
| **D13** | Enterprise uploads | deferred to V2 | Allowed with consent; an admin policy can disable them |
| **D14** | Native library compatibility | **decided 2026-11-23** | **The app and its native libraries and agent binaries are upgraded together.** The existing exact `ABI_VERSION` match stays. There is no support for old apps loading new libraries, and no capability negotiation. The ABI version is bumped when the signatures change. |

## 2. External review findings (2026-11-23): resolution

| # | Finding | Resolution | Where |
|---|---|---|---|
| 1 | Presence builds a new signed `WebRtcSessionOffer` (`Servers/presence/src/source/mod.rs:361`), so trace context is lost Presence → Target | Verified. The offer is added to the carrier list; Presence copies `telemetry` into it and excludes it from signing; tests added. **V2.** | [01 §4](01-architecture.md), [06 R8/P11](06-migration.md), [08 P3-01](08-implementation-plan.md) |
| 2 | `traceparent` cannot carry `session_id`/`operation_id` over FFI | Added `ctx_json` `{traceparent, session_id, operation_id, transfer_id}` for FFI, isolates and IPC. The handle → `connection_id` mapping is logged by Rust (`ffi.handle.bound`) and joined offline, with no return channel. **V1.** | [01 §4.1–4.2](01-architecture.md), [02 §3](02-identifiers.md) |
| 3 | UUIDv7 prefixes collide (file names, display codes) | Full `app_session_id` in file names; the display code moves to V2 and is built from the 74 random bits, with a server collision check | [04 §1.2](04-storage-crash-diagnostics-privacy.md), [02 report_id](02-identifiers.md) |
| 4 | Retention can delete another process's active files; a long-running writer escapes the cap | A per-run lock is held for the process lifetime. Deletable segments are all segments of an ended run, plus the non-highest segments of an active run, the process's own included. Superseded in detail by round 2, item R2-2. | [04 §1.3](04-storage-crash-diagnostics-privacy.md) |
| 5 | Redaction covered only `msg` and `error.message` | Every string value (stack, causes, `stderr_tail`, `panic.message`, config, string attributes) is redacted before the ring, the file or a crash record | [04 §5.2](04-storage-crash-diagnostics-privacy.md), [07 R-PRIV-7](07-rules-and-enforcement.md) |
| 6 | `Secret<T>` "no Serialize" contradicts protocol use | Contract: transparent serde for the wire; redacting `Debug`/`Display`; not a telemetry field; `expose()` | [01 §2.3](01-architecture.md), [06 C3](06-migration.md) |
| 7 | "Additive ABI" conflicts with the exact version check (`engine.rs:48`) | Verified. Resolved by D14: upgrade together, keep the exact match, bump the version | [06 R4](06-migration.md) |
| 8 | Spans emitted only at end, so a native crash leaves no evidence of open work | `persist_start` start records for long-lived spans; native-crash evidence documented as best effort | [01 §1](01-architecture.md), [03 §3.2](03-log-schema-and-events.md), [04 §3](04-storage-crash-diagnostics-privacy.md), [05 §5b](05-investigation-scenarios.md) |
| 9 | Record-count limits allow about 128 MiB | Byte caps: queue 1 MiB, ring 3 MiB (mobile 1 MiB), record 8 KiB, oversized handling | [03 §1.3](03-log-schema-and-events.md), [04 §2, §6](04-storage-crash-diagnostics-privacy.md) |
| — | Dart and Rust share `app_session_id` but each counts `seq` | `seq` is per producer; ordering by `ts` → producer → `seq` | [03 §1.3](03-log-schema-and-events.md) |
| — | DEBUG call sites must stay live for the recorder | Global DEBUG while the recorder is on, sinks filter; per-frame detail is TRACE; cost budget restated | [01 §2.3](01-architecture.md), [03 §2](03-log-schema-and-events.md), [04 §6](04-storage-crash-diagnostics-privacy.md) |
| — | Alloy would drop flushed DEBUG records | Kept when `flushed=true` (V2) | [04 §7.1](04-storage-crash-diagnostics-privacy.md) |
| — | Missing `app.stopping` does not prove a crash | Reworded as "unclean exit"; a crash is claimed only with a crash record; `app.previous_exit_unclean` | [03 §4.1](03-log-schema-and-events.md), [04 §3.3](04-storage-crash-diagnostics-privacy.md) |

### Review round 2 (2026-11-23): resolution

| # | Finding | Resolution | Where |
|---|---|---|---|
| R2-1 | Unclean-exit detection looked at single segments, but rotated segments never contain `app.stopping` | Detection is **per run**:<br>1. Group the files by (`app_session_id`, producer).<br>2. Skip active or unknown runs (lock test).<br>3. Inspect only the highest segment of an ended run, plus its crash records.<br>4. Classify the run as clean, crash or unclean.<br>5. Claim it once with an exclusive-create `.ended` sidecar. | [04 §3.3](04-storage-crash-diagnostics-privacy.md) |
| R2-2 | The lock-failure fallback (modification time under 10 min) could delete an idle process's active file | **No modification-time fallback.** If ownership cannot be established (lock error, or a missing lock file), the run is **skipped entirely** and `diag.sink.degraded` is emitted; the disk guard bounds the disk usage. Locks are per run, held for the process lifetime, whatever the write activity. | [04 §1.3](04-storage-crash-diagnostics-privacy.md), R11 |
| R2-3a | The drain excluded INFO+ records on the assumption that the queue had written them, but the queue can drop the triggering ERROR | **Persistence is tracked, not inferred from severity.** Records are shared objects with a writer-set `persisted` flag. The drain writes every snapshot record with `persisted == false` and `seq ≤ watermark_seq`, the triggering record always included. `Flush` holds a direct reference to the trigger. | [04 §2.1](04-storage-crash-diagnostics-privacy.md) |
| R2-3b | Triggers merged into a running drain cannot capture their DEBUG records, which are in the new ring | At most one **active** and one **pending** drain. Mid-drain triggers merge into the pending drain, which splits again after the active snapshot is freed (≥ 1 s pacing). Bundle requests attach to the first drain that has not yet split and complete after its write and sync. | [04 §2.1](04-storage-crash-diagnostics-privacy.md) |
| R2-3c | Swapping the whole ring discarded records created between the trigger and the swap (`seq > watermark`) when the snapshot was freed, so no follow-up could recover them | **Split instead of swap.** The writer detaches only the `seq ≤ watermark` prefix, an O(1) cut by `seq`. Later records stay in the live ring under its byte cap, so a follow-up or later drain selects them by `persisted == false`. Loss is possible only through the ring's normal oldest-first eviction, which is counted as `ring_evicted_unflushed`. | [04 §2.1](04-storage-crash-diagnostics-privacy.md) |
| R2-3 | A 3 MiB recorder flushed through a 1 MiB queue would drop its own evidence; drop policies contradicted each other | **Writer-controlled drain:** one cap-exempt `Flush` control message (coalesced), an O(1) ring split at the watermark (superseded by R2-3c), a direct write of the snapshot to the segment in 256 KiB batches, selection by `persisted` (R2-3a), scope filter. Peak memory is 7 MiB (mobile 3 MiB). **Drop policies:** the queue drops the incoming record; the ring evicts the oldest; the snapshot is never dropped. | [04 §2.1, §6](04-storage-crash-diagnostics-privacy.md), [01 §2.3](01-architecture.md) |

## 3. Risks and mitigations

| ID | Risk | Release | Mitigation |
|---|---|---|---|
| **R1** | Naming confusion: the wire `session_id` = `connection_id`; the logs' `session_id` = the logical session | V1 | Serde rename of the Rust field; lint; [07 R-ID-2](07-rules-and-enforcement.md). A wire rename is deferred to the next protocol major version. |
| **R2** | Signed-message rollout: an old verifier would reject a signer that includes `telemetry` | V2 | Excluded from canonicalization (D12); every verifier deploys first, then signers turn it on (P3-02); interop tests in both directions |
| **R3** | ABI bump breaks a mismatched app/library pair | V1 | D14 (shipped together); the existing check fails fast with `IncompatibleVersion`; a test covers it |
| **R4** | Diverged `protocol/` copies (Presence, Relay, agent) | V1 rename, V2 field | One change set across the copies; shared golden vectors in `spec/vectors/` |
| **R5** | Overhead on mobile or high-throughput transfer, including live DEBUG for the recorder | V1 | Byte caps, DEBUG bounded per operation, TRACE for per-frame detail, benchmarks in CI; the recorder can be set to 0 per platform |
| **R6** | Disk usage on user machines | V1 | Closed-segment caps enforced by every process; disk guard at 500 MiB free |
| **R7** | Clock skew across hosts | V1 | `seq` per producer; `app.clock.offset_measured`; `idr_diag merge` applies the offset |
| **R8** | Privacy / regulatory | V1 (local), V2 (uploads) | Privacy classes, full-string redaction before sinks, user-controlled export; legal review before P3-04 |
| **R9** | Drift back to ad-hoc logging | V1 | CI gates; agent-instruction pointers in every repo |
| **R10** | The thread-local last error at FFI assumes the isolate stays on one OS thread | V1 (existing) | Recommend an out-parameter error message while the signatures change in P1-21 |
| **R11** | File locks on network or redirected home directories | V1 | The log root is always local app data, where OS locks work. If a lock attempt errors, or the lock file is missing, the run's ownership is **unknown**: none of its files are deleted, and `diag.sink.degraded{reason: ownership_unknown}` is emitted. Modification time is never used to decide ownership. The 100 MiB cap may then be exceeded; the 500 MiB free-disk guard still stops all writers. |
| **R12** | Billing and `Auth_repo` are owned separately | V2 | `http.request_id` captured client-side in V1 already gives a join |
| **R13** | coturn `verbose` logs full IPs and usernames | V1 | D9 removes the email; IP truncation in V2 Alloy; revisit `verbose` |
| **R14** | Scope creep into V2 during V1 | V1 | §0 rule; PR review |

## 4. Compatibility

- **App ↔ native library / agent:** these are always released together (D14). A mismatch fails fast; it is not a supported configuration.
- **Clients ↔ servers in V1:** there is no signaling wire change. The serde rename is byte-identical. Any mix of V1 and pre-V1 clients and servers interoperates.
- **Clients ↔ servers in V2:** the `telemetry` field is sent only after every verifier is deployed (R2). An old client without the field is always accepted.

| Client \ Server | Pre-V1 / V1 servers | V2 servers |
|---|---|---|
| Pre-V1 / V1 client | works (correlation by `connection_id`) | works |
| V2 client, flag on | **not allowed** until all verifiers are V2 | full distributed traces |

## Approval checklist

Implementation starts only when every box is ticked and the owners have signed.

**Phase 1 start authorized by the project owner on 2026-11-23**, after the external reviewer confirmed no remaining issues. The unticked per-repository acceptances below are collected in each component's migration PR.

**Scope and architecture**
- [x] V1/V2 scope (§0): agreed by the project owner, 2026-11-23
- [x] Review findings 1–9 and the clarifications resolved (§2): agreed by the project owner, 2026-11-23
- [x] D14 (upgrade together): agreed by the project owner, 2026-11-23
- [x] D1 repository location decided: the agent monorepo, 2026-11-23
- [ ] Principles, package responsibilities and dependency rules ([01](01-architecture.md)) accepted by the repo owners

**Identifiers and context**
- [ ] ID catalogue and reuse decisions ([02](02-identifiers.md)) accepted
- [ ] `ctx_json` FFI, isolate and IPC context and the ABI bump accepted by the engine owner
- [x] D9 (`sourceId = email` replacement): `device.ski` adopted by the project owner, 2026-11-23 (Presence owner informed in P2-02)

**Schema, storage, privacy**
- [ ] `idr.log/1` schema, levels, naming, v1 event catalogue ([03](03-log-schema-and-events.md)) accepted
- [ ] Storage ownership, retention, byte caps, recorder, crash and unclean-exit handling ([04](04-storage-crash-diagnostics-privacy.md)) accepted
- [x] D7 retention and D10 IP policy: recommended values adopted, 2026-11-23 (privacy/legal may revise before release)
- [ ] Security fixes P1-10..12 prioritised first

**Process**
- [ ] Migration table ([06](06-migration.md)) reviewed by each component owner
- [ ] Rules and CI gates ([07](07-rules-and-enforcement.md)) accepted
- [ ] Implementation plan ([08](08-implementation-plan.md)) accepted
- [ ] Observability owner named

| Role | Name | Date | Signature |
|---|---|---|---|
| Project owner (scope, D14) | | 2026-11-23 | agreed in review |
| Observability owner | | | |
| Apps (Flutter/Dart CLI) owner | | | |
| Agent engine owner | | | |
| dp-sdk owner | | | |
| Presence owner | | | |
| Relay owner | | | |
| TURN / DNS owner | | | |
| Privacy / security | | | |

**V2 gate:** D4, D5, D13 decided; P3 tasks approved. This happens separately, after V1 ships.
