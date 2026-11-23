# 07: Rules for Developers and AI Agents

These rules are **mandatory** for every human and AI agent changing IDR code once the design is approved. When a request conflicts with these rules, follow the rules and ask. **A deviation needs an approved ADR** (§5).

AI agents must read this file and [03](03-log-schema-and-events.md) before adding or changing any log, span or ID. Each repository's `CLAUDE.md` / `AGENTS.md` will link here (task P1-00).

## 1. Rules

### Libraries and init

- **R-LIB-1.** Log only through `idr_telemetry` (Dart) or `tracing` + `idr-telemetry` (Rust). The following are forbidden in non-binary code:
  - Dart: `print`, `debugPrint`, `stderr.writeln` used for diagnostics, `developer.log`, `package:logging`, `package:logger`
  - Rust: `println!`, `eprintln!`, `dbg!`, the `log` crate
- **R-LIB-2.** Exactly one `init` per process, at the composition point: app `main`, CLI `main`, agent `main`, server `main`, or the FFI `idr_telemetry_init`. Libraries never install subscribers or sinks.
- **R-LIB-3.** User-facing terminal output (the CLI `Ui`, `--json` results, streamed chat) is not logging and must not be used for diagnostics. Diagnostics must not be printed as product output.
- **R-LIB-4.** No new logging, tracing, telemetry or crash-reporting dependency (for example Sentry, OpenTelemetry SDK, `logger`) without an ADR.

### Events and fields

- **R-LOG-1.** Every event and span name is registered in `spec/telemetry/events.yaml` **in the same PR** that introduces it. Names follow [03 §3](03-log-schema-and-events.md).
- **R-LOG-2.** Every attribute is registered in `attributes.yaml` with a type and a privacy class. Use the `fields::` / `Attr.` constants; never use string literals for well-known keys.
- **R-LOG-3.** `msg` is for humans only. Values belong in `attrs`. Never interpolate IDs or values into `msg`, and never into event names.
- **R-LOG-4.** Levels follow [03 §2](03-log-schema-and-events.md):
  - Expected user errors are INFO with an outcome.
  - ERROR means a developer may need to act.
  - There is no INFO per frame, message, packet, chunk or candidate.
  - DEBUG is bounded per operation (it is live in the recorder); per-frame, per-message and per-chunk detail is TRACE.
- **R-LOG-5.** **Log a failure once, at the boundary that decides the outcome.** Lower layers return typed errors with context and do not log and rethrow. Every WARN or ERROR carries `error.type`.
- **R-LOG-6.** Long operations emit start, state-change and end events. A silent wait longer than 30 s needs a watchdog event (`*.stalled` / `*.timed_out`).
- **R-LOG-7.** Never remove or rename a registered event without the deprecation process (§4). Dashboards and alerts depend on these names.
- **R-LOG-8.** Spans that can stay open for long are registered with `persist_start: true` ([03 §3.2](03-log-schema-and-events.md)).

### Release scope

- **R-SCOPE-1.** V1 work implements only V1 items ([09 §0](09-decisions-risks-approval.md)). The following are V2 and must not be built during V1, not even behind a flag:
  - the wire `telemetry` field
  - the upload client or display codes
  - collector configs

  Pulling a V2 item forward needs approval.

### Context and IDs

- **R-CTX-1.** Correlation context lives in Dart Zones (`span`, `withIds`) or Rust spans. **Never store "the current" trace or session ID in a global, a static, or a singleton field.**
- **R-CTX-2.** Every user intent and every inbound request starts a span. Every async boundary that leaves the context **must** pass the context through the carrier defined in [01 §4](01-architecture.md):
  - a new isolate, an FFI call or an IPC call: the full `ctx_json`
  - a spawned process: `TRACEPARENT` + env
  - the signaling wire: `telemetry`, V2 only

  `traceparent` alone never carries `session_id` or `operation_id`.
- **R-ID-1.** Use only the IDs in [02](02-identifiers.md), with their exact names and semantics. A new ID kind, or a new use of `operation_id`, needs approval.
- **R-ID-2.** Generate IDs only through `new_id()` / the span layer. The forbidden list:
  - Prefixes, custom formats, re-encoding (hex for UUIDs).
  - Using a wire ID under a different semantic key. For example, the wire `session_id` is always logged as `connection_id`.
- **R-ID-3.** Received context (`traceparent`, `telemetry`) is untrusted. Validate it, use it only for parenting and links, and never for authorization.

### Privacy and security

- **R-PRIV-1.** Never log `secret`-class data (see [04 §5](04-storage-crash-diagnostics-privacy.md)). Hold such values in `Secret<T>`:
  - It serializes transparently for the wire.
  - It redacts in `Debug` and `Display`.
  - It is never a log field.
  - It is read only via `expose()`.

  Secret-bearing structs must not `derive(Debug)`; write a redacting `Debug`.
- **R-PRIV-7.** Never bypass the library's redaction stage, for example by writing directly to a file or to stdout. Every string that reaches the ring, a file or a crash record has been redacted, whatever its registered class.
- **R-PRIV-2.** Never log `personal`-class data in clear: email, names, hostnames, file names, user paths, URL queries. Use `hash_pii`, `~`-relative paths, or omit the value.
- **R-PRIV-3.** Clients never log IP addresses at INFO or above. Servers log truncated addresses at INFO.
- **R-PRIV-4.** dp-sdk crates do not log and do not depend on `tracing`. Callers log outcomes (`crypto.*` events) without material.
- **R-PRIV-5.** HTTP errors never carry raw response bodies into `error.message`.
- **R-PRIV-6.** Nothing leaves the device without explicit, per-bundle user consent.
- **R-PRIV-8.** An email report (D15) opens the mail program with a fixed recipient and a body of the user's redacted description plus the fixed version/OS block only. It carries no logs and no identifiers. The app never attaches, sends or uploads; the user attaches the ZIP. A failed launch shows the copy-and-folder fallback.

### Reliability and performance

- **R-PERF-1.** Logging must never block or throw into the caller. Use the library's async sinks only; no synchronous file I/O, except for crash records.
- **R-PERF-2.** DEBUG attribute construction must be lazy (Dart closures; Rust `tracing`'s callsite filtering).
- **R-PERF-3.** Every `extern "C"` export goes through `ffi_guard`. No panic may cross the FFI boundary.

## 2. Testing requirements

| Test | Where | What |
|---|---|---|
| Conformance | `idr-telemetry`, `idr_telemetry` | Shared vectors: IDs, `traceparent`, redaction, record serialization (golden JSON) |
| Context propagation | both libraries | Concurrent operations do not mix IDs (Dart: 100 parallel `span()`s across `await`s; Rust: tokio tasks); isolate and FFI hand-off preserves the trace |
| Wire compatibility | `idr-protocol`, Presence and Relay protocol copies | V1: the serde rename and `Secret<String>` produce identical bytes and signatures. V2: signature verification with and without `telemetry` on all four messages; an old-verifier × new-signer simulation (R2 in [09](09-decisions-risks-approval.md)); Presence copies request `telemetry` into the offer. |
| Storage ownership | both libraries | Two processes in one service directory: retention never deletes the other's highest segment, **including after the owner has been idle for longer than any time threshold**; lower segments of a long-running writer are deleted once over the cap; a killed writer's run becomes ended; a lock error or missing lock file deletes nothing and emits `diag.sink.degraded` |
| Exit recovery | both libraries | A live process with 5 rotated segments is never reported as unclean; a killed process (no `app.stopping`) is reported once even when two processes start at the same moment; a clean exit is never reported; a crash record gives `crash_record=true` |
| Recorder drain | both libraries | With the queue full and a 3 MiB ring:<br>• an ERROR flush writes the whole in-scope selection (none dropped)<br>• **the triggering ERROR is in the file even when the queue dropped it, and even when a DEBUG burst evicted it from the ring**<br>• INFO+ records that the queue *did* write are not duplicated<br>• records with `seq` above the watermark are not written twice<br>• **records created between a trigger and its split (e.g. trigger A at watermark 100, records 101–150 before the split) stay in the live ring and are selected by a later drain (trigger B), not lost when A's snapshot is freed**<br>• a trigger arriving mid-drain produces a **follow-up drain** that captures its DEBUG prologue from the new ring<br>• many triggers mid-drain produce exactly one follow-up<br>• a bundle requested mid-drain completes only after the follow-up's write and sync<br>• peak memory ≤ 7 MiB; queue drops are counted |
| Redaction coverage | both libraries | Secrets planted in `msg`, the stack, a nested cause, `stderr_tail`, `panic.message` and a `public` string attribute never appear in the ring, the file or a crash record |
| Memory caps | both libraries | A flood of 8 KiB records keeps the queue at 1 MiB or less and the ring at 3 MiB or less; oversized records are trimmed or replaced; drops are counted |
| ABI | `idr-c-api` + `idr_core_ffi` | A mismatched ABI version fails fast with `IncompatibleVersion` (not a crash); the matching pair passes the FFI context test |
| Event emission | each component | Fakes (`RecordingSink` shipped with the library) assert that the required events and attributes from [03 §4](03-log-schema-and-events.md) are emitted for each failure class |
| Schema validation | e2e (`.e2e/`, `docs/e2e-multi-user-cli.md` flows) | Every JSONL line produced by every process validates against `log-record.schema.json`; every `event` is registered; no `personal`/`secret` patterns (redaction scanner) |
| Volume | e2e | One connect produces 25 INFO records or fewer per side; an idle agent writes 1 INFO/min or less |
| Crash | Dart + Rust | Injected panic in an FFI export → crash record + `IDR_ERR_PANIC`, and the host survives; uncaught Dart error → crash record; next start detects it |
| Performance | benches | Budgets in [04 §6](04-storage-crash-diagnostics-privacy.md); the transfer bench overhead stays under 1 % |
| Scenario replay | V1: local e2e; V2: staging nightly (P3-09) | Each scenario in [05](05-investigation-scenarios.md) is induced (fault injection: block UDP, fill the disk, expire the JWT, kill the agent) and the diagnosis is reproduced from the logs alone |

## 3. CI enforcement

| Gate | Mechanism |
|---|---|
| Banned APIs (Dart) | `analysis_options.yaml`: enable `avoid_print`; custom `custom_lint` rule (in `idr_telemetry_lints`) banning `developer.log`, `debugPrint`, and `stderr.writeln` outside `bin/` / `Ui` |
| Banned APIs (Rust) | `clippy.toml` `disallowed-macros = ["std::println", "std::eprintln", "std::dbg"]` for library crates; `disallowed-methods` for `tracing_subscriber::fmt::init` outside `idr-telemetry`; `#![deny(clippy::print_stdout, clippy::print_stderr)]` in lib crates |
| No subscriber in libraries | `cargo deny` / a `cargo tree` check: only binaries and `idr-telemetry` depend on `tracing-subscriber` |
| dp-sdk purity | CI fails if a dp-sdk crate depends on `tracing`, `log` or `idr-telemetry` |
| Event registry | `idr_diag lint-events <repo>` scans for event and span names in calls (Dart `log.*('…')`, `span('…')`; Rust `event = "…"` / span names) and fails on unregistered names or attributes |
| `derive(Debug)` on secrets | A lint script flags `derive(Debug)` on structs with fields named `*key*`, `*token*`, `*secret*`, `*password*`, `*credential*`, `private_*`, unless allow-listed with a redacting `Debug` |
| Schema validation and volume | e2e job collects all JSONL and runs `idr_diag validate` |
| Pinned versions | Consumers pin `idr-telemetry` by tag; Renovate/Dependabot proposes bumps; a major bump requires the ADR link in the PR |

### 3.1 Implementation (P1-07)

- **Entry point:** `scripts/check-telemetry.sh`, run by the `telemetry` job in `.github/workflows/ci.yml`.
- **Scope:** `spec/telemetry/lint.yaml`. A package is added to `event_names` and `banned_apis` in the PR that migrates it.
- **Commands** (`packages/idr_diag`):
  - `idr_diag lint` covers events, banned, secrets and deps.
  - `idr_diag validate` checks the schema, the registries, and that `redact()` leaves every string unchanged.
- **Existing offenders:** `derive(Debug)` on secret holders found in the audit is allow-listed in `lint.yaml` with the task that removes it (P1-10). Any **new** offender fails CI.
- **Lint escape hatch:** `// idr-lint: allow (<reason>)` on the line. The reason is mandatory and is checked in review.
- **Gate tests:** `packages/idr_diag/test/idr_diag_test.dart` seeds one violation per gate and proves that each one fails.

## 4. Versioning

| Artifact | Version | Compatible change (minor) | Breaking change (major) |
|---|---|---|---|
| Record schema | `idr.log/N` in each record | New optional fields | Renaming, removing, or changing the type of a field |
| Event registry | `events.yaml` `version:` | Adding events or attributes | Renaming or removing (only after deprecation: mark `deprecated_since`, emit both for one minor release, then remove) |
| Libraries | semver tags `telemetry-vX.Y.Z` | API additions | API removal; behaviour change of IDs or sinks |
| Wire `telemetry` object | covered by the protocol `version` | Optional sub-fields | Changing semantics |

Readers (`idr_diag`, the Alloy pipeline, dashboards) must accept `idr.log/1` and the next version during a migration window of at least one release.

## 5. Approval for architectural changes

- **Requires an ADR, approved by the observability owner plus one owner of each affected repository:**
  - schema or ID changes
  - a new ID kind or domain
  - new carriers or wire fields
  - new dependencies
  - a privacy-class change
  - retention changes
  - any deviation from these rules
- **ADR location:** `agents_engine/agent/docs/adr/NNNN-title.md`, using the existing ADR format.
- **PR checklist** (template in each repo):
  - [ ] New events and attributes registered
  - [ ] No banned APIs
  - [ ] Failures logged once with `error.type`
  - [ ] Context propagated across new async or process boundaries
  - [ ] No secret or personal data
  - [ ] Volume is acceptable
  - [ ] ADR linked if architectural
- **AI agents** must stop and ask before:
  - adding an event domain, ID or dependency
  - changing a level policy
  - logging any new kind of data that is not in `attributes.yaml`

  They must not "temporarily" add `print`/`println!` diagnostics to committed code.
