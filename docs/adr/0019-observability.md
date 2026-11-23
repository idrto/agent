# ADR-0019: Unified logging, tracing and diagnostics

## Context
IDR has no correlation IDs, no crash handling, three incompatible Rust subscriber setups, no persistent GUI log and plain-text server logs. The full audit and design are in [docs/observability](../observability/README.md).

## Decision
- **One spec, one record format.**
  - The format is `idr.log/1` JSON Lines, with W3C/OTel-compatible `trace_id`/`span_id` and UUID correlation IDs.
  - It is defined once in `spec/telemetry/`: JSON Schema, event and attribute registries, conformance vectors.
- **Shared code lives in this monorepo (D1):**
  - `crates/idr-telemetry` (Rust)
  - `packages/idr_telemetry`, `packages/idr_telemetry_flutter`, `packages/idr_diag` (Dart)
  - **Consumers:** `applications/apps` uses a `path:` dependency; Presence and Relay use a tagged git dependency.
- **Release scope:**
  - V1 is local-first: files, recorder, crash capture, local bundles, in-machine context, server JSON.
  - V2 adds wire trace context, uploads and central collection.
- **Upgrade together (D14):** native libraries and agent binaries ship with their app, so the exact `ABI_VERSION` check stays.
- **Libraries never install subscribers.** dp-sdk never logs.

## Alternatives
- A separate `observability` repo, which would add another repo to version and tag.
- Copies per repo, which would diverge the way the `protocol/` copies already have.

## Consequences
- Presence and Relay gain a git dependency on this repo. This moves the ADR-0001 open item forward.
- Rules for all contributors and AI agents: [docs/observability/07-rules-and-enforcement.md](../observability/07-rules-and-enforcement.md).

## Migration impact
- Every logging call site is migrated per [docs/observability/06-migration.md](../observability/06-migration.md).
- Env vars are unified to `IDR_LOG`, `IDR_LOG_FORMAT` and `IDR_LOG_DIR`. `RUST_LOG` is deprecated for one release.

## Unresolved
Owner acceptance per component is collected in each migration PR ([09](../observability/09-decisions-risks-approval.md#approval-checklist)).
