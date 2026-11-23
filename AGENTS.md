# Agent and contributor instructions

## Logging, tracing and diagnostics (mandatory)

Before you add or change any log, span, ID, crash handler or diagnostic output in this repository, read and follow:

- Rules: `docs/observability/07-rules-and-enforcement.md`
- Schema, levels and event names: `docs/observability/03-log-schema-and-events.md`
- IDs: `docs/observability/02-identifiers.md`

(The paths point into `agents_engine/agent/docs/observability/`.)

Short form:
- Log only through `idr-telemetry` (Rust) or `idr_telemetry` (Dart). No `print`, `println!`, `developer.log` or ad-hoc subscribers in library code.
- Register every event and attribute in `spec/telemetry/` in the same PR.
- Never log secrets or personal data.
- A new ID, domain, carrier, wire field or logging dependency needs an approved ADR. Stop and ask.
