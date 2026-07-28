# ADR-0009: Explicit flow control

## Context
Unbounded queues cause memory blowups under bulk transfer.

## Decision
Mandate bounded queues (`idr_core::BoundedQueue`), and Phase 4 stream/connection windows. APIs must surface backpressure (`IdrErrorKind::Backpressure`).

## Alternatives
- Best-effort buffering
- Only rely on SCTP backpressure

## Consequences
Callers must handle partial writes / backpressure errors.

## Migration impact
Primitives in Phase 2; wire WINDOW_UPDATE in Phase 4.

## Unresolved
Default window sizes after benchmarking.
