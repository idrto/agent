# ADR-0013: Target plugins and named service catalog

## Status

Accepted

## Context

Source opens logical streams by service name (`http`, `ollama`, …). Target had `Connector` / `ConnectorRegistry` but live WebRTC OPEN routed only by `StreamKind` via nginx bridge.

## Decision

1. Mux `StreamOpenMeta.service_name` is the primary routing key on OPEN.
2. Target boots a `ConnectorRegistry` from `[plugins]` config (http/https via nginx bridge; separate crates for ollama and database).
3. Registration advertises `capabilities.named_services` so Source can discover catalog entries.
4. Unknown service names return `OpenError` with `ServiceNotFound`.

## Consequences

- Ollama and database are **separate** crates (`idr-plugin-ollama`, `idr-plugin-database`), not folded into agent SQLite.
- Legacy OPEN without `service_name` maps `HttpPassthrough`→`http` and `TlsPassthrough`→`https` only.
