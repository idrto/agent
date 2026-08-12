# ADR-0016: Generic Target Service Gateway

## Context

App-specific Target plugins (`idr-plugin-ollama`, `idr-plugin-huggingface`, `idr-plugin-database`) required a new crate for every integration. Source already speaks each app’s native HTTP/TCP API over mux.

## Decision

Target exposes only a **generic `[[services]]` gateway**:

- `name` — mux `openStream` name
- `type` — `http` | `tcp`
- `base_url` / `host`+`port`
- optional `inject_headers` from Target env/file (secrets never leave Target)

HTTP services use a loopback reverse proxy (Host rewrite + header inject). TCP services dial upstream as a byte bridge.

Source owns application protocol knowledge (`idr_ollama`, `idr_huggingface`, or raw `idr_service_http`).

After WebRTC (or future relay) connect, Source discovers available `openStream` names via mux `ServicesCatalogRequest` / `ServicesCatalog` — not via Presence.

## Consequences

- No new Target plugin crates for LM Studio, vLLM, Redis, Postgres, etc. — add a `[[services]]` row.
- Hugging Face auth uses generic `Authorization` injection from `HF_TOKEN`, not HF-specific allowlists in the agent.
- Nginx `http`/`https` site connectors remain under `[plugins.http]` for now.
