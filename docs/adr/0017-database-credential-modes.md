# ADR-0017: Database services and credential modes

## Status

Accepted (Phase 1)

## Context

Target already exposes application-agnostic `[[services]]` (ADR-0016) over WebRTC.
Databases (Postgres, MySQL, Redis, …) fit the TCP gateway. Source must know
**who authenticates** and whether **upstream TLS** is required so Source-supplied
passwords stay opaque to the Target agent.

## Decision

1. Each `[[services]]` entry may set:
   - `credential_mode = "source" | "target"` (default `source`)
   - `require_upstream_tls = true | false` (optional; when omitted, Target derives a default for common DB names/ports in `source` mode)
2. Mux catalog:
   - Keep `ServicesCatalog { services: Vec<String> }` for legacy Sources
   - Append `ServicesCatalogDetailed { entries }` with `name`, `kind`, `credential_mode`, `require_upstream_tls`
3. **Source mode:** Target is an opaque TCP byte bridge. Source speaks the DB wire protocol (via `idr_postgres` localhost tunnel + `package:postgres`). With `require_upstream_tls`, TLS runs Source↔DB inside the mux; Target does not parse credentials unless it actively MITMs the dial.
4. **Target mode:** Target holds secrets (`inject_headers` for HTTP) or uses loopback trust for TCP DBs. Source does not send a DB password.
5. No new `idr-plugin-database` crate.

## Consequences

- Phase 1 confidentiality = WebRTC DTLS + optional upstream TLS passthrough — **not** TEE.
- A malicious Target can still retarget the dial (MITM). That is closed in ADR-0018.
- Source chat UI prompts for DB credentials only when `credential_mode = source`; passwords are memory-only and never written to Target TOML or Presence.

## Local e2e checklist

1. Target TOML:

```toml
[[services]]
name = "postgres"
type = "tcp"
host = "127.0.0.1"
port = 5432
enabled = true
credential_mode = "source"
require_upstream_tls = true
```

2. Postgres listening with SSL enabled (or use `require_upstream_tls = false` for a plaintext lab).
3. Presence + Target agent (`--features webrtc`) + Source with rebuilt `idr_c_api` (ABI 2).
4. Source connects → catalog shows `postgres` / `source` / TLS → enter Source credentials → `SELECT 1`.
5. Negative: with TLS required, a plaintext-only Postgres session must fail closed.
