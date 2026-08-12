# ADR-0014: api-backed auth — no free agent routes

## Status

Accepted

## Context

Anonymous Source auth, open `/v1/entities*`, optional usage bearer, and Presence `allow_dev` when billing was off created free product paths.

## Decision

1. `@idrto/api` requires better-auth session for entity registry routes.
2. Relay `usage_report` always requires `RELAY_USAGE_BEARER`.
3. SQL entitlement does **not** auto-provision unknown paying parties.
4. Presence billing mux is required (`enabled=true`); disabled/missing mux denies entitlement.
5. Source product path requires `Bearer` or `DeviceToken` + non-empty `auth_token`; Presence rejects `Anonymous`.

Public only: `/health`, `/.well-known/idr-configuration`, login (`/api/auth/*`).

## Consequences

Local/dev stacks must run api + Presence billing mux with real tokens. Unit tests use mock signaling with a dummy bearer token (not Anonymous).
