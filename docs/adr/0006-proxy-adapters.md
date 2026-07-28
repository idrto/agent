# ADR-0006: Proxy protocols as Source edge adapters

## Context
Desktop apps may speak HTTP CONNECT / SOCKS; Flutter should use a direct SDK.

## Decision
Proxies are optional adapters over `idr-core` stream open — no WebRTC logic inside proxy parsers. Mobile-first path is direct SDK (Phase 5 for proxies).

## Alternatives
- Proxy-only Source
- Always-on loopback proxy in mobile apps

## Consequences
Smaller mobile binary; desktop feature flags later.

## Migration impact
Deferred to Phase 5.

## Unresolved
SOCKS UDP ASSOCIATE design.
