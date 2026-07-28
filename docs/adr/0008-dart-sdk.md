# ADR-0008: Direct Dart SDK plus optional loopback proxy

## Context
Flutter apps should not require localhost proxies for first-party traffic.

## Decision
Primary mobile API is direct streams via C ABI (Phase 5). Optional embedded loopback proxy for third-party libs.

## Alternatives
- Proxy-only embedding

## Consequences
ABI and lifecycle tests become critical.

## Migration impact
Phase 5 packages: `idr_core_ffi`, `idr_client`, optional `idr_http`. Proxies stay out of the default mobile SDK.

## Unresolved
HttpClient compatibility claims; Flutter sample app.
