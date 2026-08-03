# ADR-0012: TLS trust modes (mTLS / LE / Leg 2 QUIC)

## Context
Different account types need different certificate models. Browser/edge traffic to native `*.idr.to` also needs a clear Leg 2 (Relay↔Target) encryption story that does not nest TLS into Target nginx.

## Decision
- Personal/enterprise: mTLS with entity CA-Root issued endpoint certs (Source↔Target / app path as applicable).
- Service providers: custom domain + Let’s Encrypt on Target; Relay **opaque TLS passthrough** to nginx `:443`.
- Native `*.idr.to` (browser/edge, Relay wildcard configured):
  - **Leg 1:** Client TLS terminated at Relay with the platform wildcard cert.
  - **Leg 2:** Cleartext HTTP over Target↔Relay **QUIC TLS** (Relay server identity, ALPN `idr-relay-v1`) plus connection-token auth.
  - Target bridges `HttpPassthrough` to local nginx **`:80`**.
  - **No nested TLS** into nginx; **no** Target machine / shared self-signed cert on that hop.
- Source Agent application data never uses the Relay edge (WebRTC only).

## Alternatives considered
- Single TLS policy for all tenants — rejected (SP needs customer LE; personal/enterprise need entity mTLS).
- Shared self-signed TLS from Relay into Target nginx for Leg 2 — **rejected**; QUIC TLS already protects Leg 2; nested TLS adds complexity without a trust benefit vs a compromised Relay (which already sees plaintext after edge terminate).
- Opaque passthrough for all `*.idr.to` — retained only as **legacy fallback** when wildcard PEMs are unset.

## Consequences
- Relay must hold/serve the `*.idr.to` wildcard (or multi-SAN) cert for edge terminate.
- Target nginx for native post-terminate traffic is HTTP on loopback (`http_upstream`); TLS terminates at Relay for those hosts.
- Custom-domain E2E TLS remains at Target nginx; Source P2P still uses WebRTC DTLS (+ optional app TLS to Target terminator).
- Docs that mentioned “Leg 2 shared self-signed” are superseded by this ADR.

## Migration impact
Align security-model, threat-model, README, and donor TLS docs with this decision. No wire-protocol change: `HttpPassthrough` / `TlsPassthrough` already encode the split.

## Unresolved
Exact Presence distribution of entity CA roots to Sources (mTLS path, unrelated to Leg 2).
