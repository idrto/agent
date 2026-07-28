# Security model

**Date:** 2026-07-28  
**Status:** Phase 0 stub — refine as Source and mTLS land  
**Related:** [threat-model.md](./threat-model.md), donor `target-quic/SECURITY.md`, `docs/TLS_PASSTHROUGH.md`

---

## Planes of trust

| Plane | Trust anchors | Notes |
|-------|---------------|-------|
| Presence discovery | HTTPS + pinned Ed25519 discovery key | `idr-presence.json` |
| Target registration | Target Ed25519 identity + billing entitlement | Persistent Presence session |
| Relay wake (edge path) | Relay signature + short-lived connection token | Target dials Relay |
| Relay data QUIC | TLS to Relay identity / configured Leg 2 policy | **Not used by Source Agent** |
| WebRTC signaling | Presence-signed offers; Target-signed answers | SDP/ICE size capped |
| WebRTC data | DTLS/SCTP via libdatachannel | P2P preferred; TURN is ICE relay only |
| Billing | Presence ↔ Auth+Billing mux | Entitlements gate sessions |

---

## TLS and certificate policy (authoritative)

### 1. Source Agent ↔ Target Agent (P2P)

- Application TLS (HTTPS to a Target service), when used, is **end-to-end** between the original client/app and the **Target-side** terminator (nginx, app, or connector).
- The Source Agent **must not** hold the Target service private key and **must not** intercept/terminate that application TLS.
- Transport confidentiality between agents is provided by **WebRTC (DTLS)**.
- After the DataChannel opens, perform an IDR-level authenticated handshake bound to Presence session identity (and, when available, DTLS fingerprints).

### 2. Personal and enterprise accounts — mTLS

- Each endpoint presents a certificate **signed by that entity’s CA-Root**.
- Presence already reserves target CA root distribution; agents must validate peer certs against the appropriate entity roots (implementation Phase 3+ / `idr-auth`).
- Possession of a Presence signaling channel alone is **not** sufficient authorization for Target services.

### 3. Service providers — custom domains

- Target obtains **Let’s Encrypt** certificates for customer hostnames (existing ACME path).
- Browser/edge path: Relay **opaque TLS passthrough** (Relay does not hold the customer private key).
- Source SDK path still prefers WebRTC P2P; Relay edge remains for ordinary browsers.

### 4. Native `*.idr.to` via Relay (non-Source clients)

- Relay edge may terminate or route per Relay configuration.
- **Leg 2 (Relay ↔ Target)** may use a **shared self-signed** certificate for that hop when traffic is not from the Source Agent WebRTC path.

### 5. Explicit non-goals

- Source Agent application traffic through Relay HTTP/TLS edge.
- Transparent TLS interception / MITM on the Source Agent.
- Unrestricted Target egress as default (named allowlisted services).

---

## Identities

Treat as distinct:

- Source device identity
- Local user / application principal
- Target device identity (FQHN + Ed25519 / mTLS cert)
- Target **service** identity (named connector)
- Billing parties (`using_party`, `paying_party`)

Session authorization should bind Source, Target, allowed services, expiry, nonce, signaling session id, protocol versions, and transport fingerprints where applicable.

---

## Secrets handling

Never log or commit:

- Private keys, CA keys
- Connection tokens, TURN credentials
- Authorization tokens, proxy passwords
- Raw TLS application payloads

Prefer OS credential stores (Keychain / Credential Manager / Keystore) when Source credentials are persisted.

---

## Local attack surface (future Source)

- Loopback HTTP/SOCKS proxies: bind loopback, ephemeral ports, ephemeral credentials; document OS multi-user limits.
- Admin IPC: named pipes with ACLs or Unix sockets with filesystem permissions — **not** unauthenticated TCP.

---

## Open implementation items

- [ ] Enforce entity CA-Root mTLS end-to-end for personal/enterprise
- [ ] DC CLIENT_HELLO / SERVER_HELLO with replay protection
- [ ] Validate DTLS fingerprints against signaling
- [ ] Named service ACL evaluation on every OPEN
- [ ] Formalize Leg 2 shared self-signed mode in Relay + Target config
