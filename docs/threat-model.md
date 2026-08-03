# Threat model

**Date:** 2026-07-28  
**Status:** Phase 0 stub  
**Related:** [security-model.md](./security-model.md)

Assumes the dual-path architecture: **Source↔Target WebRTC (Presence signaling)** and **Browser↔Relay↔Target QUIC**.

---

## Assets

- Target private keys / LE certs / entity CA-issued certs
- Source device credentials and local proxy credentials
- Authorization tokens and Presence session state
- Application payload confidentiality and integrity
- Availability of Target services and Presence control plane
- Billing entitlements / party binding

---

## Adversaries and scenarios

| Threat | Attack surface | Mitigations (current → planned) |
|--------|----------------|----------------------------------|
| Malicious local proxy client | Future Source loopback proxy | Loopback bind, ephemeral creds, local auth; document multi-user limits |
| Another local OS user | IPC, proxy port, config files | ACLs / socket permissions; no world-writable keys |
| Malicious Source Agent | WebRTC sessions, OPEN floods | Presence authz, service ACL, flow control, session limits |
| Malicious Target Agent | Lies about services, steals bytes | Client trust model; mTLS/entity identity; user-visible Target identity |
| Malicious / compromised Presence | Forge offers, redirect sessions | Signed messages; still require DC handshake + fingerprint checks; billing gates |
| Compromised Presence discovery | Wrong Presence set | Pin discovery key; HTTPS; `valid_until` |
| Replayed authorization tokens | Session/open | Nonce + expiry + session id binding |
| Unauthorized service access | Mux OPEN | Named allowlist; deny default TcpConnect to private IPs |
| Localhost proxy exposure | Source desktop | Default loopback; warn on non-loopback |
| DNS / identity confusion | FQHN vs alias vs SNI | Canonical FQHN; Presence alias for custom domains; reject mismatch |
| DTLS fingerprint substitution | WebRTC | Bind fingerprints in signed signaling + DC handshake |
| Malformed / oversized frames | Mux / signaling | Size caps (`MAX_FRAME_*`); strict decode; reset |
| Memory / stream / connection flooding | Sessions & OPEN | max_sessions, windows, global memory limits, fair scheduling |
| Credential theft | Disk / logs | No secret logs; secure stores; short-lived tokens |
| Compromised TURN | ICE relay path | Presence-minted creds; treat TURN as capable attacker for metadata; still need DC auth |
| Downgrade attacks | Protocol versions | Explicit version negotiation; reject unknowns safely |
| ABI misuse from Dart | Future FFI | Opaque handles; abi_version/struct_size; batched events |
| Application lifecycle races | Mobile embed | Idempotent shutdown; cancel tasks; no detached work |
| Relay used as Source shortcut | Misconfiguration | **Architecture rule:** Source has no Relay client; review deps |
| Relay sees plaintext after `*.idr.to` terminate | Browser↔Relay edge | Accepted for native FQHNs; Leg 2 still QUIC-encrypted Relay↔Target; not a substitute for Source P2P auth |
| SNI/Host wake amplification (edge) | Relay | Existing Relay caps / suffix gates (relay repo) |

---

## Trust boundaries

```text
[App / browser]
    |  (1) localhost or in-process   (2) public HTTPS
    v
[Source Agent] ----Presence signaling----> [Presence] <---- register/ensure ---- [Target Agent]
    |                                              |                                  ^
    +-------------- WebRTC P2P/TURN data ----------+----------------------------------+
                                                                             |
[Browser] ---- TCP/TLS ----> [Relay edge] ---- QUIC tunnels ------------------+
```

- Crossing Presence does **not** grant data-plane rights by itself.
- Crossing Relay edge is a **separate** path with its own TLS policy; Source Agents must not use it for app data.

---

## Residual risks (accepted for now)

- TURN operators can observe metadata and timing of relayed ICE paths.
- Dual-mod Presence placement remaps on non-append list edits (control-plane availability risk); append-only growth keeps ≥1 overlapping Primary/Secondary node across epochs.
- Anonymous Source auth mode in protocol types is weak — replace with mTLS/device identity for production personal/enterprise.
- Baseline donor tree currently fails to compile on assessor hardware — fix before production claims.

---

## Review triggers

Update this document when adding: Source proxies, C ABI, entity CA validation, mux frame types, or changes to Relay edge terminate / Leg 2 QUIC policy.
