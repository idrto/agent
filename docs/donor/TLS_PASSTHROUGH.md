# End-to-end TLS via Target nginx (custom domains) and optional Relay terminate (`*.idr.to`)

## Architecture

| Client Host | Relay behaviour | Target |
|-------------|-----------------|--------|
| `*.idr.to` (wildcard cert configured) | Terminate TLS; Leg 2 = HTTP over encrypted QUIC | nginx `:80` |
| `*.idr.to` (no wildcard cert) | Opaque TLS passthrough (legacy) | nginx `:443` |
| Custom domain (CNAME → FQHN) | Presence alias check → opaque TLS passthrough | nginx `:443` (LE on custom name) |

```
# Custom domain E2E
Browser ──TLS(SNI: app.example.com)──► HAProxy :443 ──TCP──► Relay :8443
                                                              │ peek SNI → Presence resolve
                                                              ▼
                                                        QUIC TlsPassthrough → Target nginx :443

# Native FQHN with edge terminate
Browser ──TLS(SNI: host.idr.to)──► Relay terminate (wildcard) ──HTTP/QUIC──► Target nginx :80
```

Port 80 HTTP (including ACME) remains cleartext passthrough by design.

Separate path (unchanged): `target-quic` ↔ Relay QUIC uses **Relay's certificate** and ALPN `idr-relay-v1`.

## Security properties

| Path | Relay can see? |
|------|----------------|
| Custom-domain HTTPS (passthrough) | **No** — ciphertext only; SNI for routing |
| Native HTTPS with edge terminate | **Yes** — plaintext after terminate; Leg 2 protected by QUIC TLS |
| Client HTTP :80 / ACME | **Yes** — cleartext HTTP (required for http-01) |
| Target↔Relay control/data QUIC | Encrypted with Relay identity |
| Target FQHN / custom-domain private key | Never leaves Target (`cert_dir`) |

## Design fixes applied

These flaws existed in the initial passthrough prototype and are fixed:

1. **Half-close truncation** — `tokio::select!` on bidirectional copy aborted the peer direction when one side finished. Replaced with `tokio::join!` + TCP/QUIC write shutdown on EOF so responses are not truncated after client FIN.
2. **Dead Active connections** — tunnel acceptor exited on QUIC close, but the connection table kept `Active` forever and never respawned. A supervisor awaits `connection.closed()`, clears the entry, and decrements Relay readiness so the next Presence ensure reconnects.
3. **ACME account churn** — every attempt called `Account::create` and discarded credentials (rate-limit risk). Credentials are now persisted under `cert_dir/acme-account-{staging|prod}.json`.
4. **Blind re-issue** — `renew_before_days` was unused; certs were re-ordered daily. Expiry is parsed from `fullchain.pem`; renew only inside the configured window.
5. **ACME before Relay** — HTTP-01 was started at boot before QUIC existed. ACME now waits on `RelayReadiness` (Active QUIC) before `set_challenge_ready`.
6. **Stream accounting** — Target `open_streams` and Relay `active_streams` were never decremented for tunnels, breaking idle reaping. Both sides now increment/decrement around each session (Relay uses a `Drop` guard).
7. **Frame OOM** — `TunnelOpen` length was allocated before `MAX_FRAME_BYTES` check. Length is capped first.
8. **FQHN mismatch** — Target ignored `TunnelOpen.target_fqhn`. It now rejects streams whose claimed FQHN ≠ configured identity.
9. **Non-atomic cert install** — cert then key write could leave a mismatched pair. Install uses temp files + rename; Unix privkey mode `0600`; nginx reload failure is hard-error.
10. **Edge DoS / wake amplification** — unauthenticated SNI/Host could force Presence wake for any FQHN. Relay edge now defaults `allowed_fqhn_suffix = ".idr.to"`, caps concurrent sessions, and applies peek/session timeouts.

## Relay edge

| Listener | Purpose |
|----------|---------|
| `:80` | HTTP passthrough (ACME http-01, cleartext) |
| `:8443` | TLS passthrough (peek SNI only, forward raw records) |

Config knobs (`[edge]`):

- `allowed_fqhn_suffix` — reject Host/SNI outside suffix (empty = allow all)
- `max_concurrent_sessions` — accept semaphore
- `peek_timeout_ms` / `session_timeout_seconds`

Production: put **HAProxy** in front (see [relay docs](../../relay/docs/TLS_PASSTHROUGH.md) or `docs/HAPROXY.md` in the relay repo).

## Target nginx

1. Listen `:443` with certs from `[acme].cert_dir/<custom-domain>/`.
2. Listen `:80` and serve `[acme].webroot` for `/.well-known/acme-challenge/`.
3. `proxy_pass` to your apps.
4. Native `*.idr.to` HTTPS is terminated at Relay (wildcard); Target receives HTTP over QUIC on `http_upstream`.

### Bootstrap (no certs yet)

nginx may refuse to start if `ssl_certificate` files are missing. Recommended order:

1. Deploy HTTP-only server block (port 80 + ACME location) for the custom domain.
2. Start `target-quic` with `[acme] enabled = true`, `domains = ["…"]`, `staging = true`.
3. Ensure Presence → QUIC to Relay is up (ACME waits for this).
4. After `cert_dir/<domain>/fullchain.pem` / `privkey.pem` appear, enable the `:443` server and reload nginx.

See `acme::nginx_example_config()` for a starter config.

## Let's Encrypt HTTP-01 (custom domains only)

Native `*.idr.to` FQHNs are **not** issued by Target ACME — the Relay wildcard covers them.

1. Configure `[acme].domains = ["cam.example.com"]` (and Presence `domain_aliases`).
2. Target waits until ≥1 Relay QUIC is Active.
3. Writes `{webroot}/.well-known/acme-challenge/{token}`.
4. Let's Encrypt HTTP GET hits Relay on port 80 with `Host: cam.example.com`.
5. Relay resolves alias → Target → nginx webroot.
6. Certificate installed under `cert_dir/<domain>/`; nginx reloaded.
7. Subsequent loops sleep until `notAfter - renew_before_days`.

**Requirements**

- Custom domain CNAME → Target FQHN; Billing alias pushed to Presence.
- Target registered and reachable over QUIC before validation.
- Use `staging = true` until the path works; production rejects placeholder emails.
- Do not put `*.idr.to` names in `[acme].domains` — startup will fail.

## Tunnel wire format

```
u32 BE length | postcard(TunnelOpen) | raw application bytes…
```

`TunnelOpen { protocol_version, kind, target_fqhn }`

`TunnelStreamKind` postcard indexes: `TlsPassthrough = 0`, `HttpPassthrough = 1`.

Relay opens the bi-stream; Target accepts and bridges to nginx. Target-initiated streams remain control/signaling only.

## Failure modes

| Symptom | Likely cause |
|---------|----------------|
| ACME `authorization invalid` | Missing CNAME/alias, no QUIC/tunnel, nginx not serving webroot, or wrong Host |
| ACME rejects `*.idr.to` domain | Expected — LE only for custom domains |
| ACME waits then fails “no active Relay” | Presence/QUIC not established within 120s |
| HTTPS works then dies after Relay restart | Fixed by connection supervisor — upgrade if still seen |
| HTTPS drops when Target switches WiFi/cellular | Target rebinds Relay QUIC + path probe; Relay accepts migration (`ServerConfig::migration`). Enable nginx `ssl_session_tickets` for fast retry if migration loses race |
| Truncated HTTPS responses | Fixed by half-close pipe — upgrade if still seen |
| Rate-limit from Let's Encrypt | Ensure account file persists; disable prod until staging works |
| Idle Target never disconnects on Relay | Fixed stream accounting — upgrade if still seen |

## Configuration

```toml
[nginx]
tunnel_enabled = true
tls_upstream = "127.0.0.1:443"
http_upstream = "127.0.0.1:80"

[acme]
enabled = false          # opt-in
email = "ops@example.com"
webroot = "/var/www/acme"
cert_dir = "/etc/idr/certs"
staging = true
renew_before_days = 30
nginx_reload_command = "nginx -s reload"
domains = ["cam.example.com"]   # custom domains only — never *.idr.to
```
