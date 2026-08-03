# IDR Target-to-Relay Architecture (v1)

## Separation of concerns

| Path | Role |
|------|------|
| HTTPS `public.idr.to/.well-known/idr-presence.json` | Signed Presence server discovery |
| Presence signaling | **QUIC primary** (`idr-presence-v1`) / WSS fallback | Control plane — registration and signaling |
| QUIC (ALPN `idr-relay-v1`) | Target-initiated data path to Relay |
| Edge tunnel streams (Relay→Target) | Opaque client TLS/HTTP → local nginx |
| SQLite | Durable metadata only — never live connection handles |
| ACME HTTP-01 | Target issues/renews **custom-domain** certs only; LE hits Relay :80 (native `*.idr.to` uses Relay wildcard) |

## Target flow

1. Fetch and verify signed discovery document; cache locally.
2. Derive primary/secondary Presence indexes via dual-mod placement (v1):
   `primary = hash%N`, `secondary = hash%(N-1)`, bump secondary if equal; requires `N >= 2`.
   Append-only list growth keeps ≥1 overlapping index across discovery epochs.
3. Register on both Primary and Secondary Presence connections.
4. On `ensure_relay_connection`:
   - Deduplicate by `command_id`
   - `get_or_connect(relay_id)` via open-addressing table + generational arena
   - Single shared QUIC handshake per relay_id
5. Idle timeout closes unused connections; SQLite retains endpoint hints.
6. On Active QUIC: spawn tunnel acceptor + death supervisor; signal `RelayReadiness` for ACME.
7. **Mobility (rare):** on Presence reconnect, re-detect IPv4/IPv6 caps; rebind the Relay QUIC UDP socket and nudge path validation on active connections (RFC 9000 migration). Primary session may warm-reconnect if QUIC died. Enable nginx TLS session tickets for fast browser retry when migration cannot complete in time.
8. Tunnel streams bridge to nginx (`tls_upstream` / `http_upstream`):
   - Native `*.idr.to` after Relay wildcard terminate → `HttpPassthrough` → nginx `:80` (Leg 2 = QUIC TLS only; no nested TLS).
   - Custom domain / opaque passthrough → `TlsPassthrough` → nginx `:443` (app TLS terminates at Target).

See [TLS_PASSTHROUGH.md](TLS_PASSTHROUGH.md).

## Relay flow

1. Listen for Target-initiated QUIC only.
2. Validate TLS + application `ClientHello` token.
3. Register connection keyed by `(Target FQHN, target_identity)`; replace stale epochs only within the same identity (multi-device / DNS multi-A per FQHN).
4. `ensure_target_connection(fqhn)` → RR among live Relay conns, else dual Presence dispatch (hash-pick one device) → await that identity's QUIC.

## Scale target

Relay design target: ~1M almost-idle connections / 4 GB RAM. Requires measurement — see benchmarks and kernel tuning docs.

## Placement notes (v1)

Dual-mod placement is append-safe across discovery epochs (old/new `{primary,secondary}` share ≥1 node), but still remaps under non-append edits (reorder/delete). Secondary load skews away from the last index as `N` grows. Isolated behind `PresencePlacement` for future rendezvous if needed.
