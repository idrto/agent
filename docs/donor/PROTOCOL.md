# IDR Protocol v1

## Discovery (`idr-presence.json`)

Signed JSON document at `https://public.idr.to/.well-known/idr-presence.json`. Targets and Relays verify:

1. HTTPS certificate
2. Detached canonical JSON signature (Ed25519)
3. `valid_until` not expired

## Signaling (WebSocket JSON / QUIC JSON)

Transport: **QUIC primary** (ALPN `idr-presence-v1`, length-prefixed JSON) with **WebSocket fallback**.

`ensure_relay_connection` includes `command_id`, `session_id`, `connection_token`, relay descriptor (`relay_id` + endpoints + `server_name` + ALPN), and relay signature.

Dedup key: **`command_id`** (not Presence server source).

## WebRTC signaling (JSON)

Target registration may include a signed `webrtc` block (`agent_region`, `relay_mode`, optional BYOR STUN/TURN).

Additional message types: `turn_probe_candidates`, `turn_probe_report`, `webrtc_session_offer`, `webrtc_answer`, `webrtc_ice_candidate`, `webrtc_session_request`, etc. See `docs/WEBRTC.md`.

SDP-bearing messages may use up to **256 KiB** (`MAX_WEBRTC_SIGNALING_BYTES`).

## QUIC control (binary postcard)

Length-prefixed frames: `[u32 BE len][postcard payload]`

Messages: `ClientHello`, `ServerHello`, `StreamOpen`, `GracefulDrain`

ALPN: `idr-relay-v1`

## Tunnel (opaque edge passthrough)

Relay opens a bi-stream and sends:

```
[u32 BE len][postcard TunnelOpen][raw application bytes…]
```

```text
TunnelOpen { protocol_version, kind, target_fqhn }
TunnelStreamKind: TlsPassthrough = 0, HttpPassthrough = 1  (postcard enum index)
```

After `TunnelOpen`, remaining stream bytes are opaque (client TLS records or HTTP). Target bridges to local nginx. Target must reject `target_fqhn` ≠ its identity.

## Compatibility

Duplicate `src/protocol/` in all three repositories. Run compatibility checks before release:

```bash
diff -ru target-quic/src/protocol relay/src/protocol
diff -ru target-quic/src/protocol presence/src/protocol
```

Both must match byte-for-byte for v1.
