# WebRTC on the Target Agent

Target-quic can act as a **WebRTC Answerer** for Source-Agents (Browser/Desktop/Mobile SDKs using libdatachannel). Signaling flows through **IDR Presence**; TURN is **private** (Presence-issued); STUN uses SDK defaults (`stun.l.google.com` + `stun.idr.to`).

## Current status

| Layer | Status |
|-------|--------|
| Protocol types + ICE merge | Done (synced across target-quic / presence / relay) |
| Registration + BYOR metadata | Done; `webrtc` advertised only with `--features webrtc` |
| Presence TURN inventory / probe push | Done (QUIC + WSS) |
| Bidirectional Presence signaling | Done |
| libdatachannel PeerConnection | Wired behind `--features webrtc` (event-queue responder) |
| Session manager / idle reaper | Keyed store + ICE inbox + negotiation/idle reaper |
| Postcard mux (`[u32][postcard]`) | Done |
| DataChannel → nginx/TcpConnect bridge | Wired on `DataChannelOpen` / `StreamFrame::Open` |
| Metrics / SQLite history | Schema + metric series registered; not all paths observe yet |

## Modes

| `relay_mode` | Behavior |
|--------------|----------|
| `platform` | Presence issues private TURN + SDK STUN defaults |
| `byor` | Enterprise BYOR STUN/TURN from `[webrtc.byor]` in registration |
| `hybrid` | Platform TURN + optional BYOR servers |

## Configuration

See `config/target.example.toml` section `[webrtc]`.

## Native build (Linux)

```bash
cargo build --features webrtc
./scripts/check-native-linux.sh
```

Without the feature, protocol and registration still compile; capability is **not** advertised.

Native peer callbacks use a bounded `try_send` event queue (no awaits in callbacks). Expected DataChannel label/protocol: `idr-stream-v1` / `idr.stream/1`.

## Protocol

- Signaling: `src/protocol/webrtc_signaling.rs` (SDP up to `MAX_WEBRTC_SIGNALING_BYTES`)
- Mux: `src/protocol/stream_mux.rs` — length-prefixed postcard `StreamFrame`
- Keep `src/protocol/` identical across target-quic, presence, and relay

## Session flow (Target responder)

1. Presence pushes signed `WebRtcSessionOffer`
2. Target verifies, merges ICE, creates libdatachannel PeerConnection (responder)
3. Answer + trickle ICE returned via Presence outbox
4. On `DataChannelOpen`, send `WebRtcSessionAck(Active)`
5. Binary DC messages demuxed as `StreamFrame`; Open bridges to nginx / TcpConnect

## Security notes

- Never log TURN credentials
- Cap SDP / ICE candidate sizes
- Verify Presence-signed offers and probe candidate pushes
- TcpConnect denies private/loopback/ULA when `deny_private_ips = true`
- Reject DataChannels that are not reliable/ordered with the expected label+protocol

## Billing party (Presence registration)

Configure `[billing_party]` with `using_party` (required) and optional `paying_party` as a local/dev hint. Production Targets mint a Presence entitlement JWT (`[auth].url` → `POST …/agent/token`) and send `entitlement_jwt` on `register_target`. See Presence [docs/AUTH.md](https://github.com/idrto/presence/blob/main/docs/AUTH.md).
