# idr.to agent monorepo

Source Agent + Target Agent. **This is the sole agent monorepo** (Phase 6 cutover, 2026-07-28). The donor [`target-quic`](https://github.com/idrto/target-quic) repo is deprecated/archived.

## Locked rules

- **Source ↔ Target:** WebRTC only (Presence signaling; P2P/TURN data). No Source application traffic via Relay edge.
- **Relay:** Target / browser edge path only.
- **TLS:** personal/enterprise → mTLS (entity CA-Root); service providers → custom domain + Let’s Encrypt; `*.idr.to` Leg 2 may use shared self-signed.
- **Mobile Source:** direct streams via C ABI / Dart — **no localhost proxy** in the default SDK.

## Workspace layout

```text
agent/
├── crates/
│   ├── idr-protocol/     # canonical wire types (Presence/Relay sync here)
│   ├── idr-core/
│   ├── idr-webrtc/
│   ├── idr-signaling/
│   ├── idr-source/       # minimal mobile-first Source (WebRTC only)
│   ├── idr-c-api/        # stable C ABI (opaque handles + batched events)
│   └── idr-target/
├── packages/
│   ├── idr_core_ffi/
│   ├── idr_client/
│   └── idr_http/
├── services/
│   ├── target-agent/
│   └── mock-presence/
├── config/
├── docs/
└── protocol/
```

## Quick start

```bash
cp config/target.example.toml config/target.local.toml
IDR_CONFIG=config/target.local.toml cargo run -p target-agent

# WebRTC answerer (needs native libdatachannel + cmake)
cargo run -p target-agent --features webrtc
```

## Develop

```bash
cargo test --workspace --all-targets
cargo build --workspace --release
bash scripts/check-source-no-relay.sh

# Dart (after building libidr_c_api)
cargo build -p idr-c-api --release
dart pub get --directory packages/idr_client
```

Windows ARM64: if `aws-lc-sys` needs Clang, see [`.cargo/config.windows-arm64.toml.example`](.cargo/config.windows-arm64.toml.example).

## Docs

- [docs/migration-plan.md](docs/migration-plan.md)
- [docs/architecture-gap-analysis.md](docs/architecture-gap-analysis.md)
- [docs/security-model.md](docs/security-model.md)
- [docs/threat-model.md](docs/threat-model.md)
- [docs/baselines.md](docs/baselines.md)
- ADRs under [docs/adr/](docs/adr/)
- Donor Target docs under [docs/donor/](docs/donor/)

## Sibling repos

- [`presence`](https://github.com/idrto/presence) — control plane
- [`relay`](https://github.com/idrto/relay) — edge + Target QUIC hub
- [`target-quic`](https://github.com/idrto/target-quic) — **deprecated / archived** (historical donor)

## License

MIT OR Apache-2.0
