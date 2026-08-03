# idr.to agent monorepo

Source Agent + Target Agent. **This is the sole agent monorepo** (Phase 6 cutover, 2026-07-28). The donor [`target-quic`](https://github.com/idrto/target-quic) repo is deprecated/archived.

## Locked rules

- **Source ↔ Target:** WebRTC only (Presence signaling; P2P/TURN data). No Source application traffic via Relay edge.
- **Relay:** Target / browser edge path only.
- **TLS:** personal/enterprise → mTLS (entity CA-Root); service providers → custom domain + Let’s Encrypt; `*.idr.to` Leg 2 = QUIC TLS to Relay identity (HTTP to nginx `:80`, no nested TLS).
- **Mobile Source:** direct streams via C ABI / Dart — **no localhost proxy** in the default SDK.
- **PEP (Presence):** agents dial **QUIC first**, **WSS fallback**.
- **Delegate Permissions:** agents use [`dp-sdk`](https://github.com/2keyapp/dp-sdk) (`dp-rust` / `dp-rust-mtls`) for CapabilityCredential + client cert materialization.
- **Secrets:** Dart/Flutter hosts use [`fl-start/flutter_secure_storage`](https://github.com/fl-start/flutter_secure_storage) via `packages/idr_secure_storage`. Headless Rust services inject identity JSON at process start.

## Workspace layout

```text
agent/
├── crates/
│   ├── idr-protocol/     # canonical wire types (Presence/Relay sync here)
│   ├── idr-core/
│   ├── idr-webrtc/
│   ├── idr-signaling/    # discovery + PepClient (QUIC→WSS)
│   ├── idr-dp/           # dp-sdk integration + secret store ports
│   ├── idr-source/       # minimal mobile-first Source (WebRTC only)
│   ├── idr-c-api/        # stable C ABI (opaque handles + batched events)
│   └── idr-target/
├── packages/
│   ├── idr_core_ffi/
│   ├── idr_client/       # embeddable Dart Source API
│   ├── idr_http/
│   ├── idr_secure_storage/  # flutter_secure_storage (fl-start)
│   └── idr_cli/          # Flutter desktop CLI
├── services/
│   ├── target-agent/     # desktop Target service + CLI
│   ├── source-agent/     # desktop Source service + CLI
│   └── mock-presence/
├── config/
├── docs/
└── protocol/
```

## Quick start

### Target Agent (desktop service)

```bash
cp config/target.example.toml config/target.local.toml
cargo run -p target-agent -- --config config/target.local.toml run
cargo run -p target-agent -- doctor
cargo run -p target-agent -- version

# WebRTC answerer (needs native libdatachannel + cmake)
cargo run -p target-agent --features webrtc -- run
```

### Source Agent (desktop service / CLI)

```bash
cp config/source.example.toml config/source.local.toml
# Optional: point [dp].identity_path at a DeviceIdentity JSON file
cargo run -p source-agent -- --config config/source.local.toml doctor
cargo run -p source-agent -- run
cargo run -p source-agent -- connect cam1.acme.idr.to --service https
```

### Embed in a Dart / Flutter app

```dart
import 'package:idr_client/idr_client.dart';
import 'package:idr_secure_storage/idr_secure_storage.dart';

final secrets = DpSecretStore(store: FlutterSecureKvStore());
final bundle = await secrets.loadIdentity();

final runtime = IdrRuntime.create(useMock: false);
if (bundle != null) {
  runtime.setDpIdentityMap(bundle.toNativeJson());
}
final session = await runtime.connect('cam1.acme.idr.to');
```

### Flutter desktop CLI (secrets in secure storage)

```bash
cd packages/idr_cli
flutter pub get
flutter run -d windows --dart-define=... # or: dart run bin/idr_cli.dart doctor
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

## Billing packages

Personal / Enterprise / Service Provider / Data Transfer — see
[docs/IDR_BILLING_PACKAGES.md](docs/IDR_BILLING_PACKAGES.md).

## Sibling repos

- [`presence`](https://github.com/idrto/presence) — control plane / PEP
- [`relay`](https://github.com/idrto/relay) — edge + Target QUIC hub
- [`turn`](https://github.com/idrto/turn) — coturn Docker TURN nodes
- [`dp-sdk`](https://github.com/2keyapp/dp-sdk) — Delegate Permissions SDKs
- [`billing`](https://github.com/2keyapp/billing) — seats + usage ledger
- [`target-quic`](https://github.com/idrto/target-quic) — **deprecated / archived** (historical donor)

## License

MIT OR Apache-2.0
