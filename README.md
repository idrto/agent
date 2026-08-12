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
│   ├── idr-webrtc/       # PeerTransport + native libdatachannel (feature native)
│   ├── idr-signaling/    # discovery + PepClient (QUIC→WSS) + presence_quic
│   ├── idr-dp/           # dp-sdk integration + secret store ports
│   ├── idr-dp-ffi/       # C ABI for Target desktop crypto (IdrCrypto)
│   ├── idr-source/       # minimal mobile-first Source (WebRTC only)
│   ├── idr-c-api/        # stable C ABI (opaque handles + batched events)
│   └── idr-target/       # Presence + WebRTC + generic [[services]] gateway
├── packages/
│   ├── idr_core_ffi/
│   ├── idr_dp_ffi/       # deprecated re-export; IdrDpCrypto is in idr_target
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

# Source C ABI with real offerer
cargo build -p idr-c-api --release --features native

# Target desktop crypto FFI (Windows idr_dp.dll / macOS libidr_dp.dylib / Linux libidr_dp.so)
cargo build -p idr-dp-ffi --release
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

final runtime = await IdrRuntime.create(
  useMock: false,
  authToken: '...', // Bearer / device token from @idrto/api
);
if (bundle != null) {
  // Optional: inject DP identity via C ABI when isolate wiring is available.
}
final session = await runtime.connect('cam1.acme.idr.to');
```

### Auth + plugins

- Source requires `auth_token` (Bearer / device token from `@idrto/api`). Anonymous is rejected (unless DP mTLS identity is set).
- Target `[[services]]` registers generic HTTP/TCP gateway endpoints; optional `inject_headers` keeps secrets on Target.
- `[plugins].http` still enables nginx `http`/`https` site connectors.
- ADRs: [0013](docs/adr/0013-target-plugins-catalog.md), [0014](docs/adr/0014-api-backed-auth.md), [0015](docs/adr/0015-libdatachannel-required.md), [0016](docs/adr/0016-generic-service-gateway.md).

### Flutter desktop CLI (secrets in secure storage)

```bash
cd packages/idr_cli
flutter pub get
flutter run -d windows --dart-define=... # or: dart run bin/idr_cli.dart doctor
```

## E2E runbook

```bash
# From agent/ — auth unit gates + source no-relay invariant
bash scripts/e2e-sdk.sh

# Full stack (local): start Postgres + api (RELAY_USAGE_BEARER set) + Presence
# with billing.enabled=true pointing at api mux, target-agent --features webrtc,
# HTTP upstream :18080, optional Ollama :11434, then Source native connect.
# See docs/adr/0014-api-backed-auth.md and config/target.local.toml [plugins].
```

## Develop

```bash
cargo test --workspace --all-targets
cargo build --workspace --release
bash scripts/check-source-no-relay.sh

# Dart (after building libidr_c_api)
cargo build -p idr-c-api --release
# Product: useMock false + authToken required
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
- [`api`](https://github.com/idrto/api) — Auth+Billing (`@idrto/api`)
- [`target-quic`](https://github.com/idrto/target-quic) — **deprecated / archived** (historical donor)

## License

MIT OR Apache-2.0
