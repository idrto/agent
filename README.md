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

### Device identity / CSR enrollment

`source-agent`/`target-agent` ship `identity`/`cert`/`entity` subcommands
(via the shared `idr-enroll` crate) for `dp-sdk` mTLS enrollment against a
`better-auth` server with the `delegate-permissions` plugin. All commands
accept `--identity <path>` (else `[dp].identity_path`, else `identity.dp.json`).

```bash
# Device: generate an Ed25519 key + CSR offline, then queue for approval.
cargo run -p target-agent -- identity init --role target --host db1.us-east--acme
cargo run -p target-agent -- identity enroll --auth-url http://127.0.0.1:3000/api/auth \
  --entity acme.example
# ... an entity admin runs `cert approve <enrollId>` (below) ...
cargo run -p target-agent -- identity pull --auth-url http://127.0.0.1:3000/api/auth

# Localhost instant path: admin CA + issuer keys on the same machine skip the
# approval queue entirely (generates the CSR if needed, signs the leaf
# locally, calls enroll-instant, and saves the DeviceIdentity in one step).
cargo run -p target-agent -- identity enroll --local \
  --host db1.us-east--acme --entity acme.example \
  --ca-key entity-ca.key.json --ca-cert entity-ca.cert.pem \
  --issuer-ski <rootAdminSki> --issuer-key root-admin.key.json

# Admin: bootstrap an Entity, a dev CA, and approve/reject queued CSRs.
cargo run -p source-agent -- entity kickstart --entity acme.example --package personal
cargo run -p source-agent -- cert init-ca --common-name "acme.example Entity CA" \
  --out-key entity-ca.key.json --out-cert entity-ca.cert.pem
cargo run -p source-agent -- cert list --entity acme.example --pending
cargo run -p source-agent -- cert approve <enrollId> --entity acme.example --host db1.us-east--acme \
  --csr device.csr.pem --subject-ski <deviceSki> \
  --ca-key entity-ca.key.json --ca-cert entity-ca.cert.pem \
  --issuer-ski <rootAdminSki> --issuer-key root-admin.key.json
cargo run -p source-agent -- cert reject <enrollId>
```

The resulting `identity.dp.json` includes `cert_pem`/`chain_pem` when
mTLS-enrolled; `build_runtime`/`PepClient::with_identity` materialize it via
`dp_rust_mtls::materialize_mtls_client` automatically when present, falling
back to dev/self-signed behavior otherwise.

### Auth / Presence entitlement JWT

Runtime path (after DeviceIdentity enroll):

1. Configure `[auth].url` (default `https://auth.idr.to/api/auth`) — Billing-hosted Better Auth, reverse-proxied as `auth.idr.to`.
2. Before each Presence `register_target`, the Target Agent mints a JWT: `POST {url}/agent/token` with CapabilityCredential + EdDSA proof-of-possession.
3. Include the token as `entitlement_jwt` on `register_target`. Presence verifies via JWKS and caches claims for accept_session / ensure_relay / mint_turn.

```toml
[auth]
url = "https://auth.idr.to/api/auth"
# token_path = "/agent/token"
# Fail closed when mint/identity fails (the default).
# required = true

[dp]
# identity_path = "identity.dp.json"
```

**Local/dev:** explicitly set `[auth].required = false` and run Presence with `[auth].enabled = false` so registration works without Billing. The default is `true`, matching Presence's fail-closed default.

There is no Presence↔Billing WSS mux. See Presence [docs/AUTH.md](https://github.com/idrto/presence/blob/main/docs/AUTH.md) and the Billing [Agent token contract](https://github.com/2keyapp/billing/blob/delegate_permissions/api-docs/billing-api/auth/agent-token.md).

The Dart `idr_cli` mirrors `identity init|enroll|pull` as thin wrappers that
shell out to a `--agent-binary` (`source-agent`/`target-agent` executable)
and then import the resulting JSON into secure storage:

```bash
dart run bin/idr_cli.dart identity init --agent-binary ../../target/debug/target-agent \
  --role target --host db1.us-east--acme
dart run bin/idr_cli.dart identity enroll --agent-binary ../../target/debug/target-agent \
  --local --host db1.us-east--acme --entity acme.example \
  --ca-key entity-ca.key.json --ca-cert entity-ca.cert.pem \
  --issuer-ski <rootAdminSki> --issuer-key root-admin.key.json
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

### Flutter desktop Target host (Windows)

Builds a UI that shells out to native `target-agent` (doctor / identity / run)
and keeps DP identity in `flutter_secure_storage`.

```bash
# 1) Native CLI (from agent repo root; Windows ARM64 needs VS + LLVM Clang)
cargo build -p target-agent
# optional: copy config
cp config/target.example.toml config/target.local.toml

# 2) Flutter host
cd packages/idr_cli
flutter pub get
# On Windows ARM64 with both VS Community + BuildTools installed, use:
scripts/flutter_windows.cmd run -d windows
# (plain `flutter run -d windows` once CMake picks Community cleanly)

# Console CLI (same package):
dart run bin/idr_cli.dart doctor
dart run bin/idr_cli.dart run   # starts target-agent
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
