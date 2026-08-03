# IDR Target Agent (Flutter desktop)

Windows host that drives the native `target-agent` CLI and stores DP identity
in `flutter_secure_storage`.

## Run

From the agent monorepo root:

```bash
# Native binary (Windows ARM64: VS + LLVM Clang)
cargo build -p target-agent
cp config/target.example.toml config/target.local.toml

cd packages/idr_cli
flutter pub get

# Prefer the helper on Windows ARM64 when both VS Community and BuildTools
# are installed (plain `flutter` may pick incomplete BuildTools MSBuild):
scripts\flutter_windows.cmd run -d windows

# Equivalent once the machine CMake/VS selection is healthy:
# flutter run -d windows
```

Optional dart-defines:

```bash
scripts\flutter_windows.cmd run -d windows --dart-define=IDR_AGENT_BINARY=../../target/debug/target-agent.exe
scripts\flutter_windows.cmd run -d windows --dart-define=IDR_TARGET_CONFIG=../../config/target.local.toml
```

## Console CLI

```bash
dart run bin/idr_cli.dart doctor
dart run bin/idr_cli.dart run
dart run bin/idr_cli.dart identity init --host db1.us-east--acme --role target
```
