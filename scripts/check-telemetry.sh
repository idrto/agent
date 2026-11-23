#!/usr/bin/env bash
# Telemetry CI gates (docs/observability/07 §3). Run from the agent repo root.
# Requires cargo, dart; flutter optional (Flutter hooks tests are skipped without it).
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n== %s\n' "$*"; }

step "rust: idr-telemetry fmt, clippy (deny warnings), tests"
cargo fmt -p idr-telemetry -- --check
cargo clippy -p idr-telemetry --features subscriber --all-targets -- -D warnings
cargo test -p idr-telemetry --features subscriber
cargo test -p idr-c-api --features test-hooks --test ffi_panic   # P1-12: no panic crosses the ABI

step "dart: idr_telemetry, idr_diag analyze + test"
for p in packages/idr_telemetry packages/idr_diag; do
  dart pub get --directory "$p"
  dart analyze --fatal-infos "$p"
  (cd "$p" && dart test)
done

if command -v flutter >/dev/null 2>&1; then
  step "flutter: idr_telemetry_flutter analyze + test"
  (cd packages/idr_telemetry_flutter && flutter pub get && flutter analyze --fatal-infos && flutter test)
else
  echo "flutter not installed; skipping idr_telemetry_flutter"
fi

step "ffi: Dart trace and session_id continue into the native engine (ABI 4)"
cargo build -q -p idr-c-api
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) lib="$(pwd -W)/target/debug/idr_c_api.dll" ;;
  Darwin) lib="$PWD/target/debug/libidr_c_api.dylib" ;;
  *) lib="$PWD/target/debug/libidr_c_api.so" ;;
esac
dart pub get --directory packages/idr_client
dart analyze --fatal-infos packages/idr_client
(cd packages/idr_client && IDR_C_API_LIB="$lib" dart test)

if [ -d ../../applications/apps/idr_cli_core ]; then
  step "apps: CLI telemetry wrapper (sibling checkout present)"
  (cd ../../applications/apps/idr_cli_core && dart pub get && dart analyze --fatal-infos lib && dart test test/telemetry_run_test.dart)
fi

step "schema: real Rust output validates against spec/telemetry"
sample="$(mktemp -d)"
trap 'rm -rf "$sample"' EXIT
cargo run -q -p idr-telemetry --features subscriber --example sample -- "$sample"
dart run packages/idr_diag/bin/idr_diag.dart validate --repo . "$sample"

step "lints: event registry, banned APIs, secret Debug, dependency rules"
dart run packages/idr_diag/bin/idr_diag.dart lint --repo .
