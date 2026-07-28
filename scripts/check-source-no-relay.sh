# Fail if Source / C-API crates depend on idr-target / Relay edge code.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

check_crate() {
  local crate="$1"
  local toml="$ROOT/crates/$crate/Cargo.toml"
  if grep -E '^\s*idr-target\s*=' "$toml"; then
    echo "ERROR: $crate must not depend on idr-target" >&2
    exit 1
  fi
  if grep -RInE 'use[[:space:]]+idr_target|extern[[:space:]]+crate[[:space:]]+idr_target' "$ROOT/crates/$crate" 2>/dev/null; then
    echo "ERROR: $crate sources must not import idr_target" >&2
    exit 1
  fi
}

check_crate idr-source
check_crate idr-c-api
check_crate idr-signaling
check_crate idr-webrtc
check_crate idr-core

echo "OK: Source path crates have no Target/Relay dependency"
