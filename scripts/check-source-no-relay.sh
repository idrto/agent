# Fail if Source / C-API crates depend on idr-target / Relay edge code.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

check_crate() {
  local crate="$1"
  local toml="$ROOT/crates/$crate/Cargo.toml"
  # Shipped dependencies only: a [dev-dependencies] entry (e.g. idr-c-api's loopback test against an
  # in-process Target) is not linked into the Source library.
  if awk '/^\[/ { in_dev = ($0 ~ /dev-dependencies/) } !in_dev && /^[[:space:]]*idr-target[[:space:]]*=/' "$toml" | grep .; then
    echo "ERROR: $crate must not depend on idr-target" >&2
    exit 1
  fi
  if grep -RInE 'use[[:space:]]+idr_target|extern[[:space:]]+crate[[:space:]]+idr_target' "$ROOT/crates/$crate/src" 2>/dev/null; then
    echo "ERROR: $crate sources must not import idr_target" >&2
    exit 1
  fi
}

check_crate idr-source
check_crate idr-c-api
check_crate idr-signaling
check_crate idr-webrtc
check_crate idr-core
check_crate idr-dp

echo "OK: Source path crates have no Target/Relay dependency"
