# Protocol sync helper — compare agent idr-protocol to Presence/Relay copies.
#
# Usage (from agent repo, sibling checkouts assumed):
#   bash scripts/check_protocol_sync.sh
#   bash scripts/check_protocol_sync.sh /path/to/presence /path/to/relay
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROTO="$ROOT/crates/idr-protocol/src"
PRESENCE="${1:-$ROOT/../presence/src/protocol}"
RELAY="${2:-$ROOT/../relay/src/protocol}"

fail=0
if [[ -d "$PRESENCE" ]]; then
  if ! diff -ru "$PROTO" "$PRESENCE" >/tmp/idr-proto-presence.diff; then
    echo "DIFF: agent idr-protocol vs presence" >&2
    head -n 40 /tmp/idr-proto-presence.diff >&2 || true
    fail=1
  else
    echo "OK: presence protocol matches agent"
  fi
else
  echo "SKIP: presence not found at $PRESENCE"
fi

if [[ -d "$RELAY" ]]; then
  if ! diff -ru "$PROTO" "$RELAY" >/tmp/idr-proto-relay.diff; then
    echo "DIFF: agent idr-protocol vs relay" >&2
    head -n 40 /tmp/idr-proto-relay.diff >&2 || true
    fail=1
  else
    echo "OK: relay protocol matches agent"
  fi
else
  echo "SKIP: relay not found at $RELAY"
fi

exit "$fail"
