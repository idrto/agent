#!/usr/bin/env bash
# Local end-to-end: Presence + Relay + Target (Linux)
# Source is WebRTC-only (ADR-0011) and is not required for this Relay wake path.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PRESENCE="$ROOT/../presence"
RELAY="$ROOT/../relay"
TARGET="$ROOT"
presence_bin() { [[ -n "${CARGO_TARGET_DIR:-}" && -x "$CARGO_TARGET_DIR/debug/idr-presence" ]] && echo "$CARGO_TARGET_DIR/debug/idr-presence" || echo "$PRESENCE/target/debug/idr-presence"; }
relay_bin() { [[ -n "${CARGO_TARGET_DIR:-}" && -x "$CARGO_TARGET_DIR/debug/idr-relay" ]] && echo "$CARGO_TARGET_DIR/debug/idr-relay" || echo "$RELAY/target/debug/idr-relay"; }
target_bin() { [[ -n "${CARGO_TARGET_DIR:-}" && -x "$CARGO_TARGET_DIR/debug/target-agent" ]] && echo "$CARGO_TARGET_DIR/debug/target-agent" || echo "$TARGET/target/debug/target-agent"; }

echo "==> Build"
( cd "$PRESENCE" && cargo build --bin idr-presence )
( cd "$RELAY" && cargo build --bin idr-relay )
( cd "$TARGET" && cargo build -p target-agent )

echo "==> Start in four terminals:"
echo ""
echo "# 1 — dummy HTTP upstream (Target nginx http_upstream)"
echo "python3 $TARGET/scripts/local-http-upstream.py"
echo ""
echo "# 2 — Presence"
echo "cd $PRESENCE && IDR_CONFIG=config/presence.local.toml $(presence_bin)"
echo ""
echo "# 3 — Relay"
echo "cd $RELAY && $(relay_bin) --config config/relay.local.toml"
echo ""
echo "# 4 — Target"
echo "cd $TARGET && $(target_bin) --config config/target.local.toml run"
echo ""
echo "Then:"
echo "  curl -sS http://127.0.0.1:8081/.well-known/idr-presence.json"
echo "  curl -sS http://127.0.0.1:9092/metrics | grep target_sessions_active"
echo "  curl -sS -H 'Host: dev.local.idr.to' http://127.0.0.1:18080/"
echo "Expected body: idr-target-upstream-ok"
