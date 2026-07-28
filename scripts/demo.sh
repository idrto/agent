#!/usr/bin/env bash
# Local end-to-end demo (Linux/WSL/macOS)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RELAY="$ROOT/../relay"
TARGET="$ROOT"

echo "==> Building..."
( cd "$RELAY" && cargo build --release )
( cd "$TARGET" && cargo build --release )

echo "==> Start mock presence servers, relay, and target in separate terminals:"
echo ""
echo "# Terminal 1 — primary presence"
echo "cd $TARGET && cargo run --release --bin mock-presence -- --listen 127.0.0.1:9101 --role primary"
echo ""
echo "# Terminal 2 — secondary presence"
echo "cd $TARGET && cargo run --release --bin mock-presence -- --listen 127.0.0.1:9102 --role secondary"
echo ""
echo "# Terminal 3 — relay"
echo "cd $RELAY && cargo run --release -- --config config/relay.example.toml"
echo ""
echo "# Terminal 4 — target"
echo "cd $TARGET && IDR_CONFIG=config/target.example.toml cargo run --release --bin target-quic"
echo ""
echo "Verify metrics:"
echo "  curl -s http://127.0.0.1:9090/metrics | grep idr_relay"
echo "  curl -s http://127.0.0.1:9091/metrics | grep idr_target"
