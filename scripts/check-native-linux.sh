#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "Checking native WebRTC build (Linux)..."
cargo build --features webrtc --locked
cargo test --features webrtc webrtc_signaling ice -- --nocapture
echo "Native WebRTC check passed (peer + mux compile under --features webrtc)."
