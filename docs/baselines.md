# Build and performance baselines

**Updated:** 2026-07-28 (Phase 6 cutover)

## Phase 1 — `idrto/agent` workspace (WSL2 Ubuntu aarch64)

Host: 8 CPUs, ~7.5 GiB RAM, rustc 1.96.0  
Build dir: `/tmp/agent-build` with `CC=cc CXX=c++`

| Command | Result |
|---------|--------|
| `cargo test --workspace --all-targets` | **Pass** |
| `cargo build --workspace --release` | **Pass** |
| `cargo build -p target-agent --release --features webrtc` | **Fail** on assessor host (no cmake). Covered by CI `webrtc` job. |

### Release binary sizes (default features, aarch64-unknown-linux-gnu)

| Binary | Size |
|--------|------|
| `target-agent` | **16,523,352 bytes (~15.8 MiB)** |
| `mock-presence` | **2,571,296 bytes (~2.5 MiB)** |

### Phase 6 notes

- Donor `target-quic` is **deprecated/archived**; baselines live only in this repo.
- CI `webrtc` job installs cmake/ninja and uses `Swatinem/rust-cache` (`shared-key: webrtc`, `prefix-key: v0-libdatachannel`) to retain native libdatachannel build outputs.
- Attach `--features webrtc` size from CI `webrtc-size.txt` here after the first green run.

### Phase 0 donor notes (historical)

Donor `target-quic` did not produce a green binary on the assessor machine before the port (Windows ARM aws-lc libs; WSL compile errors that Phase 1 fixed).

## Follow-up

1. Record `--features webrtc` binary size from CI.
2. Re-enable CI `RUSTFLAGS=-Dwarnings` after unused-code cleanup.
3. Idle RSS / startup timing / mobile Source binary size once native offerer ships.
