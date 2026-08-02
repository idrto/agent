# Implementation Report — IDR Target-to-Relay QUIC v1

## Completed features

- Signed Presence discovery format with canonical JSON verification
- SHA-256 dual-mod placement (primary + secondary; bump secondary on collide; `N >= 2`; append-safe across discovery epochs) behind `PresencePlacement` trait
- Dual Presence WebSocket clients with reconnection
- Relay command deduplication by `command_id` with in-flight sharing
- Open-addressing relay connection table (1024 default, SplitMix64 hash, generational handles)
- `get_or_connect` with shared connection attempts and LRU idle eviction
- Quinn QUIC transport (TLS 1.3, ALPN `idr-relay-v1`, postcard control framing)
- Target-initiated QUIC only; Relay uses observed peer address
- Connection epoch replacement on Relay
- Batched idle schedulers (DelayQueue on Target, 1s scan on Relay)
- SQLite metadata persistence with WAL and batched writer
- Prometheus metrics per spec
- GitHub Actions CI (fmt, clippy, test, doc, release, cargo-deny)
- Benchmark stubs and load-generator skeleton

## Architectural decisions

| Decision | Rationale |
|----------|-----------|
| Quinn 0.11 | Mature Rust QUIC; async Tokio integration |
| aws-lc-rs (rustls) | Better cross-platform builds than ring on Windows ARM |
| Duplicated protocol module | Only two repos available; diff-checked compatibility |
| Postcard over QUIC | Compact binary; no internally-tagged JSON enums |
| Modulo placement v1 | Spec-required; trait allows future rendezvous |

## Measured performance

Not run on production hardware in this session. Use:

```bash
cargo bench
cargo run -p idr-load-generator -- --targets 1000 --rate 50
```

Record RSS, FD count, idle PPS from `/metrics`.

## Known limitations

- One-million idle connections unverified — harness provided
- Relay dual-stack bind keeps last endpoint when both IPv4/IPv6 configured
- Dev mode skips TLS verification when discovery key empty
- Load generator QUIC client wiring incomplete (skeleton only)
- Windows ARM native build requires LLVM + MSVC libs for aws-lc-sys; use WSL/Linux CI

## Remaining work

- Full e2e integration test with spawned mock presence + relay + target
- Rendezvous / jump-consistent placement implementations
- mTLS option for QUIC
- Production relay signing key pinning separate from discovery key
- Measured benchmark report at 1k/10k/100k connection tiers
