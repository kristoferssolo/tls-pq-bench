# tls-pq-bench

Reproducible benchmarking harness for comparing TLS 1.3 key exchange
configurations:

- Classical: X25519
- Hybrid PQ: X25519MLKEM768 (via `rustls` + `aws_lc_rs`)

Primary metrics:

- Handshake latency
- TTLB (Time-to-Last-Byte)

Secondary metrics:

- CPU cycles (`perf`)
- Memory behavior (optional: Valgrind/Massif)
- Binary size (optional)

This repo is intended as the implementation for the empirical part of the
bachelor thesis (following the course thesis methodology).

## Non-goals

- Not a general-purpose TLS load tester
- Not a cryptographic audit tool
- Not a middlebox compatibility test suite (can be added later)

## Quick start (local dev)

1. Install Rust stable and Linux tooling:
   - `perf`, `tcpdump` (optional), `jq`, `python3`
2. Build:
   - `cargo build --release`

## Reproducibility notes

All experiments should record:

- commit hash
- rustc version
- CPU model and governor
- kernel version
- rustls and aws-lc-rs versions
- exact CLI parameters and network profile

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
