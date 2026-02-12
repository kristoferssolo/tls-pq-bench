# tls-pq-bench

Reproducible benchmarking harness for comparing TLS 1.3 key exchange configurations.

## Features

- **Key Exchange Modes**
  - Classical: `x25519`
  - Hybrid PQ: `x25519mlkem768` (via `rustls` + `aws_lc_rs`)

- **Metrics**
  - Handshake latency (nanoseconds)
  - TTLB - Time-to-Last-Byte (nanoseconds)

- **Benchmark Control**
  - Warmup iterations (excluded from results)
  - Configurable iterations
  - Concurrency control (parallel connections)
  - Configurable payload sizes

- **Reproducibility**
  - Structured logging (tracing)
  - Run ID for correlating logs
  - Rust version, OS, arch recorded
  - Command line arguments logged
  - Negotiated cipher suite logged

- **Matrix Benchmarks**
  - TOML configuration file support
  - Run multiple benchmark configurations sequentially
  - Each configuration: mode, payload, iters, warmup, concurrency

## Quick Start

### Build

```bash
cargo build --release
```

### Run Single Benchmark

Terminal 1 - Start server:

```bash
./target/release/server --mode x25519 --listen 127.0.0.1:4433
```

Terminal 2 - Run benchmark:

```bash
./target/release/runner --server 127.0.0.1:4433 --mode x25519 --iters 100 --warmup 10
```

### Run Matrix Benchmarks

Create a config file (`matrix.toml`):

```toml
[[benchmarks]]
server = "127.0.0.1:4433"
mode = "x25519"
payload = 1024
iters = 100
warmup = 10
concurrency = 1

[[benchmarks]]
server = "127.0.0.1:4433"
mode = "x25519mlkem768"
payload = 1024
iters = 100
warmup = 10
concurrency = 1
```

Run:

```bash
./target/release/runner --config matrix.toml
```

### Output

Results are emitted as NDJSON to stdout or a file:

```ndjson
{"iteration":0,"mode":"x25519","payload_bytes":1024,"handshake_ns":500000,"ttlb_ns":650000}
{"iteration":1,"mode":"x25519","payload_bytes":1024,"handshake_ns":490000,"ttlb_ns":620000}
```

### Logging

Enable debug logs with `RUST_LOG`:

```bash
RUST_LOG=info ./target/release/runner --server 127.0.0.1:4433
```

Output includes:

- Run ID for correlation
- Rust version, OS, arch
- Command used
- Negotiated cipher suite
- Benchmark configuration

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
