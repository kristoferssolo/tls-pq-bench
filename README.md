# tls-pq-bench

`tls-pq-bench` is a reproducible TLS 1.3 benchmark harness for comparing
classical and post-quantum hybrid key exchange groups.

The project benchmarks two application carriers:

- `raw`: minimal framing for low-overhead measurements
- `http1`: HTTP/1.1 for a more realistic application path

And four key exchange modes:

- `x25519`
- `secp256r1`
- `x25519mlkem768`
- `secp256r1mlkem768`

Each benchmark record captures:

- TCP connect latency
- TLS handshake latency
- TTLB (time to last byte)

All raw metrics are stored in nanoseconds as JSONL.

## Quick Start

### Build

```bash
cargo build --release
```

### Fastest Local Smoke Test

Start the default local listener set:

```bash
just multi-server
```

In another terminal, run the built-in smoke matrix:

```bash
just smoke-all
```

This path uses the server's ephemeral self-signed certificate and insecure
client verification. It is intended only for local validation.

### Run One Benchmark Manually

Start one server:

```bash
./target/release/server \
    --mode x25519 \
    --proto raw \
    --listen 127.0.0.1:4433
```

Run one benchmark:

```bash
./target/release/runner \
    --server 127.0.0.1:4433 \
    --proto raw \
    --mode x25519 \
    --payload-bytes 1024 \
    --iters 100 \
    --warmup 10
```

Without `--ca-cert`, the runner uses insecure certificate verification. That is
appropriate for quick local checks only.

### Run A Matrix

Use one of the bundled configs:

```bash
./target/release/runner --config benchmarks/sanity.toml
```

Or generate your own:

```bash
uv run --script scripts/generate_benchmark_matrix.py --output matrix.toml
./target/release/runner --config matrix.toml
```

## Recommended Workflows

### 1. Local Development

Use this when you are validating correctness or making code changes.

- `just multi-server`
- `just smoke-all`
- `just sanity-matrix`

### 2. Verified Local Or Remote Runs

Generate a persistent CA and server certificate:

```bash
just generate-certs
```

For a remote host, include the DNS name or IP that the runner will verify:

```bash
just generate-certs certs 365 bench.example.com
just generate-certs certs 365 localhost 10.0.1.23
```

Start the server with the generated certificate pair:

```bash
./target/release/server \
    --mode x25519 \
    --proto raw \
    --listen 0.0.0.0:4433 \
    --cert certs/server.der \
    --key certs/server.key
```

Run the client with CA verification:

```bash
./target/release/runner \
    --server 10.0.1.23:4433 \
    --server-name bench.example.com \
    --ca-cert certs/ca.der \
    --proto raw \
    --mode x25519 \
    --iters 100 \
    --warmup 10
```

`server_name` is used for both TLS verification and the HTTP/1.1 `Host` header.

### 3. Scheduled Two-Host Benchmarks

The repo includes helpers for a persistent server host plus a runner host with systemd timers.

Main entry points:

- `just prod-server-service env_file=/etc/tls-pq-bench/server.env`
- `just prod-schedule env_file=/etc/tls-pq-bench/scheduled.env`

## Result Format

Each iteration is emitted as one JSONL record:

```jsonl
{"run_id":"0195f8cf-2f6f-7e9b-9c52-6e5d6b7d0a10","iteration":0,"proto":"raw","mode":"x25519","payload_bytes":1024,"concurrency":1,"iters":100,"warmup":10,"tcp_ns":120000,"handshake_ns":500000,"ttlb_ns":650000}
```

## Analyzer

The Rust `analyzer` binary summarizes one scheduled-results directory tree into
weekly JSON artifacts.

Basic usage:

```bash
./target/release/analyzer \
    /path/to/results
```

Common options:

- `--out-dir <dir>`: defaults to `<results-dir>/analysis`
- `--profile lite|full`: restrict output to one schedule profile
- `--strict`: abort on the first missing, malformed, or invalid artifact
- `--pretty true|false`: control JSON pretty-printing, default `true`

The analyzer recursively discovers paired `*.jsonl` and `*.meta` files by shared
basename stem and writes four files:

- `manifest.json`: run counts, profile list, scenario/comparison counts, and artifact paths
- `weekly_aggregates.json`: per-scenario weekly summaries plus provenance and warnings
- `pq_deltas.json`: classical vs PQ family comparisons for matching contexts
- `diagnostics.json`: skipped runs, unmatched artifacts, parse errors, and comparison warnings

Default mode skips bad inputs when possible and records them in
`diagnostics.json`. Strict mode makes those same problems fatal.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
