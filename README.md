# tls-pq-bench

Reproducible benchmarking harness for comparing TLS 1.3 key exchange configurations.

## Features

- **Key Exchange Modes**
  - Classical: `x25519`
  - Hybrid PQ: `x25519mlkem768` (via `rustls` + `aws_lc_rs`)

- **Protocol Modes**
  - `raw` for low-overhead framed payload benchmarking
  - `http1` for HTTP/1.1 request and response benchmarking

- **Metrics**
  - TCP connection latency (nanoseconds)
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
  - Each configuration: server, proto, mode, verification, payload, iters, warmup, concurrency

## Quick Start

### Build

```bash
cargo build --release
```

### Run Single Benchmark

Terminal 1 - Start server:

```bash
./target/release/server --mode x25519 --proto raw --listen 127.0.0.1:4433
```

Terminal 2 - Run benchmark:

```bash
./target/release/runner --server 127.0.0.1:4433 --proto raw --mode x25519 --iters 100 --warmup 10
```

This CLI path defaults to insecure certificate verification unless `--ca-cert` is
provided, which makes it suitable for quick local checks against the server's
ephemeral self-signed certificate.

### Run Matrix Benchmarks

Create a config file (`matrix.toml`):

```toml
[[benchmarks]]
server = "127.0.0.1:4433"
proto = "raw"
mode = "x25519"
verification.kind = "insecure"
payload = 1024
iters = 100
warmup = 10
concurrency = 1

[[benchmarks]]
server = "127.0.0.1:4433"
proto = "raw"
mode = "x25519"
verification.kind = "insecure"
payload = 4096
iters = 100
warmup = 10
concurrency = 4
```

Run:

```bash
./target/release/runner --config matrix.toml
```

Every benchmark entry must include a `verification` block. Use
`verification.kind = "insecure"` for quick local runs, or
`verification = { kind = "cacert", path = "certs/ca.der" }` when you want CA
verification.

### Verified Certificate Workflow

Generate a persistent CA and server certificate:

```bash
just generate-certs
```

Start the server with the generated certificate pair:

```bash
./target/release/server \
    --mode x25519 \
    --proto raw \
    --listen 127.0.0.1:4433 \
    --cert certs/server.der \
    --key certs/server.key
```

Run the client with CA verification enabled:

```bash
./target/release/runner \
    --server 127.0.0.1:4433 \
    --proto raw \
    --mode x25519 \
    --ca-cert certs/ca.der \
    --iters 100 \
    --warmup 10
```

For matrix runs, switch each benchmark entry to:

```toml
verification = { kind = "cacert", path = "certs/ca.der" }
```

The runner currently always uses TLS server name `localhost`, even if `--server`
points to another IP or hostname. For remote runs, the presented certificate
must still be valid for `localhost`, and the runner machine needs a copy of the
matching CA file.

### Output

Results are emitted as JSONL to stdout or a file:

```jsonl
{"run_id":"0195f8cf-2f6f-7e9b-9c52-6e5d6b7d0a10","iteration":0,"proto":"raw","mode":"x25519","payload_bytes":1024,"concurrency":1,"iters":100,"warmup":10,"tcp_ns":120000,"handshake_ns":500000,"ttlb_ns":650000}
{"run_id":"0195f8cf-2f6f-7e9b-9c52-6e5d6b7d0a10","iteration":1,"proto":"raw","mode":"x25519","payload_bytes":1024,"concurrency":1,"iters":100,"warmup":10,"tcp_ns":130000,"handshake_ns":560000,"ttlb_ns":760000}
```

The raw records always store timing metrics in nanoseconds (`tcp_ns`,
`handshake_ns`, `ttlb_ns`). The bundled analyzer summarizes those fields and
can convert them to `us` or `ms` for presentation.

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
