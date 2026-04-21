# tls-pq-bench

Reproducible benchmarking harness for comparing TLS 1.3 key exchange configurations.

## Features

- **Key Exchange Modes**
  - Primary pair: `x25519` and `x25519mlkem768`
  - Secondary pair: `secp256r1` and `secp256r1mlkem768`
  - Hybrid modes use `rustls` + `aws_lc_rs`

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
    --server-name localhost \
    --ca-cert certs/ca.der \
    --iters 100 \
    --warmup 10
```

For matrix runs, switch each benchmark entry to:

```toml
verification = { kind = "cacert", path = "certs/ca.der" }
```

The runner now defaults to `server_name = "localhost"` for local runs. Override
it with `--server-name <hostname>` on the CLI, or `server_name = "<hostname>"`
per benchmark in TOML, when the server presents a certificate for a remote DNS
name. The same value is used for TLS verification and the HTTP/1.1 `Host`
header.

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

### Running On A Server With systemd

For a persistent server host, copy [ops/server.env.example](ops/server.env.example)
to `/etc/tls-pq-bench/server.env`, set `REPO_DIR` and `SERVER_BIN`, then
install the bundled unit:

```bash
sudo mkdir -p /etc/tls-pq-bench
sudo cp ops/server.env.example /etc/tls-pq-bench/server.env
$EDITOR /etc/tls-pq-bench/server.env
just prod-server-service env_file=/etc/tls-pq-bench/server.env
```

Inspect the service with:

```bash
systemctl status tls-pq-bench-server.service
journalctl -u tls-pq-bench-server.service -n 100 --no-pager
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
