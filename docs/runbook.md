# Runbook

## 1) Build

```bash
cargo build --release
```

## 2) Start server

Quick local example with the server's ephemeral self-signed certificate:

```bash
./target/release/server --mode x25519 --proto raw --listen 0.0.0.0:4433
```

## 3) Run client benchmark

Raw example:

```bash
./target/release/runner \
    --server 1.2.3.4:4433 \
    --proto raw \
    --mode x25519 \
    --server-name bench.example.com \
    --payload-bytes 1024 \
    --concurrency 10 \
    --iters 500 \
    --warmup 50 \
    --out results.jsonl
```

Without `--ca-cert`, the runner uses insecure certificate verification. That is
fine for ad hoc local testing, but not for CA-verified runs.

HTTP/1.1 example:

```bash
./target/release/server --mode x25519mlkem768 --proto http1 --listen 0.0.0.0:4433
./target/release/runner \
    --server 1.2.3.4:4433 \
    --proto http1 \
    --mode x25519mlkem768 \
    --payload-bytes 1024 \
    --concurrency 1 \
    --iters 200 \
    --warmup 20 \
    --out results-http1.jsonl
```

### Matrix Benchmarks

Create a config file (`matrix.toml`):

```toml
[[benchmarks]]
server = "1.2.3.4:4433"
proto = "raw"
mode = "x25519"
verification.kind = "insecure"
payload = 1024
iters = 500
warmup = 50
concurrency = 1

[[benchmarks]]
server = "1.2.3.4:4433"
proto = "raw"
mode = "x25519"
verification.kind = "insecure"
payload = 4096
iters = 500
warmup = 50
concurrency = 10
```

Run matrix:

```bash
./target/release/runner --config matrix.toml
```

Each JSONL record now includes both `proto` and `mode`, so `raw` and `http1`
runs can be aggregated separately during analysis.

## 3a) Verified certificate workflow

Generate a persistent CA and server certificate pair:

```bash
just generate-certs
```

Start the server with the generated certificate and key:

```bash
./target/release/server \
    --mode x25519 \
    --proto raw \
    --listen 0.0.0.0:4433 \
    --cert certs/server.der \
    --key certs/server.key
```

Run the benchmark with CA verification:

```bash
./target/release/runner \
    --server 1.2.3.4:4433 \
    --proto raw \
    --mode x25519 \
    --payload-bytes 1024 \
    --concurrency 10 \
    --iters 500 \
    --warmup 50 \
    --ca-cert certs/ca.der \
    --out results.jsonl
```

For matrix benchmarks, every entry must include a `verification` block. Use:

```toml
verification = { kind = "cacert", path = "certs/ca.der" }
server_name = "bench.example.com"
```

If omitted, `server_name` defaults to `localhost`. For two-machine experiments,
set it to the DNS name or IP address covered by the server certificate. The
runner uses that value for both TLS verification and the HTTP/1.1 `Host`
header, and the runner host still needs a copy of the matching `certs/ca.der`.

## 4) Collect perf stats (optional)

Run on the client:

```bash
perf stat -e cycles,instructions,cache-misses ./target/release/runner ...
```

## 5) Summarize

Use a script to compute p50/p95/p99 from JSONL.
