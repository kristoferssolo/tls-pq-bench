# Runbook

This document is the practical guide for running benchmarks by hand.

If you want automated two-host scheduling, use
[scheduled-benchmarks.md](scheduled-benchmarks.md) instead.

## Prerequisites

- Rust toolchain installed
- `cargo build --release` completed
- two terminals if you are running client and server on the same machine
- optional: `uv` for the helper scripts
- optional: generated CA and server certs for verified runs

## Workflow 1: Local Smoke Validation

Use this to confirm the binaries, listeners, and protocol wiring work.

Start the full local listener set:

```bash
just multi-server
```

Run the smoke suite in another terminal:

```bash
just smoke-all
```

Default local port layout:

| Port | Protocol | Mode |
|------|----------|------|
| 4433 | `raw` | `x25519` |
| 4434 | `http1` | `x25519` |
| 4435 | `raw` | `secp256r1` |
| 4436 | `http1` | `secp256r1` |
| 4437 | `raw` | `x25519mlkem768` |
| 4438 | `http1` | `x25519mlkem768` |
| 4439 | `raw` | `secp256r1mlkem768` |
| 4440 | `http1` | `secp256r1mlkem768` |

The smoke path uses insecure client verification and the server's ephemeral
self-signed certificate. Treat it as a development-only workflow.

## Workflow 2: One Manual Benchmark

Use this when you want a controlled single run without a TOML matrix.

Start one server:

```bash
./target/release/server \
    --mode x25519 \
    --proto raw \
    --listen 127.0.0.1:4433
```

Run the client:

```bash
./target/release/runner \
    --server 127.0.0.1:4433 \
    --server-name localhost \
    --proto raw \
    --mode x25519 \
    --payload-bytes 1024 \
    --concurrency 1 \
    --iters 200 \
    --warmup 20 \
    --out results.jsonl
```

Notes:

- `--server-name` defaults to `localhost`
- without `--ca-cert`, verification is insecure
- `--out` is optional; without it, JSONL is written to stdout

## Workflow 3: CA-Verified Benchmarking

Use this for reproducible local baselines and all serious remote runs.

Generate a CA and server certificate:

```bash
just generate-certs
```

Remote examples:

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

Run the client with CA verification enabled:

```bash
./target/release/runner \
    --server 10.0.1.23:4433 \
    --server-name bench.example.com \
    --ca-cert certs/ca.der \
    --proto raw \
    --mode x25519 \
    --payload-bytes 1024 \
    --concurrency 10 \
    --iters 500 \
    --warmup 50 \
    --out results.jsonl
```

Rules to keep straight:

- `server_name` must match the DNS name or IP in the server certificate SAN
- the runner host needs a copy of the matching `ca.der`
- the same `server_name` is also used as the HTTP `Host` header in `http1` mode

## Workflow 4: Matrix Benchmarks

Use a TOML config when you want to sweep payloads, modes, or concurrency.

### Bundled Matrices

- `benchmarks/sanity.toml`: very small local validation matrix
- `benchmarks/baseline.toml`: larger baseline matrix for the default listener layout

Run one:

```bash
./target/release/runner --config benchmarks/sanity.toml
```

### Minimal Example

```toml
[[benchmarks]]
verification.kind = "insecure"
server = "127.0.0.1:4433"
server_name = "localhost"
proto = "raw"
mode = "x25519"
payload = 1024
iters = 100
warmup = 10
concurrency = 1

[[benchmarks]]
verification = { kind = "cacert", path = "certs/ca.der" }
server = "10.0.1.23:4434"
server_name = "bench.example.com"
proto = "http1"
mode = "x25519mlkem768"
payload = 1048576
iters = 200
warmup = 20
concurrency = 10
```

Run it:

```bash
./target/release/runner --config matrix.toml --out results.jsonl
```

Every entry must include a `verification` block.

## Workflow 5: Generated Matrices

Use the generator when writing large matrices by hand becomes error-prone.

Generate a default matrix:

```bash
uv run --script scripts/generate_benchmark_matrix.py --output matrix.toml
```

Generate a remote recurring profile:

```bash
uv run --script scripts/generate_benchmark_matrix.py \
    --profile recurring \
    --host 10.0.1.23 \
    --server-name bench.example.com \
    --ca-cert certs/ca.der \
    --output benchmarks/remote-recurring.toml
```

## Summarizing Results

The repo ships with a JSONL analyzer:

```bash
uv run --script scripts/analyze_results.py results.jsonl
```

Useful variants:

```bash
uv run --script scripts/analyze_results.py results.jsonl --unit us
uv run --script scripts/analyze_results.py results.jsonl --format markdown
uv run --script scripts/analyze_results.py results.jsonl --group-by proto mode
```

See [measurement-methodology.md](measurement-methodology.md) for metric and
schema details.
