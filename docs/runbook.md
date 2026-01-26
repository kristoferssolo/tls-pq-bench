# Runbook

## 1) Build

```bash
cargo build --release
```

## 2) Start server

Example:

```bash
./target/release/server --mode x25519 --listen 0.0.0.0:4433
```

## 3) Run client benchmark

Example:

```bash
./target/release/runner \
  --server 1.2.3.4:4433 \
  --mode x25519mlkem768 \
  --payload-bytes 1024 \
  --concurrency 10 \
  --iters 500 \
  --warmup 50 \
  --out results.ndjson
```

## 4) Collect perf stats (optional)

Run on the client:

```bash
 perf stat -e cycles,instructions,cache-misses \
   ./target/release/runner ...
```

## 5) Summarize

Use a script to compute p50/p95/p99 from NDJSON.
