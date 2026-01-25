# Experiment plan

## Independent variables

1. Key exchange group:
   - X25519 (baseline)
   - X25519MLKEM768 (hybrid PQ)
2. Payload size:
   - 1 KB, 10 KB, 100 KB, 1 MB
3. Concurrency:
   - 1, 10, 100
4. Build profile:
   - release
   - optional: `RUSTFLAGS="-C target-cpu=native"`

## Dependent variables (metrics)

- handshake latency (ms)
- TTLB (ms)
- optional: CPU cycles / instructions (perf stat)
- optional: memory (valgrind/massif)
- optional: binary size

## Controls

- same server binary for a given mode
- same client binary for a given mode
- fixed CPU governor (performance) if possible
- fixed network conditions per experiment
- fixed rustls/aws-lc-rs versions
- time sync not required (only client-side monotonic clocks)

## Recommended run matrix

Start small to validate correctness:

- (mode: 2) × (payload: 4) × (concurrency: 2) = 16 cells
Then expand to concurrency=100.

## Statistical reporting

- collect N>=200 iterations per cell (after warmup)
- report: p50, p95, p99, mean, stddev
