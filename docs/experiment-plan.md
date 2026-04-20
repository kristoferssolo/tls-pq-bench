# Experiment plan

Current implementation note: the harness supports four key exchange groups:
`x25519`, `secp256r1`, `x25519mlkem768`, and `secp256r1mlkem768`. If the thesis
write-up wants a simpler narrative, treat the X25519 family as the primary
comparison and the secp256r1 family as a secondary validation set.

## Independent variables

1. Key exchange group:
   - `x25519` (primary classical baseline)
   - `x25519mlkem768` (primary hybrid PQ comparison)
   - `secp256r1` (secondary classical baseline)
   - `secp256r1mlkem768` (secondary hybrid PQ comparison)
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

- primary scope: (mode: 2) × (payload: 4) × (concurrency: 2) = 16 cells
- full four-group scope: (mode: 4) × (payload: 4) × (concurrency: 2) = 32 cells
Then expand to concurrency=100.

## Statistical reporting

- collect N>=200 iterations per cell (after warmup)
- report: p50, p95, p99, mean, stddev
