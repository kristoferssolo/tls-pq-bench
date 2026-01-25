# Implementation strategy

## Phase 1 (required)

Implement `raw` protocol end-to-end with:

- rustls TLS server/client
- KX modes: X25519 vs X25519MLKEM768
- handshake latency + TTLB
- concurrency and NDJSON output

## Phase 2 (optional)

Add `http1` mode using hyper:

- keep the same measurement interface
- reuse the same runner + output format
- run a smaller experiment matrix first (sanity + realism comparison)

### Rule

- Do not block Phase 1 on Phase 2.
