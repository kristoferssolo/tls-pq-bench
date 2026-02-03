# TODO (implementation plan)

## Milestone 1 -- Minimal client/server (raw protocol) \[MUST\]

### Server (`proto=raw`)

- [x] TLS acceptor (rustls)
- [x] Read 8-byte length `N`
- [x] Send `N` bytes deterministic payload

### Client (`proto=raw`)

- [x] Connect TLS
- [x] Send `N`
- [x] Read exactly `N` bytes

## Milestone 2 -- Measurement instrumentation \[MUST\]

- [x] T0 before connect
- [x] T_hs_done after handshake completion
- [x] T_last after last byte read
- [x] Output NDJSON

## Milestone 3 -- KX selection (X25519 vs X25519MLKEM768) \[MUST\]

- [x] rustls provider wiring (`aws_lc_rs` for PQ)
- [ ] negotiated group logging (debug mode)

## Milestone 4 -- Concurrency & runner [MUST]

- [x] tokio-based runner
- [ ] concurrency control and warmup
- [ ] matrix runner over (mode, payload, concurrency)

## Milestone 5 -- HTTP/1.1 mode (hyper) \[OPTIONAL\]

### Server (`proto=http1`)

- [ ] Implement HTTP routes:
  - [ ] `GET /bytes/{n}`
- [ ] Response body = `n` bytes deterministic payload
- [ ] Ensure keep-alive behavior is controlled (prefer 1 request per connection)

### Client (`proto=http1`)

- [ ] `GET /bytes/n` and read full body
- [ ] TTLB measured to last byte of body
- [ ] Keep behavior comparable with raw mode:
  - [ ] 1 request per new TLS connection (for now)

## Milestone 6 -- Compare `raw` vs `http1` [OPTIONAL]

- [ ] Run a small matrix:
  - [ ] payload: 1 KB, 100 KB, 1 MB
  - [ ] concurrency: 1, 10
- [ ] Document overhead differences and why `raw` is used for microbench
