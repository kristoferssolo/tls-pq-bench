# Measurement methodology

## Definitions

### Handshake latency

Time from sending `ClientHello` until the TLS session is ready to exchange
application data (handshake completed).

Operationally:

- measured at application level (recommended) using timestamps around the TLS
  connection establishment, OR
- measured via packet capture (tcpdump) by correlating handshake messages.

### TTLB (Time-to-Last-Byte)

Time from starting the request until the last byte of the response body is
received by the client.

Operationally:

- measured in the client application by timestamping:
  - T0: immediately before connect / first write attempt
  - T_end: after reading the full response payload

## Measurement principles

- Prefer monotonic clocks (e.g., `std::time::Instant`)
- Run many iterations; report distribution (p50/p95/p99) not only mean
- Separate:
  - cold handshakes (no resumption)
  - optional: resumed handshakes (if you choose to include later)

## What to record per run

- run identifier (`run_id`)
- protocol mode (`proto`)
- key exchange mode:
  - primary pair: `x25519` | `x25519mlkem768`
  - secondary pair: `secp256r1` | `secp256r1mlkem768`
- payload size (bytes)
- concurrency level
- number of iterations
- warmup iterations
- iteration index (`iteration`)
- timing metrics in nanoseconds: `tcp_ns`, `handshake_ns`, `ttlb_ns`
- CPU pinning info (if used)
- system info (kernel, CPU, governor)
- network profile (baseline / netem parameters)

## Output format

Write newline-delimited JSON (JSONL) for easy aggregation:

Example record:

```json
{
    "run_id": "0195f8cf-2f6f-7e9b-9c52-6e5d6b7d0a10",
    "iteration": 42,
    "proto": "raw",
    "mode": "x25519",
    "payload_bytes": 1024,
    "concurrency": 1,
    "iters": 500,
    "warmup": 50,
    "tcp_ns": 120000,
    "handshake_ns": 8300000,
    "ttlb_ns": 12100000
}
```

The JSONL schema uses nanoseconds in source data. Convert to milliseconds only
when rendering summaries or plots.

The bundled `scripts/analyze_results.py` tool groups records by `proto`, `mode`,
`payload_bytes`, and `concurrency` by default, and summarizes metrics named
`tcp`, `handshake`, and `ttlb` by reading the corresponding `*_ns` fields.
