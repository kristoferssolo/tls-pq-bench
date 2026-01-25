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

- key exchange mode: `x25519` | `x25519mlkem768`
- payload size (bytes)
- concurrency level
- number of iterations
- warmup iterations
- CPU pinning info (if used)
- system info (kernel, CPU, governor)
- network profile (baseline / netem parameters)

## Output format

Write newline-delimited JSON (NDJSON) for easy aggregation:

Example record:

```json
{
    "mode": "x25519",
    "payload_bytes": 1024,
    "concurrency": 1,
    "iter": 42,
    "handshake_ms": 8.3,
    "ttlb_ms": 12.1
}
```
