# Results template

## Summary (per protocol and mode)

- Environment:
- Commit:
- Rust:
- Kernel:
- VPS type(s):
- Network profile:

## Handshake latency (ms)

 | Protocol | Mode | Concurrency | p50 | p95 | p99 | mean |
 |----------|------|-------------|-----|-----|-----|------|
 | raw | X25519 | 1 |  |  |  |  |
 | raw | X25519MLKEM768 | 1 |  |  |  |  |
 | http1 | X25519 | 1 |  |  |  |  |
 | http1 | X25519MLKEM768 | 1 |  |  |  |  |

## TTLB (ms) by payload

 | Payload | Protocol | Mode | Concurrency | p50 | p95 | p99 |
 |---------|----------|------|-------------|-----|-----|-----|
 | 1 KB | raw | X25519 | 1 |  |  |  |
 | 1 KB | raw | X25519MLKEM768 | 1 |  |  |  |
 | 1 KB | http1 | X25519 | 1 |  |  |  |
 | 1 KB | http1 | X25519MLKEM768 | 1 |  |  |  |
 ...

## JSONL schema reminder

Example record:

```jsonl
{"iteration":0,"proto":"raw","mode":"x25519","payload_bytes":1024,"tcp_ns":120000,"handshake_ns":500000,"ttlb_ns":650000}
```
