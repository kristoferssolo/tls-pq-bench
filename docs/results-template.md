# Results template

Use the X25519 family as the primary comparison if needed, but keep space for
the implemented secp256r1 family as a secondary comparison.

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
 | raw | x25519 | 1 |  |  |  |  |
 | raw | secp256r1 | 1 |  |  |  |  |
 | raw | x25519mlkem768 | 1 |  |  |  |  |
 | raw | secp256r1mlkem768 | 1 |  |  |  |  |
 | http1 | x25519 | 1 |  |  |  |  |
 | http1 | secp256r1 | 1 |  |  |  |  |
 | http1 | x25519mlkem768 | 1 |  |  |  |  |
 | http1 | secp256r1mlkem768 | 1 |  |  |  |  |

## TTLB (ms) by payload

 | Payload | Protocol | Mode | Concurrency | p50 | p95 | p99 |
 |---------|----------|------|-------------|-----|-----|-----|
 | 1 KB | raw | x25519 | 1 |  |  |  |
 | 1 KB | raw | secp256r1 | 1 |  |  |  |
 | 1 KB | raw | x25519mlkem768 | 1 |  |  |  |
 | 1 KB | raw | secp256r1mlkem768 | 1 |  |  |  |
 | 1 KB | http1 | x25519 | 1 |  |  |  |
 | 1 KB | http1 | secp256r1 | 1 |  |  |  |
 | 1 KB | http1 | x25519mlkem768 | 1 |  |  |  |
 | 1 KB | http1 | secp256r1mlkem768 | 1 |  |  |  |
 ...

## JSONL schema reminder

Example record:

```jsonl
{"run_id":"0195f8cf-2f6f-7e9b-9c52-6e5d6b7d0a10","iteration":0,"proto":"raw","mode":"x25519","payload_bytes":1024,"concurrency":1,"iters":500,"warmup":50,"tcp_ns":120000,"handshake_ns":500000,"ttlb_ns":650000}
```

The bundled analyzer expects nanosecond metric fields (`tcp_ns`,
`handshake_ns`, `ttlb_ns`) and can render summaries in `ns`, `us`, or `ms`.
