# Environment / tooling

## OS & kernel

- Debian (stable) on x86_64
- kernel 6.x

## Required tools

- Rust stable toolchain
- `perf` (Linux perf events)
- `tc` (netem) from `iproute2`
- optional: `tcpdump` for packet-level handshake timing validation
- optional: Valgrind for memory profiling

## VPS setup notes (Hetzner)

- 2 VMs:
  - server VM: runs TLS endpoint
  - client VM: runs benchmark runner
- record:
  - VM type, vCPU count, RAM
  - region / network path characteristics

## Network profiling (optional)

Use `tc netem` on the client VM to emulate:

- RTT, jitter
- packet loss
- bandwidth limits (via `tbf`)
