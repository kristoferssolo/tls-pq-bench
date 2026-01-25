# Protocol modes

The benchmark supports two application-layer modes over TLS:

## 1) `raw` (custom protocol) -- primary

Goal: minimal overhead and full control over request/response sizes.

### Wire format

Client -> Server:

- 8 bytes unsigned LE: requested response size `N`

Server -> Client:

- `N` bytes payload (deterministic pattern)

Properties:

- easy TTLB measurement (client reads exactly `N`)
- minimal parsing and allocation noise (can pre-allocate)
- stable across HTTP stacks

## 2) `http1` (hyper) -- secondary

Goal: realistic request/response behavior.

Client sends:

- `GET /bytes/N` (or `GET /?n=N`)

Server replies:

- HTTP/1.1 200 with Content-Length = N
- body = N bytes payload (deterministic)

Properties:

- closer to real-world web traffic
- introduces HTTP parsing/headers overhead (acceptable for realism tests)
- TTLB becomes “time to full response body”
