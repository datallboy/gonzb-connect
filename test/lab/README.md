# Local traversal qualification lab

This lab runs the real coordinator, coturn, Pion ICE stack, DTLS/SCTP
DataChannels, and bounded HTTP framing behind isolated Linux router
namespaces. It uses synthetic data and short-lived test-only credentials.

Requirements: Linux, rootful Docker with Compose, Go, OpenSSL, curl, jq, and at
least 10 GiB of free disk. Packet scanning also requires `tshark`, `rg`, and
`xxd`. The peer containers have no ordinary Docker egress:
their default routes are replaced with their assigned router. Only router
containers retain `NET_ADMIN` and `NET_RAW`; peers drop to UID 1000 before the
test binary starts.

Image builds use the host network for dependency downloads because some VPNs
do not forward Docker bridge traffic. Runtime services never use host
networking.

```sh
test/lab/labctl preflight
test/lab/labctl matrix
test/lab/labctl case symmetric-nat
test/lab/labctl capture turn-udp
test/lab/labctl soak 5m both
test/lab/labctl path-cut 90s
test/lab/labctl status
test/lab/labctl stop
```

Individual cases are `lan-direct`, `independent-nat`, `symmetric-nat`,
`turn-udp`, and `turn-tls`. Results and non-secret state are written below
`.test-state/lab/artifacts/`. Secrets, private keys, TLS material, and canaries
remain below `.test-state/lab/` and are gitignored.

`capture` sends ten deterministic 10 MiB requests and records five interfaces,
so one run may consume approximately 1 GiB. The scanner creates a plaintext
positive-control artifact to prove each canary is detectable, then checks raw
pcaps, reassembled TCP streams, logs, and a logical coordinator database dump.
Use only synthetic lab credentials and do not publish the state directory.

`soak` accepts a duration and `direct`, `turn-tls`, or `both`. It uses 1 MiB
deterministic bodies, verifies every response digest, exercises persistent
gossip, and samples all Compose containers (including the one-off load runner).
Ordinary request channels force a PeerConnection turnover every 256 opens, so a
12-minute run at the default rate covers at least four turnover cycles.
`LAB_GATHER_TIMEOUT`, `LAB_CONNECT_TIMEOUT`, and `LAB_REQUEST_TIMEOUT` may be
set for bounded failure diagnostics; keep the connection and request budgets
larger than the gathering budget.

`path-cut` begins with two independently NATed peers on a direct candidate pair,
drops only their selected peer-to-peer UDP path, and requires ICE restart to
recover through TURN/UDP while the workload remains active. It records status
before the cut, the fault timestamp, status after recovery, router rules and
conntrack state, and the final request result.

Forced TURN cases advertise only the URI being qualified: TURN/UDP for
`turn-udp` and TURN/TLS for `turn-tls`. The diagnostic `turn-tls-blackhole`
policy instead advertises the broad list and silently drops earlier transports
while leaving TLS reachable. It currently fails closed at the gathering
timeout; this is a documented mixed-transport limitation, not a passing matrix
case.

The deterministic container matrix does not replace the later real-Internet
test across independent residential, CGNAT/mobile, and public IPv6 paths.
