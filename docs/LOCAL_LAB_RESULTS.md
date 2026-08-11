# Local Traversal Lab Results

Date: 2026-08-10 through 2026-08-11

These results qualify the deterministic Docker/Linux-network-namespace tier.
They use the production coordinator, Pion ICE/DTLS/SCTP transport, coturn, and
bounded GoNZB HTTP framing rather than mocked network components.

## NAT and transport matrix

| Case | Result | Selected path |
|---|---:|---|
| LAN direct | 100/100 | direct |
| Two independent NAT routers with STUN | 100/100 | direct |
| Symmetric NAT | 100/100 | relay |
| Forced TURN/UDP | 100/100 | relay |
| Forced TURN/TLS | 100/100 | relay |

The release rerun is under
`.test-state/lab/artifacts/release-nat-matrix-20260811T022344Z/`. Forced cases
advertise only the transport under test so the assertion proves the intended
path. TURN/TLS uses a 20-second connection budget because both signed,
non-trickle endpoints must finish gathering before signaling.

## Active-path failure and ICE restart

The path-cut fixture established a direct connection between independent NAT
routers, inserted narrow `nftables` rules that dropped only the selected
peer-to-peer UDP path, and kept signaling and TURN reachable. ICE restarted and
recovered over TURN/UDP while the 1 MiB workload continued:

- 83/83 successful exchanges over 90.032 seconds;
- zero failed exchanges;
- final path `relay`, with one restart on the offerer; and
- 87,072,118 bytes sent and 87,050,400 bytes received.

Evidence is under
`.test-state/lab/artifacts/path-cut-20260811T023658Z-3600036/`.

## Packet-capture qualification

The forced TURN/UDP capture completed 10/10 deterministic 10 MiB
request/response exchanges while recording Caddy's public and backend sides,
coturn, and both client routers. The five pcaps total approximately 979 MiB.
Binary-safe raw scans and `tshark` TCP reassembly found no ReleaseCard/API
canary, enrollment token, or TURN credential where prohibited. Coordinator
logs and its logical database dump contained no raw SDP, candidate, fingerprint,
payload, or secret. Evidence is under
`.test-state/lab/artifacts/capture-turn-udp-20260810T182448Z-3361236/`.

The same scanner also passed against the real four-node GoNZB ReleaseCard,
manifest, search, grab, and cache-reuse capture in
`.test-state/remote/artifacts/gonzb-app-capture-20260811T011742Z/`.

## Soak and memory qualification

| Path | Duration | Result | Notes |
|---|---:|---:|---|
| Direct | 5 minutes | 449/449 | 1 MiB bodies, zero failures |
| TURN/TLS | 5 minutes | 428/428 | 1 MiB bodies, zero failures |
| TURN/TLS | 60 minutes | 5,387/5,387 | about 5.65 GB each direction, zero failures |
| TURN/TLS after turnover fix | 12 minutes | 1,030/1,030 | zero failures across at least four connection turnovers |

The hour run exposed retained closed DataChannels inside a long-lived Pion
PeerConnection: the two peers grew to about 402 MiB and 428 MiB. Ordinary
channels are now capped at 256 per PeerConnection; once active work drains, the
manager replaces the connection. In the post-fix run, the initiator stayed
between 17.09 and 63.14 MiB and the receiver between 9.21 and 47.99 MiB while
file descriptors, threads, active requests, inbound channels, and aggregate
body budgets returned to baseline. Evidence is under
`.test-state/lab/artifacts/soak-20260811T035651Z-3782510/`.

## Verification

The final tree passes `go test -race ./...`, `go vet ./...`, `staticcheck
./...`, module verification, protocol/frame fuzz campaigns from the security
audit, the controlled network matrix, packet scanning, path cut, and the
post-fix soak. Earlier audited builds also passed `gosec`, `govulncheck`, and a
zero-finding Docker Scout scan; those two Go security binaries were not
installed for the final source-only rerun, and no dependency changed afterward.

## Remaining qualification

- The complete multi-transport, non-trickle candidate list can still miss an
  otherwise reachable TURN/TLS path when earlier UDP candidates are silently
  blackholed. Production should advertise a known-working transport set until
  signed trickle ICE or a reviewed staged-gathering extension resolves this.
- Run a final immutable two-hour build soak and a 24-hour release-candidate
  soak after committing both repositories.
- Exercise a genuinely independent residential/mobile or CGNAT network and
  native public IPv6. These are coverage gaps, not reasons to distrust TURN/TLS
  fallback for an initial private deployment.
- Complete independent protocol and external security review before removing
  the experimental label.
