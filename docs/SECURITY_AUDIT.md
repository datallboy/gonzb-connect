# Pre-Push Security Audit

Date: 2026-08-10

Scope: the `gonzb-connect` protocol, coordinator, TURN credential client,
in-process ICE/DataChannel transport, container deployment, and the GoNZB
request-authentication seam used to bind a DataChannel peer to an application
request author.

## Verdict

No unresolved critical or high-severity code issue was found after remediation.
The repository is suitable for a pre-release push with traversal still
experimental and disabled by default.

This is not yet a production qualification. The local namespace matrix, real
coturn UDP/TLS allocations, five-boundary packet capture, direct-path cut and
relay recovery, hour-long transport/application soaks, four-node GoNZB workload,
restart/revocation faults, and gossip-only exchange now pass. Independent
network/public-IPv6 coverage, immutable release soaks, and external review
remain release gates.
There is also one known transport limitation: a peer fails safely when earlier
advertised ICE transports are silently blackholed, but it does not yet proceed
to an otherwise reachable TURN/TLS candidate before the gathering deadline.

## Resolved findings

| Area | Resolution |
|---|---|
| Transport/application identity confusion | Both parsers now require exactly one quoted `node_id`, `timestamp`, `nonce`, and `signature`; duplicate, unknown, empty, unquoted, and multiple Authorization headers fail. Regression tests cover the former first-value/last-value mismatch. |
| DataChannel memory and goroutine pressure | SCTP messages, JSON headers, frames, queues, channels, request concurrency, request time, and aggregate in-flight request/response bytes are bounded. Sender-side buffered-amount flow control and bounded receiver backpressure prevent large responses from overrunning queues or closing before delivery. Ordinary channels close after one exchange, one inbound gossip channel is allowed per peer, and a PeerConnection is replaced after 256 ordinary outbound channels once active work drains. A post-fix 1,030-request soak kept peer RSS below 64 MiB. |
| ICE/STUN amplification | SDP is parsed before Pion. Only one DataChannel media section, full ICE, one SHA-256 DTLS fingerprint, one ICE credential pair, at most seven candidates per component, and safe candidate address classes are accepted. Duplicate candidates and common virtual bridge interfaces are removed/rejected. This bounds the two-component checklist to at most 98 candidate pairs. |
| Partial non-trickle offers | Candidate gathering must finish before an offer, answer, or restart is signed and sent. A gather timeout is a negotiation failure rather than an unsigned or partial SDP fallback. The default was raised from 3 to 10 seconds after the forced TURN/TLS lab demonstrated that 3 seconds is not reliable. |
| Coordinator authentication DoS | Enrollment syntax is checked before Argon2id. Expensive verification has per-source, per-token, global-per-minute, and global-concurrency limits. The global gate runs first so globally rejected floods cannot allocate keyed limiter buckets. Because each verification uses 64 MiB, the safe default is one at a time; a bounded queue absorbs reconnect bursts and excess work fails before Argon2 begins. A simultaneous four-node restart no longer OOMs a 256 MiB qualification container. Proxy-derived source addresses are used only when explicitly enabled behind the isolated reverse proxy. |
| Traversal/application timeout mismatch | GoNZB's outer HTTP timeout now includes the configured traversal connection budget, preventing a fixed 15-second client deadline from canceling a permitted 25-second ICE negotiation. |
| Signaling/replay exhaustion | Per-node and global message/byte limits apply to every message type. Negotiation limits remain separate. The replay cache has a fixed entry limit and heap-based expiry rather than an unbounded map with a full scan on every message. Invalid clients are disconnected after a bounded count. |
| WebSocket hardening | Browser origins default to deny unless explicitly allowlisted; non-browser clients may omit Origin. Read deadlines, ping/pong liveness, write deadlines, text-only signaling, strict JSON fields, message sizes, and total registrations are enforced. |
| TURN identity exposure | Ten-minute coturn REST usernames use a stable HMAC-derived opaque account suffix instead of the persistent GoNZB node ID. The HMAC-SHA1 credential construction is retained because it is the coturn REST API format, not a general-purpose password hash. |
| Malicious ICE-server redirection | Each coordinator has an explicit one-to-four-host ICE allowlist. URI scheme, query, host, DNS resolution, TTL, credential, and private/special address policy are checked before the list reaches Pion. |
| coturn abuse/deployment | The example sets allocation, per-user, per-session, and total bandwidth quotas; denies loopback, private, link-local, multicast, and other unsafe relay peers; uses a private secret file; separates networks; and exposes coordinator admin routes only on loopback. Images are digest-pinned and the coordinator runs distroless as non-root. |
| Secret and error handling | Coordinator secrets support file injection and minimum lengths, token grammar is exact, sensitive responses are `no-store`, internal handler errors are not returned to peers, public admin paths return 404, and build/deployment secret directories are excluded from Git and Docker contexts. |

## Standards review

- ICE behavior is delegated to pinned Pion WebRTC v4 while local policy
  requires full ICE and caps candidate checklists. This follows RFC 8445's
  full-agent model and its recommendation to limit connectivity checks to 100.
- Host, server-reflexive, and relayed candidates remain supported. TURN over
  UDP, TCP, and TLS is retained, and ICE restart remains enabled.
- TURN URI schemes, ten-minute credential lifetime, permissions, allocation
  quotas, and relayed-peer restrictions follow RFC 8656 and coturn's documented
  REST authentication mode.
- The exact signed SDP contains the DTLS fingerprint. The receiver verifies the
  Ed25519 envelope, expected persistent node key, exact payload hash, replay
  state, SDP policy, and Pion's DTLS fingerprint check before application data
  is accepted.

## Verification completed

- `go test -race ./...`
- `go vet ./...`
- `staticcheck ./...`
- `go mod verify`
- `govulncheck -show verbose ./...`: zero reachable or imported-package
  vulnerabilities; one module-only advisory for the unused
  `golang.org/x/crypto/openpgp` package.
- `gosec ./...`: no unsuppressed findings. Narrow suppressions document
  operator-selected secret/identity paths and coturn's required HMAC-SHA1 REST
  credential construction. Secret reads are size-bounded while reading.
- Protocol and frame fuzz targets: 15-second campaigns with no failure.
- Real in-process Pion integration: two managers, eight concurrent ordinary
  request channels, persistent gossip reuse, and continued traffic after
  signaling loss.
- GoNZB seam tests through a temporary workspace replacement: request auth,
  config, runtime wiring, locator policy, and admission packages pass.
- Compose parses fail-closed with required secret files; Caddy validates; the
  pinned coordinator image builds as `nonroot:nonroot`.
- The deterministic namespace matrix passes LAN direct, independent NAT/STUN,
  forced TURN/UDP, forced TURN/TLS, and an additional symmetric-NAT case.
- Ten deterministic 10 MiB requests passed over TURN/UDP while simultaneous
  captures ran at Caddy public/backend, coturn, and both client routers. Raw
  capture and reassembled TCP streams, service logs, and the coordinator
  database contained none of the prohibited payload or credential canaries.
- Five-minute 1 MiB request soaks passed directly (449/449) and over TURN/TLS
  (428/428), with zero residual in-flight body bytes or channels.
- An hour-long TURN/TLS run passed 5,387/5,387 1 MiB exchanges. The resulting
  closed-DataChannel retention finding was fixed; a 12-minute rerun passed
  1,030/1,030 with peer RSS below 64 MiB across repeated connection turnover.
- Active-path fault injection changed a live independent-NAT path from direct
  to TURN relay through ICE restart with 83/83 successful 1 MiB exchanges.
- The four-node application ran for about 63 minutes across idle expiry and a
  node restart. Signed events, ReleaseCards, manifests, search/grab/cache reuse,
  and gossip-only A-to-B/C/D propagation passed.
- A real 256 MiB coordinator OOM under simultaneous Argon2 authentication was
  reproduced, fixed with serialized verification plus a bounded queue, and
  rerun with zero restart/OOM events and a 133.5 MiB footprint.
- A PostgreSQL integration race concurrently binds one enrollment to different
  node identities and verifies that the row lock admits exactly one winner.
- Docker Scout: 0 critical, high, medium, or low package vulnerabilities in
  the built image.

Current package statement coverage is `client` 21.7%, coordinator 48.2%, ICE
47.1%, and protocol 77.0%. The production coordinator entry point has no
direct coverage; its behavior is primarily covered through coordinator package
tests and Compose qualification. Coverage should continue increasing around
startup/secret handling and the network lab control binary.

## Residual risks and release gates

- A coordinator observes signaling metadata and complete SDP in memory,
  including private candidate addresses and ICE credentials. It can deny or
  delay new negotiations. It cannot alter signed SDP or decrypt established
  DTLS/SCTP payloads without endpoint verification failing.
- A valid coordinator-enrolled peer can initiate a bounded ICE negotiation
  before GoNZB application admission is evaluated. Pool membership,
  invitations, request signatures, capabilities, and revocation remain
  authoritative at the application layer.
- The local namespace matrix proves controlled LAN, two independent NAT
  routers, symmetric NAT, TURN/UDP, TURN/TLS, and direct-to-relay restart
  behavior. It does not prove every ISP NAT, CGNAT/mobile network, or native
  public IPv6 behavior.
- When STUN, TURN/UDP, TURN/TCP, and TURN/TLS are all advertised and the
  earlier transports are silently blackholed, non-trickle gathering does not
  finish even with a 45-second experimental deadline, despite TLS-only passing.
  The default 10-second connection fails closed with no partial signed SDP.
  Resolve with a signed trickle-ICE extension or a standards-reviewed staged
  gathering design.
- Repeat the final suite against committed revisions and immutable images, then
  retain a two-hour and a 24-hour release-candidate soak report.
- Dependency/SBOM review, protocol review, and an independent security
  assessment remain mandatory before removing the experimental label.
