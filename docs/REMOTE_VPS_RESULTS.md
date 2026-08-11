# Real-Internet Traversal Results

Date: 2026-08-10 through 2026-08-11

These tests used the production signaling client, Pion ICE/DTLS/SCTP stack,
coordinator, PostgreSQL, coturn, and the four-node GoNZB application harness.
They supplement the deterministic namespace matrix in `LOCAL_LAB_RESULTS.md`.

## Topology

- Coordinator VPS: coordinator, PostgreSQL, coturn, and the existing host Caddy
  reverse proxy.
- Peer VPS: persistent unprivileged test peer.
- NATed client host: peer behind a VPN path and the four-node GoNZB E2E fixture.

The fixture avoids occupied production ports. The coordinator VPS exposes UDP 13478 for
STUN, TCP 15349 for TURN/TLS, and UDP 55000-55099 for relay allocations. The
coordinator backend is loopback-only on port 18082; Caddy publishes only the
narrow health, signaling, and TURN-credential routes. Public admin routes
return 404.

## Transport and fault results

| Case | Result | Evidence |
|---|---:|---|
| Coordinator VPS to peer VPS public direct | 100/100 | direct, 1 ms RTT |
| NATed client/VPN to peer VPS relay | 100/100 | TURN/TLS relay |
| Relay 10 MiB transfers | 2/2 | 20.97 MiB framed each direction |
| Five-minute real relay soak | 422/422 | about 444 MB each direction |
| Coordinator restart | 155/155 | established ICE unchanged; WSS reconnected |
| coturn outage: direct | 171/171 | established direct connection unchanged |
| coturn outage: relay | bounded failure | failed below the 60-second request timeout |
| coturn recovery | 50/50 | fresh TURN/TLS relay |
| Peer VPS restart | 50/50 | same persistent node ID |
| Enrollment revocation | rejected | registration closed and negotiation denied |
| Re-enrollment | 20/20 | new token rebound to the unchanged node identity |

## Four-node GoNZB application soak

The traversal-enabled application ran for about 63 minutes in two contiguous
phases, including an 11-minute interval longer than the configured idle-peer
timeout and a node-C restart. Every final application assertion passed:

- schema 1.1 admission and pool isolation;
- signed push/pull event exchange and exact-once projection;
- ReleaseCard publication, manifest resolution, Newznab search/grab, and cache
  reuse;
- production NNTP fixture ingestion and release formation;
- retained identity and synchronization state after restart; and
- role, activity, pool-health, evidence, and traversal observability.

Final databases held 149-152 accepted federation events per node, including
all three gossip-only qualification events, and nine release sources per node.
All four nodes recorded three successful typed ICE
endpoints. A harness working-directory error briefly started node C with a new
temporary identity; the harness was corrected, node C was immediately restored
with its exact admitted identity, and the remaining run and final assertions
passed.

Pull and push were then disabled on all four nodes while traversal gossip
remained enabled. A new signed tombstone from node A reached B, C, and D in
three seconds. After simultaneous four-node restarts and coordinator hardening,
fresh gossip-only events again reached every peer in 11-13 seconds. This proves
autonomous GoNZBNet state exchange over the reliable traversal gossip channel,
not merely synthetic HTTP echo traffic.

Evidence is gitignored under
`.test-state/remote/artifacts/gonzb-release-soak-20260811T023734Z/`.

## Defects found and fixed

1. Go's HTTP client synthesized Basic authorization from traversal-locator
   userinfo. The dispatch transport now removes only that synthetic header and
   preserves signed GoNZBNet authorization.
2. A base-locator validator rejected query strings on derived signed requests.
   Base locators remain query-free; request URLs now permit queries while
   retaining strict scheme, authority, identity, fragment, and path checks.
3. GoNZB's fixed 15-second outer HTTP timeout could expire before the configured
   25-second traversal negotiation. Traversal-enabled clients now include the
   connection budget in the outer timeout; defaults are 10 seconds for gathering
   and 25 seconds for connection.
4. Reusing one PeerConnection forever retained closed Pion DataChannels. The
   256-channel turnover bound reduced post-fix peer maxima to 63.14 MiB and
   47.99 MiB during 1,030 successful 1 MiB TURN/TLS exchanges.
5. Four simultaneous node restarts caused four concurrent 64 MiB Argon2id
   verifications and OOM-killed the 256 MiB coordinator container. The
   default is now one expensive verification at a time, with a bounded reconnect
   queue and an explicit 1-16 operator override. The repeated four-node restart
   produced zero restarts/OOM events and a 133.5 MiB coordinator footprint;
   gossip-only federation exchange passed afterward without traversal warnings.

## Packet and secret handling

The relay capture transferred recognizable 10 MiB payloads and produced a
99.2 MB coordinator-side pcap. A second capture used real GoNZB ReleaseCards
and manifests.
Raw binary scanning, TCP reassembly, service-log scanning, and logical
coordinator database dumps found no payload/API canary, enrollment token, TURN
credential, SDP candidate, or DTLS fingerprint where prohibited. Post-soak
scans likewise found none of the four raw enrollment tokens in retained
evidence. Candidate addresses were neither displayed nor persisted.

## Remaining release gates

- Commit both repositories, build immutable images, and repeat a clean two-hour
  four-node soak; retain revisions, image digests, resource graphs, and scan
  results. Follow it with a 24-hour release-candidate soak.
- Test one genuinely independent residential/mobile or CGNAT path and native
  public IPv6 when available. The current namespace tests already cover two NAT
  routers, symmetric NAT, TURN/UDP, and TURN/TLS deterministically.
- Resolve or explicitly scope the non-trickle silent-blackhole limitation before
  advertising a broad mixed transport list in production.
- Complete dependency/SBOM review, protocol threat-model review, and an
  independent external security review before removing the experimental label.
