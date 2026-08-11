# GoNZBNet Traversal Qualification Plan

## Recommendation

Use a layered test program. Keep protocol and two-peer tests fast enough for
every pull request, run a privileged Linux network lab nightly, and require a
long soak plus two real Internet access networks before promoting a release.
Docker bridge networking alone is not a sufficient NAT test: the lab must put
each node behind an explicit Linux router namespace where `nftables`,
connection tracking, and `tc netem` define the path.

The existing four-node GoNZBNet E2E workload remains the application-level
oracle. The `gonzb-connect` repository owns the topology, coordinator, coturn,
fault injection, captures, transport load generator, and artifact collection.

## Test topology

Create `test/lab/` with a Compose file and small router image. The router image
needs only `iproute2`, `nftables`, `conntrack`, `tcpdump`, and a shell. Grant
`NET_ADMIN` and `NET_RAW` only to router and capture containers, and run the
lab on a dedicated Linux CI worker.

```text
 node-a --- LAN ----------------------------+
                                             |
 node-b --- nat-b ---------------------------+--- public test network
                                             |       |-- Caddy/coordinator
 node-c --- inner-nat --- outer-nat ---------+       `-- coturn
                                             |
 node-d --- restricted-nat ------------------+
```

Each node network is Docker `internal: true`. Its default route goes through a
dual-homed router container; it must not retain Docker's ordinary outbound NAT
path. Use reserved test address ranges, fixed service addresses, and isolated
Compose project names so captures and firewall rules are deterministic.

The router control script should support these named policies:

- `open`: ordinary routed LAN or public IPv6;
- `home-nat`: endpoint-independent UDP mapping suitable for STUN hole punching;
- `nested-nat`: two independent source-NAT/conntrack layers;
- `turn-udp-only`: reject peer-to-peer UDP but allow STUN/TURN and the coturn
  relay range;
- `turn-tls-only`: reject all client UDP and permit only coordinator HTTPS and
  TURN TLS/TCP;
- `lossy`: configurable latency, jitter, loss, reordering, and bandwidth with
  `tc netem` and TBF;
- `cut-active-path`: install a targeted drop rule after a connection is
  established, forcing ICE restart and relay recovery.

Add an optional symmetric-NAT policy. It is not a release minimum, but it is a
valuable regression case because destination-dependent mappings are where
TURN fallback is most likely to be required.

## KVM/libvirt tier

Use KVM after the namespace matrix is green; it is most valuable where a
separate kernel or machine lifecycle changes the result. Do not spend VM time
repeating ordinary LAN, STUN, and forced-relay cases on every pull request.

The minimum libvirt topology is five small Linux cloud-image guests on three
dedicated, isolated libvirt networks:

```text
 peer-a -- lan-a -- router-a -- test-wan -- services
 peer-b -- lan-b -- router-b -----'
```

`services` runs Caddy, the coordinator, PostgreSQL, and coturn. Each router is
the only dual-homed guest and owns nftables/conntrack policy; each peer has only
its private LAN interface. A sixth router between `router-b` and `test-wan`
creates genuine nested NAT. The test-wan network should not bridge to a host
or production LAN. A temporary libvirt NAT uplink may be attached only during
package/image preparation and removed before qualification.

Use Terraform/libvirt for uniquely prefixed networks, volumes, cloud-init, and
guest lifecycle, and Ansible for pinned packages, binaries, firewall policy,
time synchronization, capture, and artifact collection. Generate a new SSH
CA/key and all coordinator/TURN credentials per run under the gitignored lab
state directory. Pin guest image checksums, allocate sparse overlays, and
destroy only resources carrying the run's explicit prefix.

Run these cases in KVM:

- inner/outer nested NAT with independent conntrack tables;
- peer reboot and persistent-identity recovery;
- interface address/route replacement followed by ICE restart;
- active-path cut and relay recovery;
- coordinator and coturn reboot/outage recovery; and
- `tc netem` loss, delay, reordering, and bandwidth pressure over a full soak.

Provision this tier after the application-level traversal E2E and the
silent-blackhole fallback issue are resolved. The deterministic namespace
harness reaches those code paths faster and with smaller artifacts.

## Common application workload

Run the same deterministic workload in every topology so transport results
are comparable:

1. Start the coordinator, coturn, PostgreSQL, and four nodes with traversal
   enabled and HTTPS retained on the direct-path scenarios.
2. Enroll each persistent node identity using a unique token file.
3. Admit nodes with a signed schema 1.1 invitation and verify the node ID,
   profile, capability, and selected endpoint.
4. Exercise pull, push, and the persistent gossip channel in both directions.
5. Publish a ReleaseCard and a deterministic 10 MiB manifest, search it from a
   consumer, fetch it, verify its digest, then prove a second grab uses cache.
6. Exchange deterministic binary evidence and verify request-author binding.
7. Restart a node and verify its identity and endpoint history survive.
8. Revoke pool membership and the coordinator enrollment separately; prove
   that neither mechanism grants the authority of the other.

Extend GoNZB's existing `scripts/gonzbnet_e2e.sh` with a traversal mode rather
than duplicating admission, publication, search, manifest, and revocation
assertions here. The lab runner should accept `GONZB_REPO` or `GONZB_IMAGE` so
CI can test explicit revisions from both repositories.

## Required matrix

| Case | Network policy | Required result |
|---|---|---|
| LAN direct | two nodes on one routed LAN | `path_type=direct`; no TURN allocation |
| Public IPv6 | globally routed test IPv6 | direct IPv6 candidate pair |
| Independent NAT | separate `home-nat` routers | STUN-derived direct path |
| Nested NAT | inner and outer NAT | direct when the policy permits punching; otherwise bounded relay fallback |
| Forced relay UDP | `turn-udp-only` | `path_type=relay`; requests and gossip succeed |
| Forced relay TLS | `turn-tls-only` | TURN/TLS relay succeeds with client UDP blocked |
| Path failure | direct path, then `cut-active-path` | ICE restart occurs and traffic resumes over relay |
| Coordinator restart | restart during an established transfer window | established PeerConnection remains usable; later negotiations recover |
| coturn outage | direct and relay variants | direct peers continue; relay failure is bounded and recovers after coturn returns |
| Node restart | restart each side independently | persistent identity is unchanged and reconnection succeeds |
| Mixed version | new node plus HTTPS-only node | HTTPS succeeds; traversal-only fails with the documented diagnostic |
| Revocation | token and membership revocation | registration closes; application authorization remains authoritative |

For each case, assert the reported coordinator, ICE state, direct/relay path,
RTT, reconnect count, byte counters, and safe failure code. Also query
`federation_node_endpoints` to verify that candidate addresses were not
persisted.

## Adversarial signaling tests

Add a programmable WSS proxy between clients and the coordinator. It should
be able to duplicate, delay, reorder, drop, and mutate individual envelopes.
The suite must prove rejection of:

- altered SDP with an unchanged hash or signature;
- changed source or target node ID;
- answers swapped between session IDs;
- replayed offers, answers, and connect notifications;
- substituted DTLS fingerprints;
- expired or future-dated envelopes;
- an enrollment key rebound to a different node identity;
- oversized messages, excess registrations, negotiation floods, and offline
  targets.

Add injectable clocks and a coordinator store interface before writing these
tests. That makes expiry, atomic binding, revocation, and restart behavior
deterministic without requiring sleeps or a PostgreSQL instance for every
case. Keep a smaller PostgreSQL integration suite for the real transaction and
row-lock behavior.

## Packet-capture procedure

Generate three unique high-entropy canaries per run:

- `release_canary` inside a ReleaseCard and manifest;
- `api_canary` used as a GoNZB request credential;
- `enrollment_canary` and the returned TURN credential for secret-handling
  checks.

Capture simultaneously at these boundaries:

1. public side of Caddy and coturn;
2. Caddy-to-coordinator backend;
3. coturn relay interfaces;
4. both client-side router interfaces.

Run `tshark` TCP stream reassembly plus a binary-safe exact search over every
pcap. The release and API canaries must be absent everywhere except an
explicit plaintext positive-control artifact. The external capture must also
hide enrollment and TURN credentials. The trusted Caddy-to-coordinator leg is
allowed to contain signed SDP and the enrollment Authorization header because
TLS terminates at Caddy, but it must never contain federation payload or GoNZB
API canaries. TURN/UDP may expose STUN/TURN metadata and the short-lived TURN
username, but never DataChannel plaintext or the TURN credential.

Also scan:

- coordinator, Caddy, coturn, and GoNZB logs;
- a logical dump of the coordinator database;
- GoNZB endpoint/observation rows.

Raw enrollment tokens, TURN credentials, SDP (`a=fingerprint` and
`a=candidate`), application canaries, and API credentials must not occur in
logs or databases. The coordinator database should contain only the token ID,
Argon2id hash, persistent node/key binding, revocation state, and timestamps.

Store pcaps, firewall rules, container logs, node status JSON, resource
samples, and workload digests as CI artifacts. Never upload TLS key logs,
unencrypted production-like credentials, or reusable enrollment tokens.

## Soak and capacity tests

Provide a Go load generator using the real signaling client and ICE manager;
an HTTP benchmark tool cannot exercise PeerConnection reuse, DataChannels, or
ICE restart correctly. Use deterministic bodies and verify the SHA-256 digest
of every response.

Run three tiers:

- pull request: 5-10 minutes, two peers, direct plus forced TURN/TLS;
- nightly: 2 hours, four GoNZB nodes plus lightweight peers, direct and relay;
- release candidate: 24 hours, repeated topology changes and service restarts.

Mix small signed requests, maximum-size event batches, persistent gossip, and
10 MiB manifests. Include bursts at 1, 8, and 32 active peer connections and
deliberately exceed every configured quota.

Acceptance criteria:

- zero silent corruption, cross-node response mix-up, signature bypass, panic,
  or unexpected request failure outside an injected outage;
- no more than 32 pooled PeerConnections and 8 concurrently handled inbound
  channels per peer;
- coordinator limits remain at 2 registrations, 8 active negotiations, 30
  initiations per minute, and 128 KiB per signaling message;
- coturn allocation and bandwidth limits are enforced and visible in lab
  metrics;
- goroutine, file-descriptor, PeerConnection, and coturn allocation counts
  return to baseline after the idle timeout;
- steady-state RSS has no positive long-term slope and post-idle RSS remains
  within 20 percent of the warmed baseline;
- direct-path loss triggers a bounded ICE restart and relay recovery within
  the configured connection timeout plus one coordinator reconnect interval;
- coordinator restart does not interrupt an already-established direct or
  relayed DataChannel.

Collect cgroup CPU/memory, `/proc` descriptor counts, Go runtime metrics,
coordinator counters, coturn allocations/bytes, request latency histograms,
and reconnect/failure counts every five seconds. Compare nightly results to a
stored baseline and fail on statistically meaningful regression rather than a
single latency spike.

## Automation and repository work

Implement in this order:

1. Add coordinator metrics and test seams: injectable clock, store interface,
   registration/session counters, quota rejection counters, and no payload or
   candidate labels.
2. Add a true two-manager integration test that establishes a DataChannel,
   performs concurrent HTTP exchanges, reuses gossip, restarts ICE, and keeps
   the connection alive across coordinator loss.
3. Expand fuzzing for frame sequences, header decoding, envelope mutations,
   locator parsing, and transport-author/body mismatches.
4. Build `test/lab/router`, `test/lab/compose.yml`, and a topology-control
   command with explicit preflight and cleanup.
5. Add the programmable signaling proxy, pcap assertion tool, and positive
   control.
6. Add the traversal mode to the GoNZB four-node E2E fixture and expose its
   existing application workload to this lab.
7. Add the Go transport load generator and resource sampler.
8. Add CI jobs: fast tests on pull requests, the matrix nightly, and a manual
   release workflow that retains signed artifacts and test metadata.
9. Run the release candidate across at least two real consumer NATs, one
   mobile hotspot or CGNAT path, and one public IPv6 path. Container tests are
   deterministic but cannot reproduce every ISP firewall or NAT mapping.
10. Complete dependency review, protocol threat-model review, and independent
    security review before removing the experimental label.

## Release evidence

A traversal release is qualified only when one immutable report identifies
the exact GoNZB and `gonzb-connect` commits, container image digests, Pion and
coturn versions, kernel/firewall versions, random seed, topology policies,
test results, resource graphs, packet-capture assertions, and known failures.
Keep the feature opt-in until that report and the external security review are
complete.
