# gonzb-connect

`gonzb-connect` is the payload-blind signaling and ICE transport companion for
GoNZBNet. It is an independently versioned Go module and Git repository,
published as `github.com/datallboy/gonzb-connect` without coupling the
coordinator binary to the GoNZB application.

The coordinator routes signed, two-minute signaling envelopes over WSS. It
stores only Argon2id enrollment-token hashes and their atomic node bindings; it
does not store SDP, candidates, offers, answers, federation payloads, TURN
credentials, or an offline mailbox. It is payload-blind, not metadata-blind:
while a negotiation is active it can observe both node IDs, complete SDP
(including host/private candidate addresses, ICE credentials, and the DTLS
fingerprint), public source addresses, timing, duration, and signaling byte
counts. coturn can observe short-lived blinded account names, allocation
metadata, endpoints, timing, and relayed byte counts. Neither component can
decrypt the DTLS/SCTP DataChannel payload. WebRTC DataChannels use the signed
SDP's DTLS fingerprint for end-to-end authentication and encryption.

Production deployment is shown in `deploy/compose.yml`: the coordinator,
PostgreSQL, coturn, and Caddy run as separate processes on isolated networks.
Create strong independent secret files and set `DATABASE_URL_FILE`,
`POSTGRES_PASSWORD_FILE`, `ADMIN_TOKEN_FILE`, and `TURN_SHARED_SECRET_FILE` to
their host paths before running Compose. The admin and TURN secrets must be at
least 32 bytes. Replace the example hostnames, mount coturn TLS certificates,
make its private key readable only by the configured coturn UID (`65534`), and
configure provider firewall/allocation/bandwidth limits before exposing it.
Image digests are pinned and should be advanced only through a reviewed
dependency update.

Enrollment verification uses Argon2id with 64 MiB per operation and is limited
to one operation at a time by default. `MAX_CONCURRENT_AUTH` may be set from
1 through 16 only after sizing the coordinator's memory limit accordingly. A
bounded in-memory queue absorbs small simultaneous reconnect bursts; excess
attempts are rejected before Argon2 work begins.

Each GoNZB coordinator entry must set `allowed_ice_server_hosts` to the exact
STUN/TURN hostnames it expects (for this example, `turn.example.com`). A
coordinator response cannot redirect ICE to a different hostname, and public
address resolution is checked again before Pion receives the server list.

Create a one-time node enrollment token with:

```sh
curl -fsS -X POST \
  -H "Authorization: Bearer $(cat /secure/admin-token)" \
  http://127.0.0.1:8081/v1/admin/enrollments
```

The public Caddy route deliberately returns 404 for `/v1/admin/*`; use the
loopback-only port locally or through an authenticated SSH tunnel. Write the
returned enrollment credential directly to the node's secret file. It is
shown only in that response and becomes permanently bound on first use to the
registering GoNZB node ID and public key. Revoke it with
`DELETE /v1/admin/enrollments/{token_id}`.

Coordinator logs must stay at request-metadata level. Do not add request-body,
WebSocket-frame, authorization-header, query-string, SDP, candidate, or TURN
credential logging.

The staged NAT, TURN, packet-capture, adversarial, and soak qualification
process is defined in [`docs/TRAVERSAL_TEST_PLAN.md`](docs/TRAVERSAL_TEST_PLAN.md).
The reproducible namespace harness is documented in
[`test/lab/README.md`](test/lab/README.md), and the latest local evidence and
remaining release gates are recorded in
[`docs/LOCAL_LAB_RESULTS.md`](docs/LOCAL_LAB_RESULTS.md).
The completed two-VPS/NATed-client qualification and four-node application run
are recorded in [`docs/REMOTE_VPS_RESULTS.md`](docs/REMOTE_VPS_RESULTS.md).

## Development and releases

Pull requests and pushes to `main` or `dev` run race tests, the PostgreSQL
enrollment race, vet, staticcheck, govulncheck, and a hardened-container check.
Dependabot watches Go modules, GitHub Actions, and container bases.

Release tags must point to `main` and use `vMAJOR.MINOR.PATCH` or a prerelease
form such as `v0.1.0-rc.1`. A tag publishes Linux amd64/arm64 archives,
checksums, a GitHub release, and a multi-architecture image at
`ghcr.io/datallboy/gonzb-connect`. Create a release tag only after the commit's
CI run succeeds.
