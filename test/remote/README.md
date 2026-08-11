# Real-Internet traversal fixture

This fixture deploys a temporary coordinator/PostgreSQL/coturn stack on the
coordinator qualification VPS without taking over its existing HTTP, Headscale, or
Tailscale ports. It uses the existing host Caddy for public HTTPS/WSS and binds
the coordinator backend only to loopback.

The selected test ports are UDP 13478 for STUN, TCP 15349 for TURN/TLS, and
UDP 55000-55099 for relay allocations. The advertised relay profile is
intentionally TLS-only while the signed trickle-ICE design remains pending.
The coordinator container is limited to 256 MiB, so it relies on the safe
default of one 64 MiB Argon2id verification at a time. The production 512 MiB
Compose example explicitly permits two. Never raise `MAX_CONCURRENT_AUTH`
without preserving memory headroom and repeating the simultaneous-reconnect
test.

Set `GONZB_CONNECT_LAB_ROOT` to a protected directory on the service VPS. All
runtime state and credentials belong there and must not be committed or copied
into this repository. Back up, validate, and atomically reload the host
Caddyfile when installing or removing the narrow `${CONNECT_HOST}` site block.
Set `CONNECT_HOST` to the test coordinator's public hostname before validating
or reloading Caddy.

The latest completed direct, TURN/TLS, soak, outage, revocation, packet-capture,
and four-node GoNZB application results are in
[`../../docs/REMOTE_VPS_RESULTS.md`](../../docs/REMOTE_VPS_RESULTS.md).

`gonzb-churn-soak` drives a disposable, already-admitted four-node GoNZB E2E
fixture through an idle interval longer than the configured peer timeout,
re-enables push, pull, and gossip, repeatedly exchanges signed events and
manifests, restarts one node, and samples application resources. It expects
five arguments: duration seconds, protected artifact directory, GoNZB root,
generated traversal-config directory, and protected enrollment-response
directory. Enrollment responses and generated configuration must remain under
gitignored test state.
