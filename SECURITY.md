# Security policy

`gonzb-connect` handles Internet-facing signaling and TURN credentials. Please
do not disclose suspected vulnerabilities in a public issue.

Use GitHub's **Security → Report a vulnerability** form for confidential
reports. Include the affected revision, deployment shape, reproduction steps,
and impact when possible. Do not include live enrollment tokens, TURN
credentials, node private keys, packet captures, or production database dumps.

Security fixes are applied to the latest release line. Traversal remains
experimental and disabled by default until the release gates in
[`docs/SECURITY_AUDIT.md`](docs/SECURITY_AUDIT.md) are complete.
