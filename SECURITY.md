# Security Policy

## Supported Versions

Only the latest release of **expose** receives security fixes. Both server and client can self-update (see [docs/auto-update.md](./docs/auto-update.md)), so staying current is the expected deployment mode.

## Reporting a Vulnerability

Please **do not** open a public issue for security problems.

Report vulnerabilities privately via [GitHub Security Advisories](https://github.com/koltyakov/expose/security/advisories/new). If you cannot use GitHub, email the maintainer at the address listed on the [GitHub profile](https://github.com/koltyakov).

When reporting, include:

- Affected component (server, client, WAF, tunnel transport, self-update, …)
- Steps to reproduce or a proof of concept
- Impact assessment (what an attacker gains)

You can expect an acknowledgement within a few days. Once a fix is released, the advisory is published and credit given unless you prefer otherwise.

## Scope

expose is a self-hosted tunnel: the server terminates public TLS traffic and forwards it to clients over an authenticated, encrypted transport. Reports of particular interest:

- Authentication or session bypass (API keys, tunnel passwords, edge cookies)
- WAF bypasses that expose tunneled applications to attack
- Tunnel transport weaknesses (traffic interception, hijacking, cross-tunnel access)
- Self-update integrity issues

The security architecture is documented in [docs/security.md](./docs/security.md).
