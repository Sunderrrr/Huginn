# Security Policy

## Reporting a vulnerability

Huginn executes commands on remote machines, so we take security seriously. If you
discover a vulnerability, **please report it privately** rather than opening a
public issue.

- Use [GitHub private vulnerability reporting](https://github.com/Sunderrrr/Huginn/security/advisories/new), or
- Email the maintainers (see repository contacts).

Please include reproduction steps and impact. We aim to acknowledge within a few
business days and will coordinate a fix and disclosure timeline with you.

## Supported versions

During the `0.x` series, only the latest minor release receives security fixes.

## Hardening overview

See [docs/security.md](docs/security.md) for the threat model and the controls
built into Huginn (auth, timing-safe comparisons, TLS enforcement, no shell
construction on the worker, audited unrestricted mode, SSRF allowlist, append-only
audit log).
