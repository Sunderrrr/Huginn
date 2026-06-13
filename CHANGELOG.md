# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Core iteration: hub (FastAPI + PostgreSQL), Go worker, MCP façade.
- Worker enrollment with one-line installer, manual approval, and per-worker
  secrets.
- Whitelisted action execution and opt-in, audited unrestricted command mode.
- Sync and async (task-queue) execution with polling and dead-lettering.
- Atomic, rollback-safe worker self-update gated by an SSRF allowlist.
- Append-only, hash-chained audit log.
- Local (Argon2id) and OIDC (Authentik) authentication with read-only/operator/
  admin capability tiers.

### Security
- The MCP agent is an operator, not an admin: a leaked service token cannot
  approve VMs, toggle unrestricted mode, manage tokens, or change settings.
- Free-command execution requires operator privileges and is refused locally by
  the worker unless it has observed unrestricted mode (defense in depth).
- The hub fails closed in production when started with placeholder/weak secrets.
- Release-update SSRF allowlist rejects IP literals and internal hostnames; repo
  and version are pattern-validated.
- Audit-log appends are serialized to keep the hash chain consistent under
  concurrency.

[Unreleased]: https://github.com/Internal-website/Huginn/commits/main
