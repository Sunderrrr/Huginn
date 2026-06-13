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
- Local (Argon2id) and OIDC (Authentik) authentication with admin/read-only RBAC.

[Unreleased]: https://github.com/Internal-website/Huginn/commits/main
