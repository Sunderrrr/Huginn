# Contributing to Huginn

Thanks for your interest! Huginn is a remote command-execution system, so we hold
contributions to a high bar for security, clarity, and test coverage.

## Ground rules

- **Open an issue first** for anything non-trivial so we can agree on the approach.
- **Tests are required.** New behaviour ships with tests; bug fixes ship with a
  regression test.
- **Security first.** Never weaken the guarantees in [docs/security.md](docs/security.md):
  auth on every endpoint, timing-safe comparisons, no shell construction on the
  worker, audited unrestricted mode, SSRF allowlist on updates.
- **Conventional, readable commits.** Follow [Semantic Versioning](https://semver.org)
  and update [CHANGELOG.md](CHANGELOG.md) under `Unreleased`.

## Repository layout

`hub/` (Python), `worker/` (Go), `mcp/` (Python), `dashboard/` (React),
`deploy/`, `scripts/`, `docs/`.

## Local development

### Hub & MCP (Python 3.12+)

```bash
cd hub
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
ruff check . && mypy app && pytest
```

### Worker (Go 1.22+)

```bash
cd worker
go vet ./... && go test ./...
make build        # cross-compiled binaries into ./dist
```

### Everything (containers)

```bash
cd deploy && docker compose up --build
```

## CI

Every PR runs: Python lint (`ruff`), type-check (`mypy`), and tests (`pytest`) for
the hub and MCP; Go `vet`, `golangci-lint`, `go test`, and `govulncheck` for the
worker. All must pass before merge.

## Reporting security issues

Please do **not** open a public issue for vulnerabilities. See
[SECURITY.md](SECURITY.md).
