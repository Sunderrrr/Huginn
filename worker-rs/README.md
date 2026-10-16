# worker-rs

The Huginn **worker** — one static Rust binary installed on each managed
machine. It pulls work from the hub over HTTPS, runs it locally, and reports the
result.

**Role:** keep a single outbound HTTPS connection to the hub (NAT-friendly),
execute only what an authenticated, approved request asks for, and self-update
toward the target version. No runtime dependencies.

## Build & test

```bash
cd worker-rs
cargo build --release          # binary: target/release/huginn-worker
cargo test --release           # unit tests (inline #[cfg(test)] modules)
cargo fmt --check && cargo clippy --release -- -D warnings
```

Static musl binaries for release are cross-built by
`.github/workflows/release.yml` (cargo-zigbuild) or locally by
`deploy/build-artifacts.sh`, which the hub serves at `/dist` for self-hosted
installs.

## Module structure

```
worker-rs/
└── src/
    ├── main.rs        # CLI + run loop (enroll / run / install-service / healthcheck / version)
    ├── config.rs      # worker.json state: load/save (atomic, 0600), build version
    ├── hubclient.rs   # HTTPS client: heartbeat, poll, submit result (auth headers)
    ├── agent.rs       # the run loop: poll -> execute -> report
    ├── exec.rs        # execute fixed argv vectors (never sh -c) or gated shell
    ├── whitelist.rs   # built-in actions -> argv vectors + param validation
    ├── update.rs      # self-update: allowlisted download, SHA-256, atomic swap
    ├── systemd.rs     # install/enable the systemd unit
    └── browser/       # browser automation via Obscura (Linux only)
        ├── mod.rs     #   task handler + install discovery (<root>/<version>/obscura)
        ├── process.rs #   `obscura serve` child: ephemeral loopback port, CDP token,
        │              #   process-group kill, memory/connection caps
        ├── cdp.rs     #   minimal CDP client (tokio-tungstenite, ~8 methods)
        ├── steps.rs   #   step parsing + worker-side re-validation
        ├── install.rs #   `browser_install` task: pinned download, SHA-256, strict
        │              #   extraction, license, smoke test
        └── tests.rs / e2e.rs  # unit tests + real-Obscura E2E (HUGINN_OBSCURA_E2E=1)
```

## CLI

The binary exposes a small subcommand set (see `main.rs`):

| Command | Purpose |
|---|---|
| `enroll` | Register with the hub using `HUB_URL` + `TOKEN`; writes `worker.json`. |
| `run` | The main daemon loop (poll / execute / report). |
| `install-service` | Install and enable the systemd unit. |
| `healthcheck` | Liveness probe. |
| `version` | Print the build version. |

`enroll` reads `HUB_URL`, `TOKEN`, `NAME`, and `HUGINN_ALLOW_INSECURE` from the
environment. State lives at `/etc/huginn/worker.json` (mode `0600`).

## Behaviour worth knowing

- **Execution safety** — whitelisted actions map to **fixed argv vectors** run
  directly (`Command::new` + separated args), never `sh -c`. Free-form shell runs
  only in the explicit, admin-enabled, audited **unrestricted** mode; the worker
  enforces this independently of the hub (it refuses a shell command unless it
  has itself observed unrestricted mode via heartbeat).
- **Transport** — HTTPS is required by default; plaintext is only allowed with
  `allow_insecure` (dev).
- **Self-update** — downloads only from the SSRF allowlist, verifies SHA-256, and
  swaps the binary atomically with rollback.
- **Browser automation (Linux only)** — `browser` tasks drive a local
  [Obscura](https://github.com/h4ckf0r0day/obscura) headless browser over CDP
  (loopback-only, random bearer token, own process group, hard kill on every
  exit path). The engine itself is **not embedded**: an admin triggers a
  `browser_install` task, which downloads the hub-pinned release from GitHub
  (SSRF-allowlisted, SHA-256 verified, glibc ≥ 2.35 checked), extracts strictly
  (only the two engine binaries, no links, no traversal) into
  `/opt/huginn/obscura/<version>/` with its Apache-2.0 license, and smoke-tests
  `obscura --version`. Uninstall removes the engine with the rest. Windows and
  non-Linux builds answer "browser not supported on this OS". See
  [../docs/browser.md](../docs/browser.md).

See `PARITY.md` for the behaviour/test map against the reference worker, and
[../CONTRIBUTING.md](../CONTRIBUTING.md) for how to add an action.
