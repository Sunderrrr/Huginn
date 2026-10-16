# Third-Party Notices

This project includes software developed by third parties:

---

## Obscura

- **Project**: [Obscura — open-source headless browser for AI agents](https://github.com/h4ckf0r0day/obscura)
- **Version**: v0.2.4
- **License**: Apache-2.0
- **Usage**: Optional browser automation component downloaded to managed VMs (not embedded in any Huginn binary). The binary is installed at `/opt/huginn/obscura/<version>/` on the VM with a copy of this notice and the Apache-2.0 license text.
- **Source**: https://github.com/h4ckf0r0day/obscura/releases/tag/v0.2.4
- **Copyright**: Copyright (c) the Obscura authors.

---

## Rust ecosystem

The following crates are used as build dependencies (not distributed as
separate works — compiled into the Huginn binaries, all Apache-2.0 or
MIT/Apache-2.0 dual-licensed):

tokio, axum, sqlx, reqwest, serde, serde_json, sha2, hmac, argon2, base64,
regex, chrono, uuid, thiserror, tracing, tracing-subscriber, tokio-tungstenite
(Linux only), flate2, tar (Linux only), and their transitive dependencies.
See each crate's `Cargo.toml` for the full dependency graph and individual
licenses.

---

Apache License, Version 2.0 text: https://www.apache.org/licenses/LICENSE-2.0
