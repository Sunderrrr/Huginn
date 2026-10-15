# Blueprint — Migration Rust de Huginn

Objectif : passer en Rust tout ce qui a un intérêt au portage, sans casser le protocole
hub↔worker ni la sécurité. Branche de référence : `main` (aee4be6).

## Décisions structurantes

| Décision | Choix |
|---|---|
| Coexistence Go/Rust | `worker-rs/` (Rust) remplace `worker/` (Go) à la fin ; coexistence pendant la transition |
| Protocole | INCHANGÉ (mêmes endpoints, mêmes JSON, même state file) — install.sh et le hub ne voient aucune différence |
| Version 1ʳᵉ release Rust | `v1.4.0` (protocole identique, pas de bump majeur) |
| Binaires | statiques musl, noms identiques `huginn-worker-linux-{amd64,arm64}` + `checksums.txt` |
| Hub | reste Python pour l'instant ; optimisation long-poll event-driven faite en Python (phase 3) ; portage Rust complet = phase 4 GÉLÉE (re-audit sécurité requis, décision séparée) |

## Steps

### Step 1 — Worker Rust (branche `rust-worker`, worktree `<worktree>/worker-rs-work`)
Portage intégral de `worker/` (Go, 1 400 lignes) vers `worker-rs/` (Rust, tokio).
Parité stricte : CLI (`enroll|run|install-service|healthcheck|version`, `--state-dir`),
env (`HUB_URL, TOKEN, NAME, HUGINN_ALLOW_INSECURE`), state `worker.json` (0600, atomique),
endpoints hub (`/api/worker/enroll|heartbeat|tasks/next?wait=N|tasks/{id}/result`),
headers `X-Worker-Id/X-Worker-Secret`, whitelist 5 actions + idempotence, exec argv pur
(jamais `sh -c` sauf commande libre en mode `unrestricted` observé via heartbeat),
custom commands (mode `custom|unrestricted`, fail-fast, sorties étiquetées),
self-update (allowlist SSRF par hop https, checksums.txt, swap atomique, backup,
healthcheck, rollback), systemd (unit template identique), uninstall, retry backoff
1s×2ᵏ cap 8s cap 3 essais idempotents, merge allowlist (jamais retirer les défauts,
refuser localhost/.local/.internal/169.254.169.254…).
Tests : port de tous les `*_test.go` + clippy clean. Sortie : `cargo test` vert.
Vérif : `cargo build --release && ./target/release/huginn-worker version`

### Step 2 — MCP Rust (branche `rust-mcp`, worktree `<worktree>/mcp-rs-work`) — PARALLÈLE au Step 1
Portage de `mcp/` (Python, 533 lignes) vers `mcp-rs/` avec le SDK officiel `rmcp`.
Contrat strict : 9 tools identiques (list_vms/brief, get_vm_status, list_actions,
execute_action, execute_command, trigger_update, get_task, wait_for_task,
get_audit_log), `_resolve_vm` (id|name, exact→case-insensitive, ambiguïté→409,
préférence active), auth Bearer par utilisateur (validate `/api/mcp/whoami` avec
`X-MCP-Service-Token` + `X-MCP-On-Behalf-Of`, cache (token,ip) TTL 30s max 1024),
forwarding OBO sur chaque call, extraction IP X-Real-IP→XFF→peer, instructions
identiques, env `HUGINN_MCP_HUB_URL/SERVICE_TOKEN/TRANSPORT/HOST/PORT`.
Sortie : `cargo test` vert (tests resolve_vm + cache avec serveur mock).

### Step 3 — Hub : long-poll event-driven (branche `hub-longpoll-events`, worktree `<worktree>/hub-perf-work`) — PARALLÈLE
`hub/app/api/routes/worker.py::next_task` : remplacer le re-poll aveugle de 0,5 s par
une attente réveillée par `task_events` (déjà notifié dans submit_result). Cap 25 s et
commit-entre-checks conservés. Gain : latence de pickup ≤0,5 s → <10 ms ; charge idle
2·N req/s → ~0. Tests pytest adaptés/ajoutés.

### Step 4 — Intégration (moi, après 1–3) — séquentiel
- Cross-compile statique musl amd64+arm64 (musl-tools/zig), tailles binaires comparées
- `deploy/build-artifacts.sh` → build Rust (Go conservé en fallback via flag)
- `.github/workflows/release.yml` → job Rust (rustup + cargo-zigbuild/musl)
- compose : build context `mcp-rs` + Dockerfile Rust multi-stage ; docs (README,
  docs/deployment.md, CHANGELOG v1.4.0) ; revues code-reviewer sur les 3 branches
- Push branches + PRs vers `main`

### Step 5 — Bascule + retrait Go (PR séparée, après validation déployée)
Bump `HUGINN_TARGET_WORKER_VERSION=v1.4.0`, re-test enrollment réel (`install.sh`),
suppression de `worker/` (Go), nettoyage Makefile.

### Phase 4 — Hub en Rust (ACTIVÉE le 2026-10-14, decision of the owner)
Pré-requis : parité sécurité re-auditée (Argon2id, TOTP chiffré, WebAuthn, audit chaîné,
rate limits, OIDC/LDAP), compat migrations Alembic, budget 4–8 semaines. Ne PAS
démarrer sans feu vert explicite.

## Invariants vérifiés après chaque step
1. `cargo test`/`pytest` verts ; 2. aucun changement de protocole wire ;
3. pas de `sh -c` hors commande libre ; 4. allowlist SSRF intacte ;
5. state file lisible par l'ancien ET le nouveau binaire.

## Avancement Phase 4 (hub-rs/)

Méthode : sécurité d'abord, parité prouvée par vecteurs générés depuis le code
Python lui-même (hub-rs/security_vectors.json) — jamais déployé sans parité.

- [x] Inventaire : 7 490 lignes, 54 endpoints, 17 modèles, 14 migrations Alembic
- [x] Schéma canonique : hub-rs/migrations/0001_baseline.sql (dump Alembic head
      n4c5d6e7f8a9, stamp alembic_version → coexistence Python/Rust possible)
- [x] Vecteurs de sécurité Python (argon2id PHC, HMAC-SHA256 secrets, JWT HS256,
      Fernet+key derivation, TOTP RFC6238, audit hash chain)
- [x] config.rs (validate_for_prod fail-closed)
- [ ] security/* (argon2id, secrets, jwt, fernet, totp, audit chain) — en cours
- [ ] db + models (sqlx, 17 tables) — en cours
- [ ] API worker + task events (long-poll event-driven) — en cours
- [ ] API auth/mfa/users/vms/execution/settings/tokens/tags/schedules/events(SSE)
- [ ] WebAuthn (webauthn-rs) — candidat à un 2e lot (TOTP prioritaire)
- [ ] OIDC / LDAP
- [ ] Vérification de parité API (diff de réponses contre le hub Python)
- [ ] Bascule déploiement + retrait hub Python
