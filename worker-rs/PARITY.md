# Parity checklist — Go `worker/` → Rust `worker-rs/`

Chaque comportement du worker Go et son test d'équivalence Rust. Le protocole
wire, le CLI, et le state file sont **strictement identiques** : le hub et
`install.sh` ne voient aucune différence.

| Comportement (Go) | Module Rust | Test Rust |
|---|---|---|
| CLI `enroll\|run\|install-service\|healthcheck\|version` + `--state-dir` | `main.rs` | (compile + smoke `version`/`healthcheck`) |
| Enroll : `HUB_URL`/`TOKEN`/`NAME`/`HUGINN_ALLOW_INSECURE`, arch Go (`amd64`/`arm64`) | `main.rs` | — |
| State `worker.json` : atomique (tmp+rename), 0600, dir 0700, refuse identité vide | `config.rs` | `save_load_roundtrip`, `save_sets_0600_permissions`, `save_refuses_empty_identity`, `test_saved_json_uses_omitempty_shape` |
| `allowed_domains()` (défauts builtin) / `binary_location()` | `config.rs` | `allowed_domains_default`, `binary_location_default` |
| Version build-time (`-ldflags` → `option_env!`) | `config.rs` | — |
| Client : https exigé sauf `allow_insecure`, headers `X-Worker-Id/Secret`, timeout 70s, cap réponse 4 MiB, `APIError` non-2xx | `hubclient.rs` | `new_rejects_plaintext_by_default`, `new_allows_plaintext_when_opted_in`, `heartbeat_sends_auth_headers`, `non2xx_returns_api_error` |
| `null`/vide → `None` (long-poll) | `hubclient.rs` | `poll_next_task_null_means_no_work`, `poll_next_task_returns_task` |
| Exec argv pur, jamais de shell, cap stdout/stderr 1 MiB, timeout kill, exit -1 si signal, argv vide → erreur | `exec.rs` | `test_run_captures_stdout_and_exit_zero`, `test_run_non_zero_exit`, `test_run_timeout`, `test_run_unknown_binary_errors`, `test_run_empty_argv`, `test_no_shell_interpretation`, `test_output_is_capped` |
| Whitelist 5 actions + params en argv séparé + regex `safeName` | `whitelist.rs` | `known_actions_build_argv`, `restart_service_builds_expected_argv`, `restart_service_rejects_injection`, `restart_service_requires_param`, `unknown_action_rejected`, `known_lookup` |
| Idempotence (status/metrics/list_upgradable_packages) | `whitelist.rs` | (+ tests agent) |
| Retry idempotent ×3 backoff cap 8s ; pas de retry mutatif | `agent.rs` | `idempotent_action_retries_then_succeeds`, `idempotent_action_gives_up_after_max_attempts`, `non_idempotent_action_not_retried` |
| Commande libre `sh -c` UNIQUEMENT si exec_mode `unrestricted` observé via heartbeat | `agent.rs` | `dispatch_command_uses_shell_when_unrestricted`, `dispatch_command_refused_when_not_unrestricted` |
| Custom commands (mode `custom`/`unrestricted`), séquentiel fail-fast, sorties étiquetées `$ argv` | `agent.rs` | `custom_command_runs_sequence_in_custom_mode`, `custom_command_stops_at_first_failure`, `custom_command_refused_outside_custom_mode` |
| Dispatch : action/whitelist, action/custom, command, update, uninstall, type inconnu → failed | `agent.rs` | `dispatch_action_uses_whitelist_argv`, `dispatch_unknown_action_fails`, `dispatch_unknown_type_fails` |
| Merge allowlist heartbeat : ajouts seulement + `isSafeReleaseDomain` (pas de localhost/.local/.internal/IP dangereuses) | `agent.rs` | `is_safe_release_domain_rules` |
| Update : allowlist SSRF (URL initiale + **chaque hop de redirect**), https seul, checksums.txt `sha256sum` match basename, sha256 constant-time, chmod 0755, backup .bak, rename atomique, healthcheck `<binary> healthcheck` 30s, rollback + restart | `update.rs` | `test_apply_success_swaps_binary`, `test_apply_checksum_mismatch_keeps_old_binary`, `test_apply_rolls_back_on_health_failure`, `test_apply_rejects_disallowed_redirect_hop`, `test_apply_rejects_disallowed_host`, `test_validate_url`, `test_base_name_matches_go_filepath_base` |
| Uninstall : stop/disable service, rm unit, daemon-reload, rm binaire, rm state dir | `agent.rs` | (chemin de sortie ; exécution réelle non testable en CI) |
| Systemd unit template identique + enable --now | `systemd.rs` | `unit_content_matches_go_template`, `unit_file_written_without_systemd` |
| Sortie propre exit 0 après update (systemd relance le nouveau binaire) | `agent.rs`/`main.rs` | — |
| SIGINT/SIGTERM → arrêt propre du loop | `main.rs` | — |

## Écarts assumés (documentés)

1. **Health-check en timeout** : le Go `CommandContext` kill le processus ; le
   Rust (thread + `recv_timeout`) abandonne sans kill — le binaire
   `healthcheck` répond immédiatement dans tous les cas réels.
2. **Messages d'erreur** : texte différent par endroits (Go fmt.Errorf vs
   thiserror), sémantique et classification identiques (`HostNotAllowed`
   préservé à travers les wraps — équivalent `errors.Is`).
3. **`restart_self`/`state_dir`/`with_http`** : API de parité conservées,
   non appelées en prod (identique au Go).

## Valeurs mesurées

| | Go (CGO_ENABLED=0) | Rust (opt-level=z, LTO, strip) |
|---|---|---|
| binaire linux/arm64 | 6.0 MB | **3.35 MB (−45 %)** |
| RAM idle typique (runtime) | 10–20 MB (GC) | **~1–3 MB (pas de runtime)** |
