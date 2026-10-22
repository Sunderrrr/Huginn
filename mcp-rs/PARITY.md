# Parity checklist — Python `mcp/` → Rust `mcp-rs/`

Le protocole MCP, les 9 tools, et le contrat d'authentification sont identiques.
Le hub voit exactement les mêmes appels REST (mêmes headers, mêmes corps).

| Comportement (Python) | Module Rust | Test |
|---|---|---|
| Env `HUGINN_MCP_HUB_URL/SERVICE_TOKEN/TRANSPORT/HOST/PORT` | `config.rs` | — |
| Transports : stdio (défaut) et streamable-http stateless json-response | `main.rs` | e2e tests |
| Instructions verbatim (les 4 points "How to use these tools as designed") | `tools.rs::INSTRUCTIONS` | — |
| 9 tools avec signatures et docstrings identiques | `tools.rs` | `protocol::initialize_and_lists_tools` (noms), e2e |
| `_resolve_vm` : UUID → direct ; name exact → case-insensitive ; 0 → 404 ; >1 actifs → 409 ; préférence `state=="active"` | `tools.rs` | `resolve_vm_variants` (5 cas) |
| `list_actions(vm_id)` : `[]` hors mode custom/unrestricted ; filtre par intersection tag_ids ; enabled only ; forme brève {name, description, commands} | `tools.rs` | (couvert par resolve_vm + code reviewed) |
| Auth Bearer : `GET /api/mcp/whoami` avec `X-MCP-Service-Token` + `X-MCP-On-Behalf-Of`, 401 JSON `{"error":"unauthorized"}` sinon | `main.rs`, `auth.rs` | `rejects_unauthenticated_requests`, `invalid_token_is_denied`, `serves_tools_list_for_valid_token` |
| Cache de validation (token, ip) TTL 30s, borne 1024 (clear si plein) | `auth.rs` | `validator_caches_and_caps` |
| Extraction IP : `X-Real-IP` > 1er hop `X-Forwarded-For` > peer | `auth.rs` | `ip_precedence` |
| Forwarding `X-MCP-On-Behalf-Of` + `X-Forwarded-For` sur chaque call métier, `X-MCP-Service-Token` sur tout | `hub_client.rs` | `tools_call_is_forwarded_with_obo_and_ip` |
| Timeout : 10s whoami / 30s calls métier | `config.rs`/`hub_client.rs` | — |
| Erreurs hub → `{"error":{"status","detail"}}` (detail JSON `detail` extrait) | `tools.rs` | unit |
| WebSocket rejeté (le routeur n'accepte que POST /mcp ; GET → 405) | `main.rs` | — |
| Batch JSON-RPC + notifications (pas de réponse, 202 côté HTTP) | `protocol.rs` | `notifications_get_no_response` |

## Écarts assumés (documentés)

1. **`isError`** : quand un tool retourne un dictionnaire `{"error": ...}`, le
   Rust met `isError: true` dans le résultat (le Python laisse `false`). Le
   texte JSON est identique ; les agents interprètent mieux la panne.
2. **Fallback peer IP** : le peer TCP direct n'est pas extrait (axum 0.8 ne
   fait pas d'extracteur optionnel de ConnectInfo) — derrière le Caddy fourni,
   `X-Real-IP` est toujours stampé par l'edge proxy et devient la source
   d'autorité.
3. **JSON-RPC edge cases** : versions de protocole MCP échoïsées sur
   `initialize` (comportement standard des serveurs) ; JSON-RPC 2.0 strict
   (-32700/-32600/-32601/-32602).

## Valeurs mesurées

| | Python (image ~250 MB) | Rust (binaire statique) |
|---|---|---|
| RAM | 41 MB (runtime Python) | ~3–5 MB |
| Image/deploiement | python:3.12 + pip install | un seul binaire |


## Browser automation tools (post-migration, hub `browser` task type)

| Tool | What |
|---|---|
| `browser_engine_check()` | Triggers an immediate Obscura release check (admin) and re-pins the settings on update. |
| `browser_install(vm_id)` | Queues the Obscura engine install (admin-only hub route, hub-pinned version + SHA-256). |
| `browser_start(vm_id, steps, timeout)` | Executes a step sequence on a headless browser (navigate, click, type, eval, wait_for, screenshot, get_text, get_html). |
| `browser_navigate(vm_id, url, timeout)` | Shortcut: navigate + get_text. |
| `browser_screenshot(vm_id, url, quality, timeout)` | Shortcut: navigate + screenshot (JPEG/PNG, optional full page). |
| `browser_pdf(vm_id, url, timeout)` | Shortcut: navigate + pdf (Page.printToPDF, base64 PDF in stdout). |
| `browser_eval(vm_id, url, js, timeout)` | Shortcut: navigate + eval. |
