# hub-rs parity notes — auth / MFA / users (`src/routes/authapi/`)

Port of `hub/app/api/routes/{auth,mfa,users}.py` and the authentication /
authorization dependencies of `hub/app/api/deps.py`. This file records where
the Rust port is byte-faithful, where it is deliberately faithful to a Python
*quirk*, and what is deferred to phase 2.

## Endpoint coverage

| route | status |
|---|---|
| `GET /api/auth/config` | ported (exact dict of `auth.auth_config`) |
| `POST /api/auth/login` | ported (local password; LDAP fallback = phase 2) |
| `GET/PUT /api/auth/me` | ported |
| `POST /api/auth/logout` | ported (204 + audit; the Python hub clears no cookie here either) |
| `POST /api/auth/mfa/verify` | ported (TOTP with replay claim + single-use backup codes) |
| `POST /api/auth/mfa/totp/enroll/begin` | ported (pending secret, Fernet-encrypted) |
| `POST /api/auth/mfa/totp/enroll/finish` | ported (backup codes + setup-flow `access_token`) |
| `POST /api/auth/mfa/totp/disable` | ported (re-auth with a *current second factor*) |
| `POST /api/auth/mfa/totp/backup-codes/regenerate` | ported |
| `POST /api/auth/mfa/webauthn/register/{begin,finish}` | **501** (phase 2) |
| `POST /api/auth/mfa/webauthn/login/{begin,finish}` | **501** (phase 2) |
| `GET/PUT/DELETE /api/auth/mfa/webauthn/credentials[...]` | ported (pure credential CRUD) |
| `GET/POST /api/users` | ported |
| `GET/PUT/DELETE /api/users/{user_id}` | ported |
| `PUT /api/users/{user_id}/password` | ported (self-change checks `old_password`, admin reset does not) |
| `POST /api/users/{user_id}/mfa/reset` | ported (`include_passkeys` query) |
| `PUT /api/users/{user_id}/vms` | ported (`user_vm_access` replace) |
| `GET /api/auth/oidc/{login,callback}` | **not ported** (phase 2) |

## Decisions

### WebAuthn: ceremonies 501 (phase 2), credential management ported

`services/webauthn.py` wraps **py_webauthn** for the ceremony crypto:
registration options/attestation verification (CBOR attestation objects, COSE
public keys) and assertion verification (authenticator data, signature over
clientDataJSON, sign-counter clone detection). Porting that faithfully requires
the `webauthn-rs` stack (or a hand-rolled CBOR/COSE verifier) — a large,
security-critical surface that cannot be parity-tested against the Python
implementation in this pass. The four ceremony endpoints therefore answer:

```json
501 {"detail": "webauthn not yet implemented in hub-rs"}
```

coherently: the challenge/credential *ceremonies* are the only gap. The three
**credential management** endpoints (list / rename / delete passkeys) are plain
CRUD over `webauthn_credentials` and are fully ported, so passkeys registered
through the Python hub stay manageable (the databases are interchangeable by
design). `DELETE` keeps the Python lockout guard: a passwordless user with no
TOTP may not delete their last passkey. `GET /api/auth/config` still reports
`webauthn_enabled` with the exact Python computation (rp_id + origin from the
DB row with env fallback), so the SPA contract is unchanged; the passkey button
itself will only work once phase 2 lands.

Phase 2 checklist: add `webauthn-rs`, port `services/webauthn.py` (rp_config,
challenge persistence via `models::webauthn::create_challenge`/`consume_challenge`
— already ported), then replace the four `WEBAUTHN_UNIMPLEMENTED` bodies.

### OIDC and LDAP: not ported (phase 2)

`/api/auth/oidc/*` needs an HTTP client (discovery, code exchange) and JWKS
verification; the `login` LDAP fallback needs an LDAP client. Neither dependency
exists in the crate yet. `/api/auth/config` and the `login` SSO-first policy
(OIDC enabled ⇒ password login 403 unless re-enabled) are ported exactly.

### Auth middleware (`deps.py`) 

`get_principal`, `require_admin`, `require_operator`, `rate_limit_exec`,
`client_ip`, `challenge_user` and `enrolling_actor` live in
`src/routes/authapi/mod.rs` and mirror `hub/app/api/deps.py` /
`hub/app/api/routes/mfa.py`, including the MCP service-token branch
(`X-MCP-Service-Token`, `X-MCP-On-Behalf-Of`, timing-safe compare, token
`allowed_ip` CIDR matching, `last_used_at` bump) and the rejection of `mfa` /
`mfa_setup` scoped tokens on the business API. `RateLimiter` is the fixed-window
`core/ratelimit.py` port with both `allow()` and the non-consuming `check()`
(its twin in `routes/worker.rs` predates it and lacks `check()`; a follow-up
should share one).

### Faithful quirks kept on purpose

- `passkey_count` is `0` in the `create_user` / `update_user` / `set_user_vms`
  responses: the Python handlers build `UserOut.model_validate(user).model_copy(
  update={"vm_ids": ...})` and never set the counter. `get_user`, `list_users`,
  `me` and `reset_user_mfa` do report the live count — exactly like Python.
- An email-only `PUT /api/users/{id}` records **no** audit entry (only
  `role`/`is_active` go into `changes`), and `PUT /api/auth/me` with an empty
  `email` string clears it to NULL (`body.email or None`).
- Error precedence follows FastAPI: body validation (422) happens before the
  handler only where Python has no dependency (`login`, `mfa/verify`, the
  webauthn *login* endpoints); where Python declares `Depends(get_principal)` /
  `enrolling_actor`, the 401/403 comes first. (Note `routes/worker.rs` chose the
  opposite order for its validation — that file is owned elsewhere.)
- 422 bodies use the shared `ApiError` shape `{"detail": "<message>"}` instead
  of FastAPI's `detail`-as-list; likewise the `WWW-Authenticate: Bearer` header
  on 401 is not emitted because `ApiError` cannot carry headers. Codes, detail
  strings and JSON shapes of all successful responses match.

### Small SQL owned by this module

The `models::user` patch API cannot express two Python writes
(`COALESCE` keeps NULL out): `set_user_email` (clearing the profile email) and
`set_pending_totp_secret` (`totp_enroll_begin` stores the pending secret without
enabling TOTP). Both are single `UPDATE`s in `authapi/mod.rs`.

## Tests

- Pure/unit: response shapes (UserOut, TokenResponse, LoginChallengeResponse,
  AuthConfigResponse, WebAuthnCredentialOut), the login second-factor decision,
  TOTP verification at a frozen time (±1 step window, replay claims), backup
  code format/hashing, RBAC matrix (`require_admin` 403 for an operator),
  token errors (expired/malformed/wrong scope), rate limiter, `client_ip` and
  the MCP IP allow-list, pydantic-bound validations.
- HTTP-level (lazy pool, no DB): 422/429 paths, 401 for missing/invalid/mfa
  scoped tokens, 501 on the WebAuthn login ceremony, dependency-before-body
  precedence.
- `live_tests` (skipped unless `HUGINN_TEST_DATABASE_URL` is set, like
  `db.rs`/`models::live_tests`): full login → setup challenge → TOTP enrollment
  → verify → replay rejection → backup-code single use, and the users CRUD /
  RBAC / password / deactivation flows, verified against PostgreSQL 18.
