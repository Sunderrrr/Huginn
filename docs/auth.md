# Authentication & 2FA

Huginn supports several sign-in methods, all resolving to the same
admin / operator / read-only RBAC and the same JWT session.

| Method | First factor | Notes |
|---|---|---|
| Local password | Argon2id | Bootstrap admin + any local users. |
| LDAP / LDAPS | directory bind | Admin-configured; local password tried first. |
| OIDC / SSO | external IdP | Tested with Authentik; MFA delegated to the IdP. |
| Passkey (WebAuthn) | authenticator | **Passwordless** — possession + user verification. |

Second factors (for **local** accounts) layer on top:

| Second factor | How |
|---|---|
| TOTP | Authenticator app (Google Authenticator, Aegis, 1Password…) + single-use backup codes. |
| Passkey | Also usable as a standalone passwordless login. |

> OIDC/LDAP users get their MFA from the identity provider; Huginn's TOTP/passkey
> 2FA applies to local password accounts.

## The login flow

```
POST /api/auth/login {username, password}
   │
   ├─ password disabled (SSO-first)      → 403  (use SSO / passkey)
   ├─ ok, no 2FA                         → { access_token }
   ├─ ok, TOTP enabled                   → { mfa_required, challenge_token }
   └─ ok, admin without a factor         → { mfa_setup_required, challenge_token }
```

The `challenge_token` is a **short-lived, scoped** JWT (`scope=mfa` /
`mfa_setup`, ~5 min). `get_principal` **rejects it on every business endpoint** —
it is only accepted by the `/api/auth/mfa/*` routes. The client exchanges it:

```
POST /api/auth/mfa/verify   (Authorization: Bearer <challenge_token>)
     { "code": "123456" }      # TOTP
     { "backup_code": "…" }     # or a backup code
   → { access_token }
```

Passwordless passkey login is independent and returns an access token directly:

```
POST /api/auth/mfa/webauthn/login/begin   → options
POST /api/auth/mfa/webauthn/login/finish  → { access_token }
```

## Managing your factors

The dashboard **Account › Security** page (any role) lets a user:

- change their password,
- enable/disable **TOTP** (QR + manual key; backup codes shown once),
- regenerate backup codes,
- register/remove **passkeys**.

Admins can clear a locked-out user's factors from **Users → Reset 2FA**
(`POST /api/users/{id}/mfa/reset`); this only ever *removes* factors, so it
can't brick an account.

## Admin-MFA enforcement

When `HUGINN_REQUIRE_ADMIN_MFA=true` (default), a local **admin** with no factor
is handed an `mfa_setup` token at login and must enrol TOTP or a passkey before
receiving a real access token. The setup token cannot reach the business API.

## SSO-first

When OIDC is enabled, the password form is **disabled by default** and re-enabled
only by `HUGINN_ALLOW_PASSWORD_LOGIN=true` (env, the "unsafe" opt-in) or the
admin-set DB settings row. When OIDC is **off**, password login is always
available — you can never be locked out by this flag. The SPA reads
`GET /api/auth/config` (`password_login_enabled`, `webauthn_enabled`,
`oidc_enabled`) to decide which controls to render.

## WebAuthn / passkey constraints

- `HUGINN_WEBAUTHN_RP_ID` **must be a registrable domain, not a bare IP** — the
  hub fails closed otherwise. So passkeys only work over the configured domain
  (e.g. `huginn.example.com`), not the LAN IP. TOTP works everywhere.
- User verification is **required** (PIN/biometric), so a passkey is a genuine
  multi-factor, not mere possession.
- Challenges are server-generated, single-use, and expiring; the signature
  counter is persisted to detect cloned authenticators.

## Security properties

- **TOTP secrets are encrypted at rest** with Fernet, keyed by a dedicated
  `HUGINN_MFA_ENCRYPTION_KEY` (distinct from the JWT and HMAC keys). Backup codes
  are stored only as keyed HMACs and are single-use.
- TOTP verification is replay-guarded (a code can't be reused within its window),
  rate-limited per IP and per user, and constant-time compared.
- Every MFA event (enrol, verify success/failure, disable, passkey add/remove,
  passwordless login, admin reset) is written to the hash-chained audit log.

## Relevant settings

| Env var | Default | Meaning |
|---|---|---|
| `HUGINN_MFA_ENCRYPTION_KEY` | — (required in prod) | Encrypts TOTP secrets. `openssl rand -hex 32`. |
| `HUGINN_REQUIRE_ADMIN_MFA` | `true` | Force local admins to enrol a factor. |
| `HUGINN_ALLOW_PASSWORD_LOGIN` | `false` | Re-enable password login when OIDC is on. |
| `HUGINN_WEBAUTHN_RP_ID` | `HUGINN_DOMAIN` | Passkey relying-party id (registrable domain). |
| `HUGINN_WEBAUTHN_RP_NAME` | `Huginn` | Display name shown by the authenticator. |
| `HUGINN_WEBAUTHN_ORIGIN` | `https://<domain>` | Expected origin for passkey ceremonies. |

OIDC and LDAP have their own settings (admin-editable in **Settings**); see
[security.md](security.md).
