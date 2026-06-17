# Huginn Dashboard

A React (Vite + TypeScript) single-page app for operating the Huginn fleet — a
distinctive "raven control-console" interface (near-black panels, ember signal
accents, HUD telemetry).

## Features
- **Auth** — local password, OIDC/SSO, and LDAP login; two-step **TOTP 2FA** and
  passwordless **passkeys**; an Account/Security page to manage your own password,
  TOTP, and passkeys. RBAC (admin / operator / read-only) reflected in the UI.
- **Home** — fleet-health overview, recent activity, upcoming schedules, stale workers.
- **Fleet view** — live roster with state, mode, installed-vs-target version,
  heartbeat, tags; filter by tag, one-click approve, bulk actions.
- **Node detail** — whitelisted actions, toggle/use unrestricted shell, trigger
  updates, assign tags, revoke, permanently delete, live activity feed.
- **Tags**, **Schedules** (cron/preset commands), **Users** (incl. 2FA reset).
- **Tokens** — enrollment tokens (with the install one-liner) and a rotatable
  **MCP token** with ready-to-paste agent configs.
- **Audit log** — filterable, with hash-chain verification.
- **Settings** — worker version, release repo/SSRF allowlist, SSO/LDAP, notifications.

## Develop

```bash
cp .env.example .env        # VITE_HUB_URL=http://localhost:8000 for the dev hub
npm install
npm run dev                 # http://localhost:5173
```

In dev the hub runs on a different port, so set `VITE_HUB_URL` and allow the dev
origin via `HUGINN_CORS_ORIGINS`. In production `VITE_HUB_URL` is left empty so the
SPA calls the hub **same-origin** (relative `/api`) behind the reverse proxy — no
CORS needed. For OIDC login to return to the SPA, set the hub's
`HUGINN_OIDC_POST_LOGIN_REDIRECT` to the dashboard URL.

## Build

```bash
npm run build       # tsc + vite build -> dist/
npm run lint
```

## Docker

```bash
docker build --build-arg VITE_HUB_URL=https://hub.example.com -t huginn-dashboard .
```

## Stack
React 18 · Vite · TypeScript · React Router · TanStack Query · Framer Motion.
Fonts: Chakra Petch (display) + IBM Plex Mono (data).
