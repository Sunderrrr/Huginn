# Huginn Dashboard

A React (Vite + TypeScript) single-page app for operating the Huginn fleet — a
distinctive "raven control-console" interface (near-black panels, ember signal
accents, HUD telemetry).

## Features
- **Local + OIDC login** (Authentik), with admin / read-only RBAC reflected in the UI.
- **Fleet view** — live roster with state, mode, installed-vs-target worker version,
  heartbeat; one-click approve for pending nodes.
- **Node detail** — run whitelisted actions, toggle (and use) unrestricted shell,
  trigger worker updates, revoke, and a live per-node activity feed.
- **Enrollment tokens** — generate (with the one-line install command), list, revoke.
- **Audit log** — filterable, with hash-chain verification.
- **Settings** — target worker version, release repo, and SSRF allowlist.

## Develop

```bash
cp .env.example .env        # set VITE_HUB_URL to your hub
npm install
npm run dev                 # http://localhost:5173
```

The hub must allow this origin via `HUGINN_CORS_ORIGINS`. For OIDC login to return
to the SPA, set the hub's `HUGINN_OIDC_POST_LOGIN_REDIRECT` to the dashboard URL.

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
