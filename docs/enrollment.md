# Enrollment

Adding a VM to the fleet is a two-step process: **enroll** (automated) then
**approve** (manual).

## 1. Generate an enrollment token

As an admin (dashboard or API). Tokens are limited-use, time-limited, and
revocable.

```bash
curl -X POST https://<hub>/api/enrollment-tokens \
  -H "Authorization: Bearer <admin-jwt>" \
  -H "Content-Type: application/json" \
  -d '{"label":"batch-2026-06","ttl_seconds":3600,"max_uses":5}'
# => { "token": "<plaintext-shown-once>", ... }
```

The plaintext token is shown **once**; only its HMAC is stored.

## 2. Install on the VM

```bash
# trusted (public domain) cert:
curl -fsSL  https://<hub>/install.sh | HUB_URL=https://<hub> TOKEN=<token> bash
# self-signed / internal CA — add -k to fetch the script (it then installs the
# hub's CA so everything afterwards is verified):
curl -fsSLk https://<hub>/install.sh | HUB_URL=https://<hub> TOKEN=<token> bash
```

The installer detects the architecture, downloads and checksum-verifies the
worker binary **from the hub** (`/dist`), bootstraps trust for a self-signed hub
CA if needed, enrolls, and installs the systemd service.

### What enrollment does
- The worker calls `POST /api/worker/enroll` with the token and host metadata.
- The hub validates the token (timing-safe), consumes one use, creates the VM in
  **PENDING**, and returns a **per-worker secret** (delivered once over TLS).
- The worker stores `{hub_url, worker_id, worker_secret}` at `/etc/huginn/worker.json`
  with `0600` permissions.

A PENDING worker can authenticate but **cannot run any task** — every worker
endpoint rejects non-approved VMs.

## 3. Approve in the dashboard

```bash
curl -X POST https://<hub>/api/vms/<vm-id>/approve -H "Authorization: Bearer <admin-jwt>"
```

The VM moves to **ACTIVE** and begins receiving tasks. Revoking a VM
(`POST /api/vms/<id>/revoke`) sets it to **REVOKED** and invalidates its secret.

> **Why the secret is issued at enrollment, not approval:** delivering it over the
> already-TLS-protected enrollment response avoids a second secret-delivery
> channel and a polling race. Approval remains the human authorization gate — the
> credential is inert until then.
