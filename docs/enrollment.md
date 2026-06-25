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

Fields:
- `ttl_seconds` — lifetime in seconds; **`0` = never expires**.
- `max_uses` — how many VMs may enroll with it; **`0` = unlimited** (a reusable
  *join key*).
- `auto_approve` — when `true`, VMs enrolled with this token come up **ACTIVE**
  immediately instead of PENDING (skips step 3). Convenient for unattended /
  bulk provisioning; the tradeoff is that anyone holding the token can add a live
  worker, so keep it secret and revoke it when the rollout is done.

In the dashboard, **Fleet → Add a VM** exposes both as checkboxes ("Reusable
(join key)" and "Auto-approve enrolled VMs") and shows the ready-to-paste install
command for the generated token.

## Bulk / unattended enrollment (Ansible, cloud-init, scripts)

Create **one reusable, auto-approving token** and reuse it for the whole fleet:

```bash
curl -X POST https://<hub>/api/enrollment-tokens \
  -H "Authorization: Bearer <admin-jwt>" -H "Content-Type: application/json" \
  -d '{"label":"ansible","ttl_seconds":0,"max_uses":0,"auto_approve":true}'
```

Then run the same one-liner on every host — no per-VM token, no manual approval:

```bash
curl -fsSLk https://<hub>/install.sh | HUB_URL=https://<hub> TOKEN=<token> bash
```

The installer is idempotent-friendly: it writes `/etc/huginn/worker.json`, so in
an Ansible role gate the `shell`/`command` task on `creates: /etc/huginn/worker.json`
(or `args.creates`) to skip already-enrolled hosts on re-runs. Set `NAME=<inventory_hostname>`
to control the VM name (defaults to the host's hostname). Revoke the token
(`DELETE /api/enrollment-tokens/<id>`) once provisioning is complete.

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
