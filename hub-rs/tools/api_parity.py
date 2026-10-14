#!/usr/bin/env python3
"""API parity harness for the hub-rs migration.

Captures golden HTTP responses from a running hub (Python today, Rust later)
and diffs two captures byte-for-byte (after normalizing volatile fields:
timestamps, ids, tokens).

Usage:
  # capture goldens from the Python hub
  python3 api_parity.py capture --base http://127.0.0.1:8000 \
      --admin-user admin --admin-pass '...' --out golden/python

  # later: capture from hub-rs and diff
  python3 api_parity.py capture --base http://127.0.0.1:8000 \
      --admin-user admin --admin-pass '...' --out golden/rust
  python3 api_parity.py diff golden/python golden/rust

Every request in the sequence exercises one endpoint of API_SURFACE.json
(auth, fleet, execution, worker protocol, settings, tokens...). Volatile
values (uuids, tokens, datetimes) are replaced by stable placeholders so the
diff reflects *shape and semantics*, not randomness.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

PLACEHOLDERS = [
    (
        re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
        "<UUID>",
    ),
    (re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|\+00:00)"), "<TS>"),
    (
        re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?(\+\d{2}:\d{2})?"),
        "<TS>",
    ),
    (
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "<JWT>",
    ),
    (re.compile(r"\b[0-9a-f]{64}\b"), "<HASH64>"),
    # Volatile test fixtures: generated names, urlsafe secrets (dots would only
    # appear inside JWTs, already matched above).
    (re.compile(r"parity-\d+"), "parity-<N>"),
    (re.compile(r"[A-Za-z0-9_-]{40,}"), "<TOKEN>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<IP>"),
]


def normalize(value):
    if isinstance(value, str):
        out = value
        for rx, ph in PLACEHOLDERS:
            out = rx.sub(ph, out)
        return out
    if isinstance(value, list):
        return [normalize(v) for v in value]
    if isinstance(value, dict):
        return {k: normalize(v) for k, v in sorted(value.items())}
    return value


def call(
    base: str,
    method: str,
    path: str,
    token: str | None = None,
    body: dict | None = None,
    extra_headers: dict | None = None,
):
    req = urllib.request.Request(base + path, method=method)
    req.add_header("content-type", "application/json")
    if token:
        req.add_header("authorization", f"Bearer {token}")
    for k, v in (extra_headers or {}).items():
        req.add_header(k, v)
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(req, data=data, timeout=30) as resp:
            raw = resp.read().decode()
            status = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        status = e.code
    except urllib.error.URLError as e:
        raw, status = f"URL_ERROR: {e.reason}", 0
    try:
        parsed = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        parsed = {"_raw": raw[:400]}
    # Raw body is returned so callers can use real tokens; normalization
    # happens only when recording goldens.
    return status, parsed


def capture(base: str, admin_user: str, admin_pass: str, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    results = {}

    def rec(name, method, path, **kw):
        status, body = call(base, method, path, **kw)
        results[name] = {
            "method": normalize(method),
            "path": normalize(path),
            "status": status,
            "body": normalize(body),
        }
        return status, body

    # --- unauthenticated surface (auth gate shapes) -------------------------
    rec("healthz", "GET", "/healthz")
    rec("vms_unauthenticated", "GET", "/api/vms")
    rec("users_unauthenticated", "GET", "/api/users")
    rec("audit_unauthenticated", "GET", "/api/audit")
    rec("settings_unauthenticated", "GET", "/api/settings")
    rec("worker_next_unauthenticated", "GET", "/api/worker/tasks/next")
    rec("worker_heartbeat_unauthenticated", "POST", "/api/worker/heartbeat", body={})
    rec("mcp_whoami_unauthenticated", "GET", "/api/mcp/whoami")
    rec("auth_config", "GET", "/api/auth/config")

    # --- login -------------------------------------------------------------
    status, body = rec(
        "login",
        "POST",
        "/api/auth/login",
        body={"username": admin_user, "password": admin_pass},
    )
    token = (body or {}).get("access_token") if status == 200 else None
    challenge = (body or {}).get("challenge_token")

    if token:
        hdr = {"authorization": f"Bearer {token}"}
        rec("me", "GET", "/api/auth/me", token=token)
        rec("vms_list", "GET", "/api/vms", token=token)
        rec("users_list", "GET", "/api/users", token=token)
        rec("tags_list", "GET", "/api/tags", token=token)
        rec("actions_list", "GET", "/api/actions", token=token)
        rec("schedules_list", "GET", "/api/schedules", token=token)
        rec("enrollment_tokens_list", "GET", "/api/enrollment-tokens", token=token)
        rec("mcp_tokens_list", "GET", "/api/mcp/tokens", token=token)
        rec("settings_get", "GET", "/api/settings", token=token)
        rec("audit_list", "GET", "/api/audit?limit=5", token=token)
        rec("audit_verify", "GET", "/api/audit/verify", token=token)
        # creation + read shapes
        st, tag = rec(
            "tag_create",
            "POST",
            "/api/tags",
            body={"name": f"parity-{int(time.time())}", "color": "#ff0000"},
            token=token,
        )
        if st == 201 and tag:
            rec(
                "tag_update",
                "PUT",
                f"/api/tags/{tag['id']}",
                body={"name": tag["name"], "color": "#00ff00"},
                token=token,
            )
            rec("tag_delete", "DELETE", f"/api/tags/{tag['id']}", token=token)
        st, tok = rec(
            "enrollment_token_create",
            "POST",
            "/api/enrollment-tokens",
            body={"name": "parity"},
            token=token,
        )
        if st == 201 and tok:
            rec(
                "enrollment_token_delete",
                "DELETE",
                f"/api/enrollment-tokens/{tok['id']}",
                token=token,
            )
    else:
        results["_note"] = {
            "detail": "admin login not possible (MFA required?)",
            "challenge_token_present": challenge is not None,
        }
        if challenge:
            results["mfa_setup_required"] = {
                "status": status,
                "body_keys": sorted((body or {}).keys()),
            }

    # --- worker protocol (enroll with a minted token when available) --------
    enroll_token = None
    if token:
        st, tok = call(
            base,
            "POST",
            "/api/enrollment-tokens",
            token=token,
            body={"name": "parity-worker"},
        )
        if st == 201:
            enroll_token = tok.get("token") or tok.get("secret")
            rec(
                "worker_enroll",
                "POST",
                "/api/worker/enroll",
                body={
                    "token": enroll_token or "",
                    "name": "parity-vm",
                    "hostname": "parity",
                    "arch": "amd64",
                    "worker_version": "v1.4.0",
                },
            )
    st, hb = rec(
        "worker_heartbeat_noauth_shape",
        "POST",
        "/api/worker/heartbeat",
        body={"worker_version": "v1.4.0"},
        extra_headers={
            "X-Worker-Id": "00000000-0000-0000-0000-000000000000",
            "X-Worker-Secret": "wrong",
        },
    )
    rec(
        "worker_tls_required",
        "GET",
        "/api/worker/tasks/next?wait=0",
        extra_headers={
            "X-Worker-Id": "00000000-0000-0000-0000-000000000000",
            "X-Worker-Secret": "wrong",
        },
    )

    (out_dir / "responses.json").write_text(
        json.dumps(results, indent=1, sort_keys=True)
    )
    print(f"wrote {len(results)} golden responses to {out_dir}/responses.json")
    return results


def diff(a_dir: Path, b_dir: Path) -> int:
    # Normalize on read too: goldens stay raw, and normalization rules can be
    # tightened without re-capturing both sides.
    a = normalize(json.loads((a_dir / "responses.json").read_text()))
    b = normalize(json.loads((b_dir / "responses.json").read_text()))
    names = sorted(set(a) | set(b))
    bad = 0
    for name in names:
        ra, rb = a.get(name), b.get(name)
        if ra != rb:
            bad += 1
            print(f"DIFF {name}")
            if ra is None or rb is None:
                print(f"   only in {'A' if rb is None else 'B'}")
                continue
            if ra["status"] != rb["status"]:
                print(f"   status: {ra['status']} != {rb['status']}")
            if ra["body"] != rb["body"]:
                print(f"   body A: {json.dumps(ra['body'])[:300]}")
                print(f"   body B: {json.dumps(rb['body'])[:300]}")
    print(f"\n{len(names) - bad}/{len(names)} responses identical")
    return 1 if bad else 0


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("capture")
    c.add_argument("--base", required=True)
    c.add_argument("--admin-user", required=True)
    c.add_argument("--admin-pass", required=True)
    c.add_argument("--out", required=True, type=Path)
    d = sub.add_parser("diff")
    d.add_argument("a", type=Path)
    d.add_argument("b", type=Path)
    args = p.parse_args()
    if args.cmd == "capture":
        capture(args.base, args.admin_user, args.admin_pass, args.out)
    else:
        sys.exit(diff(args.a, args.b))


if __name__ == "__main__":
    main()
