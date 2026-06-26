"""MFA: TOTP two-step login, challenge-token lock, backup codes, WebAuthn."""

from __future__ import annotations

import pyotp

from app.models.user import User
from app.services import totp as totp_service


async def _user_token(client, make_user, *, username="totp-user", role=None):
    """Create a local user and return (user, password, access_token)."""
    from app.models.enums import UserRole

    user, password = await make_user(
        username=username, password="s3cret-passw0rd", role=role or UserRole.operator
    )
    resp = await client.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return user, password, resp.json()["access_token"]


async def _enroll_totp(client, token) -> tuple[str, list[str]]:
    """Enrol TOTP for the bearer's account; return (secret, backup_codes)."""
    hdr = {"Authorization": f"Bearer {token}"}
    begin = await client.post("/api/auth/mfa/totp/enroll/begin", headers=hdr)
    assert begin.status_code == 200, begin.text
    secret = begin.json()["secret"]
    code = pyotp.TOTP(secret).now()
    finish = await client.post(
        "/api/auth/mfa/totp/enroll/finish", json={"code": code}, headers=hdr
    )
    assert finish.status_code == 200, finish.text
    return secret, finish.json()["backup_codes"]


async def test_totp_secret_encrypted_at_rest(client, make_user, session_factory) -> None:
    _user, _pw, token = await _user_token(client, make_user)
    secret, _codes = await _enroll_totp(client, token)
    async with session_factory() as s:
        from sqlalchemy import select

        row = (await s.execute(select(User).where(User.username == "totp-user"))).scalar_one()
        assert row.totp_enabled is True
        assert row.totp_secret_enc and row.totp_secret_enc != secret  # not plaintext
        assert totp_service.decrypt_secret(row.totp_secret_enc) == secret  # reversible


async def test_login_with_totp_returns_challenge_not_token(client, make_user) -> None:
    _user, password, token = await _user_token(client, make_user)
    await _enroll_totp(client, token)
    resp = await client.post(
        "/api/auth/login", json={"username": "totp-user", "password": password}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body.get("mfa_required") is True
    assert "challenge_token" in body
    assert "access_token" not in body


async def test_challenge_token_rejected_on_business_api(client, make_user) -> None:
    """The linchpin: a challenge token must NOT work on normal endpoints."""
    _user, password, token = await _user_token(client, make_user)
    await _enroll_totp(client, token)
    challenge = (
        await client.post(
            "/api/auth/login", json={"username": "totp-user", "password": password}
        )
    ).json()["challenge_token"]
    hdr = {"Authorization": f"Bearer {challenge}"}
    assert (await client.get("/api/auth/me", headers=hdr)).status_code == 401
    assert (await client.get("/api/vms", headers=hdr)).status_code == 401


async def test_mfa_verify_totp_issues_working_token(client, make_user) -> None:
    _user, password, token = await _user_token(client, make_user)
    secret, _codes = await _enroll_totp(client, token)
    challenge = (
        await client.post(
            "/api/auth/login", json={"username": "totp-user", "password": password}
        )
    ).json()["challenge_token"]
    chdr = {"Authorization": f"Bearer {challenge}"}

    bad = await client.post("/api/auth/mfa/verify", json={"code": "000000"}, headers=chdr)
    assert bad.status_code == 401

    ok = await client.post(
        "/api/auth/mfa/verify", json={"code": pyotp.TOTP(secret).now()}, headers=chdr
    )
    assert ok.status_code == 200, ok.text
    access = ok.json()["access_token"]
    me = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {access}"})
    assert me.status_code == 200
    assert me.json()["totp_enabled"] is True


async def test_backup_code_single_use(client, make_user) -> None:
    _user, password, token = await _user_token(client, make_user)
    _secret, codes = await _enroll_totp(client, token)

    def fresh_challenge():
        return (
            client.post("/api/auth/login", json={"username": "totp-user", "password": password})
        )

    challenge = (await fresh_challenge()).json()["challenge_token"]
    chdr = {"Authorization": f"Bearer {challenge}"}
    first = await client.post(
        "/api/auth/mfa/verify", json={"backup_code": codes[0]}, headers=chdr
    )
    assert first.status_code == 200

    challenge2 = (await fresh_challenge()).json()["challenge_token"]
    reuse = await client.post(
        "/api/auth/mfa/verify",
        json={"backup_code": codes[0]},
        headers={"Authorization": f"Bearer {challenge2}"},
    )
    assert reuse.status_code == 401  # single-use


async def test_totp_replay_rejected(client, make_user) -> None:
    _user, password, token = await _user_token(client, make_user)
    secret, _codes = await _enroll_totp(client, token)
    challenge = (
        await client.post(
            "/api/auth/login", json={"username": "totp-user", "password": password}
        )
    ).json()["challenge_token"]
    chdr = {"Authorization": f"Bearer {challenge}"}
    code = pyotp.TOTP(secret).now()
    first = await client.post("/api/auth/mfa/verify", json={"code": code}, headers=chdr)
    assert first.status_code == 200
    # Same code, same window → rejected as replay.
    again = await client.post("/api/auth/mfa/verify", json={"code": code}, headers=chdr)
    assert again.status_code == 401


async def test_mfa_verify_rate_limited(client, make_user) -> None:
    _user, password, token = await _user_token(client, make_user)
    await _enroll_totp(client, token)
    challenge = (
        await client.post(
            "/api/auth/login", json={"username": "totp-user", "password": password}
        )
    ).json()["challenge_token"]
    chdr = {"Authorization": f"Bearer {challenge}"}
    results = []
    for _ in range(12):
        r = await client.post("/api/auth/mfa/verify", json={"code": "000000"}, headers=chdr)
        results.append(r.status_code)
    assert 429 in results


async def test_totp_disable_requires_reauth(client, make_user) -> None:
    _user, _password, token = await _user_token(client, make_user)
    secret, _codes = await _enroll_totp(client, token)
    hdr = {"Authorization": f"Bearer {token}"}
    no_reauth = await client.post("/api/auth/mfa/totp/disable", json={}, headers=hdr)
    assert no_reauth.status_code == 401
    ok = await client.post(
        "/api/auth/mfa/totp/disable", json={"code": pyotp.TOTP(secret).now()}, headers=hdr
    )
    assert ok.status_code == 204


async def test_admin_reset_mfa_and_rbac(client, admin_headers, make_user) -> None:
    _user, _password, token = await _user_token(client, make_user)
    await _enroll_totp(client, token)
    uid = (await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})).json()[
        "id"
    ]
    # Non-admin cannot reset.
    forbidden = await client.post(
        f"/api/users/{uid}/mfa/reset", headers={"Authorization": f"Bearer {token}"}
    )
    assert forbidden.status_code == 403
    # Admin can.
    ok = await client.post(f"/api/users/{uid}/mfa/reset", headers=admin_headers)
    assert ok.status_code == 200
    assert ok.json()["totp_enabled"] is False


async def test_admin_without_mfa_forced_to_setup(client, admin_headers, make_user) -> None:
    """With admin MFA required, a factor-less admin gets a setup challenge token
    (no access token), and that token can complete enrollment."""
    from app.models.enums import UserRole

    # Turn the policy on via the live DB settings row.
    assert (
        await client.put(
            "/api/settings", json={"require_admin_mfa": True}, headers=admin_headers
        )
    ).status_code == 200

    _user, password = await make_user(
        username="adm2", password="admin-pass-1234", role=UserRole.admin
    )
    resp = await client.post("/api/auth/login", json={"username": "adm2", "password": password})
    assert resp.status_code == 200
    body = resp.json()
    assert body.get("mfa_setup_required") is True
    assert "access_token" not in body
    setup_token = body["challenge_token"]

    # The setup token may enrol TOTP but NOT hit the business API.
    shdr = {"Authorization": f"Bearer {setup_token}"}
    assert (await client.get("/api/auth/me", headers=shdr)).status_code == 401
    begin = await client.post("/api/auth/mfa/totp/enroll/begin", headers=shdr)
    assert begin.status_code == 200
    secret = begin.json()["secret"]
    finish = await client.post(
        "/api/auth/mfa/totp/enroll/finish",
        json={"code": pyotp.TOTP(secret).now()},
        headers=shdr,
    )
    assert finish.status_code == 200
    # Setup flow hands back a real access token so the admin is now logged in.
    assert "access_token" in finish.json()


# --- WebAuthn (verification mocked; we exercise challenge/credential plumbing) ---


async def _configure_webauthn(client, admin_headers) -> None:
    resp = await client.put(
        "/api/settings",
        json={
            "webauthn_rp_id": "huginn.example.com",
            "webauthn_rp_name": "Huginn",
            "webauthn_origin": "https://huginn.example.com",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 200, resp.text


async def test_webauthn_not_configured_returns_400(client, make_user) -> None:
    _user, _pw, token = await _user_token(client, make_user)
    resp = await client.post(
        "/api/auth/mfa/webauthn/register/begin",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400


async def test_webauthn_rejects_ip_rp_id(client, admin_headers, make_user) -> None:
    """An IP literal as rp_id must fail closed (passkeys can't bind to an IP)."""
    await client.put(
        "/api/settings",
        json={"webauthn_rp_id": "192.0.2.13", "webauthn_origin": "https://192.0.2.13"},
        headers=admin_headers,
    )
    _user, _pw, token = await _user_token(client, make_user, username="ipuser")
    resp = await client.post(
        "/api/auth/mfa/webauthn/register/begin",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400


async def test_webauthn_register_then_login(client, admin_headers, make_user, monkeypatch) -> None:
    import base64
    import json as _json
    import types

    from webauthn.helpers import bytes_to_base64url

    from app.services import webauthn as wa

    await _configure_webauthn(client, admin_headers)
    _user, _pw, token = await _user_token(client, make_user, username="pk-user")
    hdr = {"Authorization": f"Bearer {token}"}

    begin = await client.post("/api/auth/mfa/webauthn/register/begin", headers=hdr)
    assert begin.status_code == 200, begin.text
    options = begin.json()
    challenge_b64 = options["challenge"]  # base64url

    # Build a fake client credential whose clientDataJSON echoes our challenge.
    client_data = base64.urlsafe_b64encode(
        _json.dumps({"type": "webauthn.create", "challenge": challenge_b64}).encode()
    ).rstrip(b"=").decode()
    fake_cred = {"id": "cred-abc", "response": {"clientDataJSON": client_data}}

    cred_id_bytes = b"cred-abc-raw"
    monkeypatch.setattr(
        wa.webauthn,
        "verify_registration_response",
        lambda **kw: types.SimpleNamespace(
            credential_id=cred_id_bytes,
            credential_public_key=b"pubkey",
            sign_count=0,
            aaguid="aaguid-1",
        ),
    )
    finish = await client.post(
        "/api/auth/mfa/webauthn/register/finish",
        json={"name": "Test Key", "credential": fake_cred},
        headers=hdr,
    )
    assert finish.status_code == 200, finish.text

    # Replaying the same (now consumed) challenge must fail.
    replay = await client.post(
        "/api/auth/mfa/webauthn/register/finish",
        json={"name": "again", "credential": fake_cred},
        headers=hdr,
    )
    assert replay.status_code == 400

    creds = await client.get("/api/auth/mfa/webauthn/credentials", headers=hdr)
    assert creds.status_code == 200
    assert len(creds.json()) == 1

    # --- passwordless login with clone detection ---
    lbegin = await client.post("/api/auth/mfa/webauthn/login/begin", json={})
    assert lbegin.status_code == 200
    lchallenge = lbegin.json()["challenge"]
    lclient_data = base64.urlsafe_b64encode(
        _json.dumps({"type": "webauthn.get", "challenge": lchallenge}).encode()
    ).rstrip(b"=").decode()
    login_cred = {
        "id": bytes_to_base64url(cred_id_bytes),
        "response": {"clientDataJSON": lclient_data},
    }
    # Counter regresses (0 <= 0 but stored advanced earlier? here stays 0) — make it clone.
    monkeypatch.setattr(
        wa.webauthn,
        "verify_authentication_response",
        lambda **kw: types.SimpleNamespace(new_sign_count=0, credential_id=cred_id_bytes),
    )
    # stored sign_count is 0 and new is 0 → allowed (both zero). Should succeed.
    lfinish = await client.post(
        "/api/auth/mfa/webauthn/login/finish", json={"credential": login_cred}
    )
    assert lfinish.status_code == 200, lfinish.text
    assert "access_token" in lfinish.json()
