"""Fleet settings: the hub is the source of truth for the target worker version."""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, get_principal, require_admin
from app.core import audit
from app.core.principal import Principal
from app.db import get_session
from app.models.enums import ActorType
from app.schemas.setting import SettingsOut, SettingsUpdate
from app.services import settings_service
from app.services.versioning import SSRFError, validate_release_domain

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("")
async def get_settings_endpoint(
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> dict:
    row = await settings_service.get_settings_row(session)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "settings not initialized")
    full = SettingsOut.model_validate(row).model_dump(mode="json")
    if principal.is_admin:
        return full
    # Non-admins only get fleet fields; SSO/LDAP/notification config is hidden.
    public_keys = {
        "target_worker_version",
        "target_release_repo",
        "allowed_release_domains",
        "auto_update_enabled",
        "updated_at",
    }
    return {k: v for k, v in full.items() if k in public_keys}


@router.put("", response_model=SettingsOut)
async def update_settings_endpoint(
    body: SettingsUpdate,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> SettingsOut:
    row = await settings_service.get_settings_row(session)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "settings not initialized")
    changed = body.model_dump(exclude_none=True)
    # Guard the SSRF allowlist: no IP literals / internal hostnames.
    for domain in changed.get("allowed_release_domains", []):
        try:
            validate_release_domain(domain)
        except SSRFError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    for key, value in changed.items():
        setattr(row, key, value)
    if principal.user is not None:
        row.updated_by = principal.user.id
    # Never write secrets into the audit log.
    _SECRET_KEYS = {"ldap_bind_password", "oidc_client_secret"}
    audit_detail = {
        k: ("***" if k in _SECRET_KEYS else v) for k, v in changed.items()
    }
    await audit.record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="settings_update",
        detail=audit_detail,
        source_ip=client_ip(request),
    )
    return SettingsOut.model_validate(row)


@router.get("/mcp-token")
async def get_mcp_token(
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    """Return the current MCP client token (full value).

    Allowed for admins (dashboard "MCP Token" page) and for the MCP agent itself,
    which authenticates with the service token and needs the client token to
    validate incoming agent requests. Read-only/operator users are rejected.
    """
    if not (principal.is_admin or principal.actor_type is ActorType.agent):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin role required")
    row = await settings_service.get_settings_row(session)
    if row is None or not row.mcp_client_token:
        return {"token": "", "masked": "(not set)"}
    t = row.mcp_client_token
    masked = f"****{t[-8:]}" if len(t) > 8 else "****"
    return {"token": t, "masked": masked}


@router.put("/mcp-token")
async def regenerate_mcp_token(
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    """Generate a new MCP client token and return it (shown once)."""
    row = await settings_service.get_settings_row(session)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "settings not initialized")
    new_token = secrets.token_hex(32)
    row.mcp_client_token = new_token
    await audit.record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="mcp_token_regenerated",
        detail={},
        source_ip=client_ip(request),
    )
    await session.commit()
    return {"token": new_token, "masked": f"****{new_token[-8:]}"}
