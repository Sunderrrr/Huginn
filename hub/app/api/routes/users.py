"""User management endpoints (admin only)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, get_principal, require_admin
from app.core import security
from app.core.audit import record
from app.core.principal import Principal
from app.db import get_session
from app.models.enums import ActorType
from app.models.user import User
from app.models.user_vm_access import UserVMAccess
from app.schemas.user import (
    PasswordChange,
    UserCreate,
    UserOut,
    UserUpdate,
    UserVmAccessUpdate,
)
from app.services import mfa as mfa_service
from app.services import users as users_service

router = APIRouter(prefix="/api/users", tags=["users"])


async def _get_user_or_404(user_id: uuid.UUID, session: AsyncSession) -> User:
    user = await users_service.get_by_id(session, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    return user


async def _load_user_vm_ids(session: AsyncSession, user_id: uuid.UUID) -> list[uuid.UUID]:
    result = await session.execute(
        select(UserVMAccess.vm_id).where(UserVMAccess.user_id == user_id)
    )
    return [row[0] for row in result.all()]


async def _set_user_vm_access(
    session: AsyncSession, user_id: uuid.UUID, vm_ids: list[uuid.UUID]
) -> None:
    # Remove existing
    result = await session.execute(
        select(UserVMAccess).where(UserVMAccess.user_id == user_id)
    )
    for access in result.scalars().all():
        await session.delete(access)
    # Add new
    for vm_id in vm_ids:
        session.add(UserVMAccess(user_id=user_id, vm_id=vm_id))


@router.get("", response_model=list[UserOut])
async def list_users(
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> list[UserOut]:
    result = await session.execute(select(User).order_by(User.created_at))
    users = result.scalars().all()
    out = []
    for u in users:
        vm_ids = await _load_user_vm_ids(session, u.id)
        passkeys = await mfa_service.passkey_count(session, u.id)
        out.append(
            UserOut.model_validate(u).model_copy(
                update={"vm_ids": vm_ids, "passkey_count": passkeys}
            )
        )
    return out


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreate,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> UserOut:
    existing = await users_service.get_by_username(session, body.username)
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "username already exists")

    user = User(
        username=body.username,
        email=body.email,
        password_hash=security.hash_password(body.password),
        role=body.role,
        is_active=True,
    )
    session.add(user)
    await session.flush()

    if body.vm_ids:
        await _set_user_vm_access(session, user.id, body.vm_ids)

    await record(
        session,
        actor_type=ActorType.user,
        actor_id=principal.actor_id,
        event_type="user_created",
        detail={"username": user.username, "role": user.role.value},
        source_ip=client_ip(request),
    )
    await session.commit()

    vm_ids = await _load_user_vm_ids(session, user.id)
    return UserOut.model_validate(user).model_copy(update={"vm_ids": vm_ids})


@router.get("/{user_id}", response_model=UserOut)
async def get_user(
    user_id: uuid.UUID,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> UserOut:
    user = await _get_user_or_404(user_id, session)
    vm_ids = await _load_user_vm_ids(session, user.id)
    passkeys = await mfa_service.passkey_count(session, user.id)
    return UserOut.model_validate(user).model_copy(
        update={"vm_ids": vm_ids, "passkey_count": passkeys}
    )


@router.put("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: uuid.UUID,
    body: UserUpdate,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> UserOut:
    user = await _get_user_or_404(user_id, session)
    changes: dict[str, dict[str, object]] = {}
    if body.role is not None:
        changes["role"] = {"old": user.role.value, "new": body.role.value}
        user.role = body.role
    if body.is_active is not None:
        changes["is_active"] = {"old": user.is_active, "new": body.is_active}
        user.is_active = body.is_active
    if body.email is not None:
        user.email = body.email
    if changes:
        await record(
            session,
            actor_type=ActorType.user,
            actor_id=principal.actor_id,
            event_type="user_updated",
            detail={"user_id": str(user_id), **changes},
            source_ip=client_ip(request),
        )
    await session.commit()
    vm_ids = await _load_user_vm_ids(session, user.id)
    return UserOut.model_validate(user).model_copy(update={"vm_ids": vm_ids})


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_user(
    user_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> None:
    user = await _get_user_or_404(user_id, session)
    if str(user.id) == principal.actor_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot deactivate yourself")
    user.is_active = False
    await record(
        session,
        actor_type=ActorType.user,
        actor_id=principal.actor_id,
        event_type="user_deactivated",
        detail={"user_id": str(user_id)},
        source_ip=client_ip(request),
    )
    await session.commit()


@router.put("/{user_id}/password")
async def change_password(
    user_id: uuid.UUID,
    body: PasswordChange,
    request: Request,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    user = await _get_user_or_404(user_id, session)

    # Self-change requires old_password; admin reset does not
    is_self = principal.user and principal.user.id == user_id
    if is_self:
        if not body.old_password:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "old_password required for self-change"
            )
        if not security.verify_password(body.old_password, user.password_hash):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "incorrect old password")
    elif not principal.is_admin:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "admin role required to reset other passwords"
        )

    user.password_hash = security.hash_password(body.new_password)
    await record(
        session,
        actor_type=ActorType.user,
        actor_id=str(principal.user.id if principal.user else "unknown"),
        event_type="password_changed",
        detail={"user_id": str(user_id), "self": bool(is_self)},
        source_ip=client_ip(request),
    )
    await session.commit()
    return {"status": "ok"}


@router.post("/{user_id}/mfa/reset", response_model=UserOut)
async def reset_user_mfa(
    user_id: uuid.UUID,
    request: Request,
    include_passkeys: bool = False,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> UserOut:
    """Admin: clear a locked-out user's TOTP (and optionally their passkeys).

    Only ever removes factors, so it cannot brick an account.
    """
    user = await _get_user_or_404(user_id, session)
    await mfa_service.reset_user_mfa(session, user, include_passkeys=include_passkeys)
    await record(
        session,
        actor_type=ActorType.user,
        actor_id=principal.actor_id,
        event_type="admin_mfa_reset",
        detail={"user_id": str(user_id), "include_passkeys": include_passkeys},
        source_ip=client_ip(request),
    )
    await session.commit()
    vm_ids = await _load_user_vm_ids(session, user.id)
    passkeys = await mfa_service.passkey_count(session, user.id)
    return UserOut.model_validate(user).model_copy(
        update={"vm_ids": vm_ids, "passkey_count": passkeys}
    )


@router.put("/{user_id}/vms", response_model=UserOut)
async def set_user_vms(
    user_id: uuid.UUID,
    body: UserVmAccessUpdate,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> UserOut:
    user = await _get_user_or_404(user_id, session)
    await _set_user_vm_access(session, user.id, body.vm_ids)
    await record(
        session,
        actor_type=ActorType.user,
        actor_id=principal.actor_id,
        event_type="user_vm_access_changed",
        detail={"user_id": str(user_id), "vm_count": len(body.vm_ids)},
        source_ip=client_ip(request),
    )
    await session.commit()
    vm_ids = await _load_user_vm_ids(session, user.id)
    return UserOut.model_validate(user).model_copy(update={"vm_ids": vm_ids})
