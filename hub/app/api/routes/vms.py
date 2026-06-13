"""VM inventory and lifecycle endpoints (dashboard / MCP)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip, get_principal, require_admin
from app.core import audit
from app.core.principal import Principal
from app.db import get_session
from app.models.enums import ExecMode, VMState
from app.schemas.vm import ExecModeUpdate, VMOut
from app.services import vms as vms_service

router = APIRouter(prefix="/api/vms", tags=["vms"])


async def _load_vm(session: AsyncSession, vm_id: uuid.UUID):  # type: ignore[no-untyped-def]
    vm = await vms_service.get(session, vm_id)
    if vm is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "VM not found")
    return vm


@router.get("", response_model=list[VMOut])
async def list_vms(
    state: VMState | None = None,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> list[VMOut]:
    vms = await vms_service.list_vms(session, state)
    return [VMOut.model_validate(v) for v in vms]


@router.get("/{vm_id}", response_model=VMOut)
async def get_vm(
    vm_id: uuid.UUID,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> VMOut:
    vm = await _load_vm(session, vm_id)
    return VMOut.model_validate(vm)


@router.post("/{vm_id}/approve", response_model=VMOut)
async def approve_vm(
    vm_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> VMOut:
    vm = await _load_vm(session, vm_id)
    try:
        approved_by = principal.user.id if principal.user else None
        vm = await vms_service.approve(session, vm, approved_by=approved_by)
    except vms_service.VMError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    await audit.record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="approve",
        vm_id=vm.id,
        source_ip=client_ip(request),
    )
    return VMOut.model_validate(vm)


@router.put("/{vm_id}/exec-mode", response_model=VMOut)
async def set_exec_mode(
    vm_id: uuid.UUID,
    body: ExecModeUpdate,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> VMOut:
    vm = await _load_vm(session, vm_id)
    try:
        vm = await vms_service.set_exec_mode(session, vm, body.exec_mode)
    except vms_service.VMError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    # Enabling unrestricted mode is a sensitive, explicitly audited action.
    await audit.record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="toggle_unrestricted",
        vm_id=vm.id,
        detail={
            "exec_mode": body.exec_mode.value,
            "unrestricted": body.exec_mode == ExecMode.unrestricted,
        },
        source_ip=client_ip(request),
    )
    return VMOut.model_validate(vm)


@router.post("/{vm_id}/revoke", response_model=VMOut)
async def revoke_vm(
    vm_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> VMOut:
    vm = await _load_vm(session, vm_id)
    vm = await vms_service.revoke(session, vm)
    await audit.record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="revoke",
        vm_id=vm.id,
        source_ip=client_ip(request),
    )
    return VMOut.model_validate(vm)
