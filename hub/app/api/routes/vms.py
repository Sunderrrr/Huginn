"""VM inventory and lifecycle endpoints (dashboard / MCP)."""

from __future__ import annotations

import asyncio
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    accessible_vm_ids,
    client_ip,
    get_principal,
    principal_can_access_vm,
    require_admin,
)
from app.core import audit
from app.core.principal import Principal
from app.db import get_session
from app.models.enums import ExecMode, VMState
from app.schemas.tag import TagOut, VMTagsUpdate
from app.schemas.vm import ExecModeUpdate, VMOut
from app.services import tags as tags_service
from app.services import tasks as tasks_service
from app.services import vms as vms_service

router = APIRouter(prefix="/api/vms", tags=["vms"])


async def _load_vm(session: AsyncSession, vm_id: uuid.UUID):  # type: ignore[no-untyped-def]
    vm = await vms_service.get(session, vm_id)
    if vm is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "VM not found")
    return vm


def _vm_out(vm, tags) -> VMOut:  # type: ignore[no-untyped-def]
    out = VMOut.model_validate(vm)
    return out.model_copy(update={"tags": [TagOut.model_validate(t) for t in tags]})


class RevokeRequest(BaseModel):
    uninstall: bool = False


@router.get("", response_model=list[VMOut])
async def list_vms(
    state: VMState | None = None,
    tag_id: list[uuid.UUID] = Query(default=[]),
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> list[VMOut]:
    allowed = await accessible_vm_ids(session, principal)
    vms = await vms_service.list_vms(
        session, state, allowed_vm_ids=allowed, tag_ids=tag_id or None
    )
    tag_map = await tags_service.load_tags_for_vms(session, [v.id for v in vms])
    return [_vm_out(v, tag_map.get(v.id, [])) for v in vms]


@router.get("/{vm_id}", response_model=VMOut)
async def get_vm(
    vm_id: uuid.UUID,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> VMOut:
    if not await principal_can_access_vm(session, principal, vm_id):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "access to this VM denied")
    vm = await _load_vm(session, vm_id)
    tag_map = await tags_service.load_tags_for_vms(session, [vm.id])
    return _vm_out(vm, tag_map.get(vm.id, []))


@router.put("/{vm_id}/tags", response_model=VMOut)
async def set_vm_tags(
    vm_id: uuid.UUID,
    body: VMTagsUpdate,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> VMOut:
    vm = await _load_vm(session, vm_id)
    await tags_service.set_vm_tags(session, vm.id, body.tag_ids)
    await audit.record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="vm_tags_set",
        vm_id=vm.id,
        detail={"tag_count": len(body.tag_ids)},
        source_ip=client_ip(request),
    )
    await session.commit()
    tag_map = await tags_service.load_tags_for_vms(session, [vm.id])
    return _vm_out(vm, tag_map.get(vm.id, []))


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
    body: RevokeRequest | None = None,
    request: Request = None,  # type: ignore[assignment]
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> VMOut:
    vm = await _load_vm(session, vm_id)
    uninstall_result = None

    if body and body.uninstall and vm.state in (VMState.active, VMState.offline):
        # Send uninstall task to the worker first, wait for result (best-effort)
        try:
            task = await tasks_service.create_uninstall_task(
                session,
                vm=vm,
                created_by=str(principal.user.id) if principal.user else "system",
            )
            await session.commit()

            # Poll for the uninstall task result (up to 30s)
            for _ in range(30):
                await asyncio.sleep(1)
                await session.refresh(task)
                if task.status.is_terminal:
                    uninstall_result = task.status.value
                    break
            else:
                uninstall_result = "timeout"
        except vms_service.VMError:
            uninstall_result = "vm_not_active"
        except Exception:
            uninstall_result = "error"

    # Proceed with revocation regardless of uninstall outcome
    vm = await vms_service.revoke(session, vm)
    await audit.record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="revoke",
        vm_id=vm.id,
        detail={"uninstall_result": uninstall_result} if uninstall_result else {},
        source_ip=client_ip(request),
    )
    return VMOut.model_validate(vm)


@router.delete("/{vm_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vm(
    vm_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> None:
    """Permanently delete a revoked VM. The VM must be revoked first."""
    vm = await _load_vm(session, vm_id)
    name = vm.name
    try:
        await vms_service.delete(session, vm)
    except vms_service.VMError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    # Record after the VM row is gone — the audit log keeps its own copy of the id.
    await audit.record(
        session,
        actor_type=principal.actor_type,
        actor_id=principal.actor_id,
        event_type="vm_deleted",
        vm_id=vm_id,
        detail={"name": name},
        source_ip=client_ip(request),
    )
