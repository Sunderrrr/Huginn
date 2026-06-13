"""VM inventory operations: listing, approval, mode toggling, revocation."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import ExecMode, VMState
from app.models.mixins import utcnow
from app.models.vm import VM


class VMError(Exception):
    """Raised on invalid VM state transitions."""


async def get(session: AsyncSession, vm_id: uuid.UUID) -> VM | None:
    return await session.get(VM, vm_id)


async def list_vms(session: AsyncSession, state: VMState | None = None) -> list[VM]:
    stmt = select(VM).order_by(VM.created_at.desc())
    if state is not None:
        stmt = stmt.where(VM.state == state)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def approve(session: AsyncSession, vm: VM, *, approved_by: uuid.UUID | None) -> VM:
    if vm.state is VMState.revoked:
        raise VMError("cannot approve a revoked VM")
    if vm.state is VMState.pending:
        vm.state = VMState.active
        vm.approved_at = utcnow()
        vm.approved_by = approved_by
    return vm


async def set_exec_mode(session: AsyncSession, vm: VM, mode: ExecMode) -> VM:
    if vm.state not in (VMState.active, VMState.offline):
        raise VMError("VM must be approved before changing exec mode")
    vm.exec_mode = mode
    return vm


async def revoke(session: AsyncSession, vm: VM) -> VM:
    vm.state = VMState.revoked
    # Invalidate the worker's credential so it can no longer authenticate.
    vm.worker_secret_hash = None
    return vm
