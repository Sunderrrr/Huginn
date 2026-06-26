"""VM inventory operations: listing, approval, mode toggling, revocation."""

from __future__ import annotations

import uuid

from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enums import ExecMode, VMState
from app.models.mixins import utcnow
from app.models.scheduled_command import ScheduledCommand
from app.models.tag import VMTag
from app.models.task import Task
from app.models.user_vm_access import UserVMAccess
from app.models.vm import VM


class VMError(Exception):
    """Raised on invalid VM state transitions."""


async def get(session: AsyncSession, vm_id: uuid.UUID) -> VM | None:
    return await session.get(VM, vm_id)


async def list_vms(
    session: AsyncSession,
    state: VMState | None = None,
    allowed_vm_ids: list[uuid.UUID] | None = None,
    tag_ids: list[uuid.UUID] | None = None,
) -> list[VM]:
    """List VMs. When ``allowed_vm_ids`` is provided, restrict to those ids.

    ``None`` means unrestricted (admin/agent). An empty list returns nothing.
    ``tag_ids`` further restricts to VMs carrying at least one of those tags.
    """
    stmt = select(VM).order_by(VM.created_at.desc())
    if state is not None:
        stmt = stmt.where(VM.state == state)
    if allowed_vm_ids is not None:
        if not allowed_vm_ids:
            return []
        stmt = stmt.where(VM.id.in_(allowed_vm_ids))
    if tag_ids:
        from app.models.tag import VMTag

        stmt = stmt.where(
            VM.id.in_(select(VMTag.vm_id).where(VMTag.tag_id.in_(tag_ids)))
        )
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


async def delete(session: AsyncSession, vm: VM) -> None:
    """Permanently remove a revoked VM and everything that references it.

    Only revoked VMs can be deleted — this is the final step after the worker's
    credential has already been invalidated. The audit log is intentionally left
    untouched: it is an immutable, tamper-evident record, so the VM's history
    survives the deletion even though the VM row itself is gone.
    """
    if vm.state is not VMState.revoked:
        raise VMError("only revoked VMs can be deleted")
    # Clear dependent rows explicitly so the delete works on any dialect
    # (SQLite doesn't enforce ON DELETE CASCADE by default) and so tasks /
    # schedules — which carry no FK to vms — don't dangle.
    await session.execute(sa_delete(Task).where(Task.vm_id == vm.id))
    await session.execute(sa_delete(VMTag).where(VMTag.vm_id == vm.id))
    await session.execute(sa_delete(UserVMAccess).where(UserVMAccess.vm_id == vm.id))
    await session.execute(
        sa_delete(ScheduledCommand).where(ScheduledCommand.target_vm_id == vm.id)
    )
    await session.delete(vm)
