"""Task polling endpoint for dashboard / MCP callers."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_principal, principal_can_access_vm
from app.core.principal import Principal
from app.db import get_session
from app.schemas.task import TaskOut
from app.services import tasks as tasks_service

router = APIRouter(prefix="/api/tasks", tags=["tasks"])


@router.get("/{task_id}", response_model=TaskOut)
async def get_task(
    task_id: uuid.UUID,
    principal: Principal = Depends(get_principal),
    session: AsyncSession = Depends(get_session),
) -> TaskOut:
    task = await tasks_service.get_task(session, task_id)
    if task is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "task not found")
    # IDOR guard: the caller must have access to the task's VM.
    if not await principal_can_access_vm(session, principal, task.vm_id):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "access to this task denied")
    return TaskOut.model_validate(task)
