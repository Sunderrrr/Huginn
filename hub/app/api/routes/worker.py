"""Worker-facing endpoints. Enrollment is authenticated by the enrollment token;
all other worker endpoints (added later) use the per-worker secret.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import client_ip
from app.config import Settings, get_settings
from app.core import audit
from app.db import get_session
from app.models.enums import ActorType
from app.schemas.enrollment import WorkerEnrollRequest, WorkerEnrollResponse
from app.services import enrollment as enrollment_service

router = APIRouter(prefix="/api/worker", tags=["worker"])


def _enforce_tls(request: Request, settings: Settings) -> None:
    """In prod, refuse plaintext hub<->worker traffic."""
    if not settings.require_tls:
        return
    forwarded = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    scheme = forwarded or request.url.scheme
    if scheme != "https":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "TLS is required for worker communication"
        )


@router.post("/enroll", response_model=WorkerEnrollResponse, status_code=status.HTTP_201_CREATED)
async def enroll(
    body: WorkerEnrollRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> WorkerEnrollResponse:
    _enforce_tls(request, settings)
    try:
        vm, secret = await enrollment_service.enroll_worker(
            session,
            token=body.token,
            name=body.name,
            hostname=body.hostname,
            ip_address=body.ip_address or client_ip(request),
            arch=body.arch,
            os_info=body.os_info,
            worker_version=body.worker_version,
        )
    except enrollment_service.EnrollmentError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc

    await audit.record(
        session,
        actor_type=ActorType.system,
        actor_id="worker",
        event_type="enroll",
        vm_id=vm.id,
        detail={"name": vm.name, "arch": vm.arch.value},
        source_ip=client_ip(request),
    )
    return WorkerEnrollResponse(worker_id=vm.id, worker_secret=secret, state=vm.state.value)
