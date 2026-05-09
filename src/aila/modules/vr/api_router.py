"""FastAPI router for the vulnerability research module.

Mounted at ``/vr`` by ``VRModule.route_specs()``. Every endpoint uses
``DataEnvelope[T]`` response models, the platform's authenticated rate
limiter, and require_auth so unauthenticated callers get HTTP 401 before
they can reach project / finding state.

Server-side pagination uses ``offset`` and ``limit`` query parameters per
D-26; total counts go in ``meta`` via ``PaginatedMeta``.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func as sa_func
from sqlmodel import select

from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope, PaginatedMeta
from aila.platform.contracts.auth import AuthContext, require_auth
from aila.platform.uow import UnitOfWork

from .contracts import (
    DisclosureStatus,
    TargetClass,
    VRFinding,
    VRProjectCreate,
    VRProjectStatus,
    VRProjectSummary,
)

__all__ = ["DisclosureUpdate", "create_vr_router"]

_log = logging.getLogger(__name__)


class DisclosureUpdate(BaseModel):
    """PATCH body for advancing a finding's coordinated-disclosure status."""

    model_config = ConfigDict(extra="forbid")

    disclosure_status: DisclosureStatus
    vendor_contact: str | None = Field(default=None, max_length=512)
    assigned_cve_id: str | None = Field(default=None, max_length=32)
    patch_version: str | None = Field(default=None, max_length=64)


def _summary_from_record(record: Any, finding_count: int = 0) -> VRProjectSummary:
    """Project a ``VRProjectRecord`` row to the public ``VRProjectSummary``."""
    return VRProjectSummary(
        id=record.id,
        name=record.name,
        cve_id=record.cve_id,
        status=VRProjectStatus(record.status),
        target_class=TargetClass(record.target_class),
        finding_count=finding_count,
        created_at=record.created_at.isoformat() if record.created_at else None,
    )


def _finding_from_record(record: Any) -> VRFinding:
    """Project a ``VRFindingRecord`` row to the public ``VRFinding``."""
    from .contracts import CrashType, PoCResult

    poc: PoCResult | None = None
    if record.poc_code:
        poc = PoCResult(
            code=record.poc_code,
            language=record.poc_language or "python",
            asan_report=record.asan_report or "",
        )
    crash_type = CrashType(record.crash_type) if record.crash_type else None
    return VRFinding(
        id=record.id,
        project_id=record.project_id,
        crash_type=crash_type,
        crash_signature=None,
        root_cause=record.root_cause or "",
        vulnerable_function=record.vulnerable_function or "",
        poc=poc,
        advisory_id=None,
        disclosure_status=DisclosureStatus(record.disclosure_status),
        vendor_contact=record.vendor_contact,
        reported_at=record.reported_at.isoformat() if record.reported_at else None,
        embargo_until=record.embargo_until.isoformat() if record.embargo_until else None,
        assigned_cve_id=record.assigned_cve_id,
        patch_version=record.patch_version,
    )


def create_vr_router() -> APIRouter:
    """Construct and return the VR module APIRouter."""
    router = APIRouter(tags=["vr"])

    def _team_filter(stmt: Any, model: Any, auth: AuthContext) -> Any:
        if auth.team_id is not None:
            stmt = stmt.where(model.team_id == auth.team_id)
        return stmt

    def _require_project_ownership(project: Any, auth: AuthContext) -> None:
        if auth.team_id is not None and getattr(project, "team_id", None) != auth.team_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Project is not owned by your team.",
            )

    @router.get(
        "/projects",
        response_model=DataEnvelope[list[VRProjectSummary]],
        summary="List VR projects.",
    )
    @limiter.limit("60/minute")
    async def list_projects(
        request: Request,
        auth: AuthContext = Depends(require_auth),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=20, ge=1, le=100),
    ) -> DataEnvelope[list[VRProjectSummary]]:
        del request
        from .db_models import VRFindingRecord, VRProjectRecord

        async with UnitOfWork() as uow:
            count_stmt = _team_filter(
                select(sa_func.count()).select_from(VRProjectRecord),
                VRProjectRecord, auth,
            )
            total = (await uow.session.exec(count_stmt)).one()

            page_stmt = _team_filter(
                select(VRProjectRecord), VRProjectRecord, auth,
            ).order_by(
                VRProjectRecord.created_at.desc()
            ).offset(offset).limit(limit)
            rows = (await uow.session.exec(page_stmt)).all()

            counts_by_project: dict[str, int] = {}
            if rows:
                project_ids = [r.id for r in rows]
                count_rows = (await uow.session.exec(
                    select(VRFindingRecord.project_id, sa_func.count())
                    .where(VRFindingRecord.project_id.in_(project_ids))
                    .group_by(VRFindingRecord.project_id)
                )).all()
                counts_by_project = {pid: int(n) for pid, n in count_rows}

        items = [_summary_from_record(r, counts_by_project.get(r.id, 0)) for r in rows]
        meta = PaginatedMeta(total=int(total), offset=offset, limit=limit).model_dump()
        return DataEnvelope(data=items, meta=meta)

    @router.post(
        "/projects",
        response_model=DataEnvelope[VRProjectSummary],
        status_code=status.HTTP_201_CREATED,
        summary="Create a new VR project.",
    )
    @limiter.limit("30/minute")
    async def create_project(
        request: Request,
        body: VRProjectCreate,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRProjectSummary]:
        from aila.api.deps import get_task_queue

        from .db_models import VRProjectRecord
        from .workflow.task import run_vr_nday

        integration: dict[str, Any] = {}
        async with UnitOfWork() as uow:
            if body.system_id is not None:
                from aila.storage.db_models import ManagedSystemRecord

                sys_stmt = select(ManagedSystemRecord).where(
                    ManagedSystemRecord.id == body.system_id,
                )
                if auth.team_id is not None:
                    sys_stmt = sys_stmt.where(
                        ManagedSystemRecord.team_id == auth.team_id,
                    )
                system = (await uow.session.exec(sys_stmt)).first()
                if system is None:
                    raise HTTPException(
                        status_code=404,
                        detail=f"System {body.system_id} not found.",
                    )
                integration = {
                    "name": system.name, "host": system.host,
                    "username": system.username, "port": system.port,
                    "private_key_path": system.private_key_path,
                    "password_secret_id": system.password_secret_id,
                }

            record = VRProjectRecord(
                name=body.name,
                cve_id=body.cve_id,
                target_class=body.target.target_class.value,
                target_path=body.target.path,
                binary_id=body.target.binary_id,
                patched_path=body.patched_target.path if body.patched_target else None,
                patched_binary_id=(
                    body.patched_target.binary_id if body.patched_target else None
                ),
                source_available=body.target.source_available,
                context_notes=body.context_notes,
                status=VRProjectStatus.CREATED.value,
                team_id=auth.team_id,
            )
            uow.session.add(record)
            await uow.session.commit()
            await uow.session.refresh(record)

        # Dispatch the durable n-day workflow through the task queue. The
        # API request must not block on the multi-hour pipeline; the task
        # wrapper owns DurableStateMachine execution.
        task_queue = get_task_queue("vr", request)
        handle = await task_queue.submit(
            track="vr",
            fn=run_vr_nday,
            kwargs={
                "project_id": record.id,
                "name": body.name,
                "cve_id": body.cve_id,
                "target_path": body.target.path,
                "target_class": body.target.target_class.value,
                "binary_id": body.target.binary_id,
                "patched_path": body.patched_target.path if body.patched_target else None,
                "patched_binary_id": (
                    body.patched_target.binary_id if body.patched_target else None
                ),
                "source_available": body.target.source_available,
                "context_notes": body.context_notes,
                "system_id": body.system_id,
                "integration": integration,
            },
            user_id=auth.user_id,
            group_id=auth.role,
            team_id=auth.team_id,
        )

        return DataEnvelope(
            data=_summary_from_record(record),
            meta={"task_id": handle.task_id, "status": "queued"},
        )

    @router.get(
        "/projects/{project_id}",
        response_model=DataEnvelope[VRProjectSummary],
        summary="Get VR project details.",
    )
    @limiter.limit("60/minute")
    async def get_project(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRProjectSummary]:
        del request
        from .db_models import VRFindingRecord, VRProjectRecord

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(VRProjectRecord).where(VRProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"VR project {project_id!r} not found.")
            _require_project_ownership(project, auth)

            finding_count = int((await uow.session.exec(
                select(sa_func.count()).select_from(VRFindingRecord).where(
                    VRFindingRecord.project_id == project_id
                )
            )).one())

        return DataEnvelope(data=_summary_from_record(project, finding_count))

    @router.get(
        "/projects/{project_id}/findings",
        response_model=DataEnvelope[list[VRFinding]],
        summary="List findings for a VR project.",
    )
    @limiter.limit("60/minute")
    async def list_findings(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> DataEnvelope[list[VRFinding]]:
        del request
        from .db_models import VRFindingRecord, VRProjectRecord

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(VRProjectRecord).where(VRProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"VR project {project_id!r} not found.")
            _require_project_ownership(project, auth)

            total = int((await uow.session.exec(
                select(sa_func.count()).select_from(VRFindingRecord).where(
                    VRFindingRecord.project_id == project_id
                )
            )).one())

            rows = (await uow.session.exec(
                select(VRFindingRecord)
                .where(VRFindingRecord.project_id == project_id)
                .order_by(VRFindingRecord.created_at.desc())
                .offset(offset).limit(limit)
            )).all()

        items = [_finding_from_record(r) for r in rows]
        meta = PaginatedMeta(total=total, offset=offset, limit=limit).model_dump()
        return DataEnvelope(data=items, meta=meta)

    @router.get(
        "/projects/{project_id}/findings/{finding_id}",
        response_model=DataEnvelope[VRFinding],
        summary="Get a single VR finding.",
    )
    @limiter.limit("60/minute")
    async def get_finding(
        request: Request,
        project_id: str,
        finding_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRFinding]:
        del request
        from .db_models import VRFindingRecord, VRProjectRecord

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(VRProjectRecord).where(VRProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"VR project {project_id!r} not found.")
            _require_project_ownership(project, auth)

            finding = (await uow.session.exec(
                select(VRFindingRecord).where(
                    VRFindingRecord.id == finding_id,
                    VRFindingRecord.project_id == project_id,
                )
            )).first()
            if finding is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Finding {finding_id!r} not found in project {project_id!r}.",
                )

        return DataEnvelope(data=_finding_from_record(finding))

    @router.patch(
        "/projects/{project_id}/findings/{finding_id}/disclosure",
        response_model=DataEnvelope[VRFinding],
        summary="Update a finding's coordinated-disclosure status.",
    )
    @limiter.limit("30/minute")
    async def update_disclosure(
        request: Request,
        project_id: str,
        finding_id: str,
        body: DisclosureUpdate,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRFinding]:
        del request
        from aila.platform.contracts._common import utc_now

        from .db_models import VRFindingRecord, VRProjectRecord

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(VRProjectRecord).where(VRProjectRecord.id == project_id)
            )).first()
            if project is None:
                raise HTTPException(status_code=404, detail=f"VR project {project_id!r} not found.")
            _require_project_ownership(project, auth)

            finding = (await uow.session.exec(
                select(VRFindingRecord).where(
                    VRFindingRecord.id == finding_id,
                    VRFindingRecord.project_id == project_id,
                )
            )).first()
            if finding is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Finding {finding_id!r} not found in project {project_id!r}.",
                )

            new_status = body.disclosure_status
            previous_status = finding.disclosure_status
            finding.disclosure_status = new_status.value
            if body.vendor_contact is not None:
                finding.vendor_contact = body.vendor_contact
            if body.assigned_cve_id is not None:
                finding.assigned_cve_id = body.assigned_cve_id
            if body.patch_version is not None:
                finding.patch_version = body.patch_version
            # Stamp reported_at on first transition out of UNDISCLOSED so the
            # disclosure timeline reflects when the vendor was notified, not
            # when the row was updated.
            if (
                previous_status == DisclosureStatus.UNDISCLOSED.value
                and new_status != DisclosureStatus.UNDISCLOSED
                and finding.reported_at is None
            ):
                finding.reported_at = utc_now()
            finding.updated_at = utc_now()
            uow.session.add(finding)
            await uow.session.commit()
            await uow.session.refresh(finding)

        return DataEnvelope(data=_finding_from_record(finding))

    return router
