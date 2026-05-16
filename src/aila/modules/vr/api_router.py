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
    TargetKind,
    VRFinding,
    VRProjectCreate,
    VRProjectStatus,
    VRProjectSummary,
)


def _infer_target_kind(spec: Any) -> TargetKind:
    """Infer a TargetKind from an ingestion spec's input_source + target_format.

    Source-tree ingestion paths map to SOURCE_REPO. Binary uploads/downloads
    map to a kind derived from target_format when set, otherwise NATIVE_BINARY.
    Archive-class formats (APK/IPA/JAR/.NET) get their own TargetKind so
    enrichment routes them through the appropriate toolchain.
    """
    if spec.input_source.value == "git_repo":
        return TargetKind.SOURCE_REPO
    fmt = spec.target_format.value if spec.target_format else None
    if fmt == "apk":
        return TargetKind.APK
    if fmt == "ipa":
        return TargetKind.IPA
    if fmt == "jar":
        return TargetKind.JAR
    if fmt == "dotnet":
        return TargetKind.DOTNET_ASSEMBLY
    return TargetKind.NATIVE_BINARY


def _descriptor_from_spec(spec: Any) -> str:
    """Serialize a TargetIngestionSpec into a vr_targets.descriptor_json string.

    The descriptor captures kind-specific identification so the workflow
    setup state can recover everything needed to materialize the binary on
    the workstation. It is also the canonical record of what was ingested.
    """
    import json as _json

    descriptor: dict[str, Any] = {
        "input_source": spec.input_source.value,
        "target_format": spec.target_format.value if spec.target_format else None,
        "target_class": spec.target_class.value,
        "source_available": spec.source_available,
    }
    for field in (
        "upload_filename", "upload_sha256", "repo_url", "vulnerable_ref",
        "patched_ref", "build_command", "build_artifact", "download_url",
        "binary_id",
    ):
        value = getattr(spec, field, None)
        if value is not None:
            descriptor[field] = value
    return _json.dumps(descriptor)


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
    """Project a ``VRProjectRecord`` row to the public ``VRProjectSummary``.

    Target metadata (target_class, input_source, format) lives on the
    linked vr_targets row — callers can fetch it via /api/vr/targets/{id}.
    """
    return VRProjectSummary(
        id=record.id,
        name=record.name,
        cve_id=record.cve_id,
        status=VRProjectStatus(record.status),
        target_id=record.target_id,
        patched_target_id=record.patched_target_id,
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

        from .db_models import VRProjectRecord, VRTargetRecord
        from .workflow.task import run_vr_nday

        async def _resolve_system(
            uow_session: Any, sys_id: int, auth_ctx: AuthContext,
        ) -> dict[str, Any]:
            from aila.storage.db_models import ManagedSystemRecord

            sys_stmt = select(ManagedSystemRecord).where(
                ManagedSystemRecord.id == sys_id,
            )
            if auth_ctx.team_id is not None:
                sys_stmt = sys_stmt.where(
                    ManagedSystemRecord.team_id == auth_ctx.team_id,
                )
            system = (await uow_session.exec(sys_stmt)).first()
            if system is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"System {sys_id} not found.",
                )
            return {
                "name": system.name, "host": system.host,
                "username": system.username, "port": system.port,
                "private_key_path": system.private_key_path,
                "password_secret_id": system.password_secret_id,
            }

        analysis_integration: dict[str, Any] = {}
        poc_integration: dict[str, Any] | None = None
        async with UnitOfWork() as uow:
            analysis_integration = await _resolve_system(
                uow.session, body.analysis_system_id, auth,
            )
            if body.poc_system_id is not None:
                poc_integration = await _resolve_system(
                    uow.session, body.poc_system_id, auth,
                )

            primary_target = VRTargetRecord(
                workspace_id=body.workspace_id,
                team_id=auth.team_id,
                display_name=body.name,
                kind=_infer_target_kind(body.target).value,
                descriptor_json=_descriptor_from_spec(body.target),
                primary_language=None,
                secondary_languages_json="[]",
                status="active",
                capability_profile_json="{}",
                tags_json="[]",
                enrichment_status="unenriched",
            )
            uow.session.add(primary_target)
            await uow.session.flush()

            patched_target: VRTargetRecord | None = None
            if body.patched_target:
                patched_target = VRTargetRecord(
                    workspace_id=body.workspace_id,
                    team_id=auth.team_id,
                    display_name=f"{body.name} (patched)",
                    kind=_infer_target_kind(body.patched_target).value,
                    descriptor_json=_descriptor_from_spec(body.patched_target),
                    primary_language=None,
                    secondary_languages_json="[]",
                    status="active",
                    capability_profile_json="{}",
                    tags_json='["patched"]',
                    enrichment_status="unenriched",
                )
                uow.session.add(patched_target)
                await uow.session.flush()

            record = VRProjectRecord(
                name=body.name,
                cve_id=body.cve_id,
                target_id=primary_target.id,
                patched_target_id=patched_target.id if patched_target else None,
                context_notes=body.context_notes,
                status=VRProjectStatus.CREATED.value,
                team_id=auth.team_id,
                analysis_system_id=body.analysis_system_id,
                poc_system_id=body.poc_system_id,
            )
            uow.session.add(record)
            await uow.session.commit()
            await uow.session.refresh(record)

        t = body.target
        task_kwargs: dict[str, Any] = {
            "project_id": record.id,
            "target_id": record.target_id,
            "patched_target_id": record.patched_target_id,
            "name": body.name,
            "cve_id": body.cve_id,
            "input_source": t.input_source.value,
            "target_class": t.target_class.value,
            "target_format": t.target_format.value if t.target_format else None,
            "binary_id": t.binary_id,
            "upload_filename": t.upload_filename,
            "upload_sha256": t.upload_sha256,
            "repo_url": t.repo_url,
            "vulnerable_ref": t.vulnerable_ref,
            "build_command": t.build_command,
            "build_artifact": t.build_artifact,
            "download_url": t.download_url,
            "source_available": t.source_available,
            "context_notes": body.context_notes,
            "analysis_integration": analysis_integration,
            "poc_integration": poc_integration,
        }
        if body.patched_target:
            pt = body.patched_target
            task_kwargs.update({
                "patched_input_source": pt.input_source.value,
                "patched_binary_id": pt.binary_id,
                "patched_upload_filename": pt.upload_filename,
                "patched_repo_url": pt.repo_url,
                "patched_ref": pt.patched_ref or pt.vulnerable_ref,
                "patched_build_command": pt.build_command,
                "patched_build_artifact": pt.build_artifact,
                "patched_download_url": pt.download_url,
            })

        task_queue = get_task_queue("vr", request)
        handle = await task_queue.submit(
            track="vr",
            fn=run_vr_nday,
            kwargs=task_kwargs,
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
