"""FastAPI router for the vulnerability research module.

Mounted at ``/vr`` by ``VRModule.route_specs()``. Every endpoint uses
``DataEnvelope[T]`` response models, the platform's authenticated rate
limiter, and require_auth so unauthenticated callers get HTTP 401 before
they can reach project / finding state.

Server-side pagination uses ``offset`` and ``limit`` query parameters per
D-26; total counts go in ``meta`` via ``PaginatedMeta``.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncGenerator
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func as sa_func
from sqlmodel import select

from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope, PaginatedMeta
from aila.platform.contracts._common import utc_now
from aila.platform.contracts.auth import AuthContext, require_auth
from aila.platform.uow import UnitOfWork

from .contracts import (
    BranchStatus,
    CampaignStatus,
    CrashSeverity,
    CrashTriageVerdict,
    CVEFeedSource,
    CVERecordSummary,
    DisclosureStatus,
    DisclosureSubmissionStatus,
    DisclosureTrackInfo,
    InvestigationKind,
    InvestigationPauseReason,
    InvestigationStatus,
    OperatorIntent,
    OutcomeConfidence,
    OutcomeDispatchStatus,
    OutcomeKind,
    PatternKind,
    PatternScope,
    PatternStatus,
    PayloadKind,
    PersonaVoice,
    RenderedSubmission,
    SenderKind,
    StrategyBranchSpawn,
    TargetKind,
    TargetStatus,
    VRBranchSummary,
    VRCVERecordCreate,
    VRDisclosureSubmissionCreate,
    VRDisclosureSubmissionPatch,
    VRDisclosureSubmissionSummary,
    VRFinding,
    VRFuzzCampaignCreate,
    VRFuzzCampaignPatch,
    VRFuzzCampaignSummary,
    VRFuzzCrashCreate,
    VRFuzzCrashSummary,
    VRInvestigationCreate,
    VRInvestigationSummary,
    VRInvestigationTargetAttach,
    VRInvestigationTargetSummary,
    VRMessageCreate,
    VRMessageSummary,
    VROutcomeSummary,
    VRPatternCreate,
    VRPatternPatch,
    VRPatternSummary,
    VRProjectCreate,
    VRProjectStatus,
    VRProjectSummary,
    VRTargetCreate,
    VRTargetPatch,
    VRTargetSummary,
    VRWorkspaceCreate,
    VRWorkspacePatch,
    VRWorkspaceSummary,
    WorkspaceStatus,
    WorkspaceTheme,
)

# SSE polling cadence for the messages stream — 1s feels live without
# hammering the DB. Heartbeat every 15s keeps proxies from idling out.
_SSE_POLL_INTERVAL_S = 1.0
_SSE_HEARTBEAT_S = 15.0
_SSE_BATCH_LIMIT = 100


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


def _workspace_summary(
    record: Any,
    target_count: int = 0,
    active_investigation_count: int = 0,
) -> VRWorkspaceSummary:
    """Project a VRWorkspaceRecord row to the public VRWorkspaceSummary.

    Counts default to 0 for endpoints that don't need them (e.g. create).
    List/get endpoints supply real counts via batched queries below.
    """
    return VRWorkspaceSummary(
        id=record.id,
        name=record.name,
        slug=record.slug,
        description=record.description or "",
        theme=WorkspaceTheme(record.theme),
        status=WorkspaceStatus(record.status),
        target_count=target_count,
        active_investigation_count=active_investigation_count,
        created_at=record.created_at.isoformat() if record.created_at else None,
        updated_at=record.updated_at.isoformat() if record.updated_at else None,
    )


async def _workspace_counts(
    uow: Any,
    workspace_ids: list[str],
) -> tuple[dict[str, int], dict[str, int]]:
    """Two batched queries returning per-workspace counts.

    Returns ``(target_counts, active_investigation_counts)``: each a
    dict mapping ``workspace_id`` -> count. Workspaces with no rows
    are absent from the dict (caller defaults to 0).

    Active investigation = status in {CREATED, RUNNING, PAUSED}.
    COMPLETED/FAILED/ABANDONED are terminal and excluded.
    """
    from sqlmodel import select as _select

    from .contracts.investigation import InvestigationStatus
    from .db_models import VRInvestigationRecord, VRTargetRecord

    if not workspace_ids:
        return {}, {}

    target_rows = (await uow.session.exec(
        _select(
            VRTargetRecord.workspace_id,
            sa_func.count().label("c"),
        )
        .where(VRTargetRecord.workspace_id.in_(workspace_ids))
        .group_by(VRTargetRecord.workspace_id),
    )).all()
    target_counts: dict[str, int] = {row[0]: int(row[1]) for row in target_rows}

    active_statuses = (
        InvestigationStatus.CREATED.value,
        InvestigationStatus.RUNNING.value,
        InvestigationStatus.PAUSED.value,
    )
    inv_rows = (await uow.session.exec(
        _select(
            VRTargetRecord.workspace_id,
            sa_func.count().label("c"),
        )
        .join(
            VRInvestigationRecord,
            VRInvestigationRecord.target_id == VRTargetRecord.id,
        )
        .where(VRTargetRecord.workspace_id.in_(workspace_ids))
        .where(VRInvestigationRecord.status.in_(active_statuses))
        .group_by(VRTargetRecord.workspace_id),
    )).all()
    active_inv_counts: dict[str, int] = {row[0]: int(row[1]) for row in inv_rows}

    return target_counts, active_inv_counts


def _target_summary(record: Any) -> VRTargetSummary:
    """Project a VRTargetRecord row to the public VRTargetSummary."""
    import json as _json

    from .contracts.target import TargetTag, TargetTagSource

    raw_tags = _json.loads(record.tags_json or "[]")
    tags: list[TargetTag] = []
    for entry in raw_tags:
        if isinstance(entry, dict) and "tag" in entry:
            try:
                tags.append(TargetTag(
                    tag=str(entry["tag"]),
                    source=TargetTagSource(entry.get("source", "operator")),
                ))
            except ValueError:
                continue
        elif isinstance(entry, str):
            tags.append(TargetTag(tag=entry, source=TargetTagSource.OPERATOR))

    return VRTargetSummary(
        id=record.id,
        workspace_id=record.workspace_id,
        display_name=record.display_name,
        kind=TargetKind(record.kind),
        descriptor=_json.loads(record.descriptor_json or "{}"),
        primary_language=record.primary_language,
        secondary_languages=_json.loads(record.secondary_languages_json or "[]"),
        status=TargetStatus(record.status),
        enrichment_status=record.enrichment_status,  # type: ignore[arg-type]
        last_enriched_at=record.last_enriched_at.isoformat() if record.last_enriched_at else None,
        tags=tags,
        created_at=record.created_at.isoformat() if record.created_at else None,
        updated_at=record.updated_at.isoformat() if record.updated_at else None,
    )


def _investigation_summary(
    record: Any,
    branch_count: int = 0,
    message_count: int = 0,
    outcome_count: int = 0,
) -> VRInvestigationSummary:
    """Project a VRInvestigationRecord row to the public summary."""
    import json as _json

    return VRInvestigationSummary(
        id=record.id,
        title=record.title,
        target_id=record.target_id,
        workspace_id=None,  # joined separately by callers that need it
        parent_investigation_id=record.parent_investigation_id,
        kind=InvestigationKind(record.kind),
        status=InvestigationStatus(record.status),
        pause_reason=(
            InvestigationPauseReason(record.pause_reason)
            if record.pause_reason else None
        ),
        auto_pilot=record.auto_pilot,
        strategy_family=record.strategy_family,
        cost_budget_usd=record.cost_budget_usd,
        cost_actual_usd=record.cost_actual_usd,
        llm_tokens_cost_usd=record.llm_tokens_cost_usd,
        mcp_calls_cost_usd=record.mcp_calls_cost_usd,
        fuzz_infra_cost_usd=record.fuzz_infra_cost_usd,
        branch_count=branch_count,
        message_count=message_count,
        outcome_count=outcome_count,
        primary_outcome_id=record.primary_outcome_id,
        linked_campaign_ids=_json.loads(record.linked_campaign_ids_json or "[]"),
        linked_finding_ids=_json.loads(record.linked_finding_ids_json or "[]"),
        started_at=record.started_at,
        stopped_at=record.stopped_at,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def _branch_summary(record: Any) -> VRBranchSummary:
    """Project a VRInvestigationBranchRecord row to summary."""
    return VRBranchSummary(
        id=record.id,
        investigation_id=record.investigation_id,
        parent_branch_id=record.parent_branch_id,
        status=BranchStatus(record.status),
        persona_voice=PersonaVoice(record.persona_voice) if record.persona_voice else None,
        fork_reason=record.fork_reason or "",
        fork_at_turn=record.fork_at_turn,
        turn_count=record.turn_count,
        branch_cost_usd=record.branch_cost_usd,
        closed_reason=record.closed_reason or "",
        merged_into_branch_id=record.merged_into_branch_id,
        promoted=record.promoted,
        closed_at=record.closed_at,
        created_at=record.created_at,
        updated_at=record.updated_at,
        strategy_family=record.strategy_family,
    )


def _message_summary(record: Any) -> VRMessageSummary:
    """Project a VRInvestigationMessageRecord row to summary."""
    import json as _json

    return VRMessageSummary(
        id=record.id,
        investigation_id=record.investigation_id,
        branch_id=record.branch_id,
        sender_kind=SenderKind(record.sender_kind),
        sender_id=record.sender_id,
        payload_kind=PayloadKind(record.payload_kind),
        payload=_json.loads(record.payload_json or "{}"),
        operator_intent=(
            OperatorIntent(record.operator_intent) if record.operator_intent else None
        ),
        at_turn=record.at_turn,
        evidence_refs=_json.loads(record.evidence_refs_json or "[]"),
        created_at=record.created_at,
    )


def _outcome_summary(record: Any) -> VROutcomeSummary:
    """Project a VRInvestigationOutcomeRecord row to summary."""
    import json as _json

    return VROutcomeSummary(
        id=record.id,
        investigation_id=record.investigation_id,
        branch_id=record.branch_id,
        outcome_kind=OutcomeKind(record.outcome_kind),
        payload=_json.loads(record.payload_json or "{}"),
        confidence=OutcomeConfidence(record.confidence),
        evidence_refs=_json.loads(record.evidence_refs_json or "[]"),
        accepted_by_operator=record.accepted_by_operator,
        accepted_at=record.accepted_at,
        dispatch_status=OutcomeDispatchStatus(record.dispatch_status),
        dispatch_target=record.dispatch_target,
        created_at=record.created_at,
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

    # ── Workspaces (D-49) ──────────────────────────────────────────────

    @router.post(
        "/workspaces",
        response_model=DataEnvelope[VRWorkspaceSummary],
        status_code=status.HTTP_201_CREATED,
        summary="Create a VR workspace (thematic project per D-49).",
    )
    @limiter.limit("30/minute")
    async def create_workspace(
        request: Request,
        body: VRWorkspaceCreate,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRWorkspaceSummary]:
        del request
        from .db_models import VRWorkspaceRecord

        async with UnitOfWork() as uow:
            existing = (await uow.session.exec(
                _team_filter(
                    select(VRWorkspaceRecord).where(VRWorkspaceRecord.slug == body.slug),
                    VRWorkspaceRecord, auth,
                )
            )).first()
            if existing is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Workspace slug {body.slug!r} already exists for this team.",
                )
            record = VRWorkspaceRecord(
                name=body.name,
                slug=body.slug,
                description=body.description,
                theme=body.theme.value,
                team_id=auth.team_id,
            )
            uow.session.add(record)
            await uow.session.commit()
            await uow.session.refresh(record)

        return DataEnvelope(data=_workspace_summary(record))

    @router.get(
        "/workspaces",
        response_model=DataEnvelope[list[VRWorkspaceSummary]],
        summary="List VR workspaces.",
    )
    @limiter.limit("60/minute")
    async def list_workspaces(
        request: Request,
        auth: AuthContext = Depends(require_auth),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> DataEnvelope[list[VRWorkspaceSummary]]:
        del request
        from .db_models import VRWorkspaceRecord

        async with UnitOfWork() as uow:
            count_stmt = _team_filter(
                select(sa_func.count()).select_from(VRWorkspaceRecord),
                VRWorkspaceRecord, auth,
            )
            total = (await uow.session.exec(count_stmt)).one()

            page_stmt = _team_filter(
                select(VRWorkspaceRecord), VRWorkspaceRecord, auth,
            ).order_by(
                VRWorkspaceRecord.created_at.desc()
            ).offset(offset).limit(limit)
            rows = (await uow.session.exec(page_stmt)).all()

            workspace_ids = [r.id for r in rows]
            target_counts, active_inv_counts = await _workspace_counts(
                uow, workspace_ids,
            )

        items = [
            _workspace_summary(
                r,
                target_count=target_counts.get(r.id, 0),
                active_investigation_count=active_inv_counts.get(r.id, 0),
            )
            for r in rows
        ]
        return DataEnvelope(
            data=items,
            meta=PaginatedMeta(total=int(total), offset=offset, limit=limit).model_dump(),
        )

    @router.get(
        "/workspaces/{workspace_id}",
        response_model=DataEnvelope[VRWorkspaceSummary],
        summary="Get one VR workspace by id (with live counts).",
    )
    @limiter.limit("120/minute")
    async def get_workspace(
        request: Request,
        workspace_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRWorkspaceSummary]:
        del request
        from .db_models import VRWorkspaceRecord

        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _team_filter(
                    select(VRWorkspaceRecord).where(VRWorkspaceRecord.id == workspace_id),
                    VRWorkspaceRecord, auth,
                )
            )).first()
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Workspace {workspace_id} not found.",
                )
            target_counts, active_inv_counts = await _workspace_counts(uow, [workspace_id])

        return DataEnvelope(data=_workspace_summary(
            row,
            target_count=target_counts.get(workspace_id, 0),
            active_investigation_count=active_inv_counts.get(workspace_id, 0),
        ))

    @router.patch(
        "/workspaces/{workspace_id}",
        response_model=DataEnvelope[VRWorkspaceSummary],
        summary="Partial update of workspace fields (name / description / theme / status).",
    )
    @limiter.limit("30/minute")
    async def patch_workspace(
        request: Request,
        workspace_id: str,
        body: VRWorkspacePatch,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRWorkspaceSummary]:
        del request
        from aila.platform.contracts._common import utc_now

        from .db_models import VRWorkspaceRecord

        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _team_filter(
                    select(VRWorkspaceRecord).where(VRWorkspaceRecord.id == workspace_id),
                    VRWorkspaceRecord, auth,
                )
            )).first()
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Workspace {workspace_id} not found.",
                )
            mutated = False
            if body.name is not None and body.name != row.name:
                row.name = body.name
                mutated = True
            if body.description is not None and body.description != (row.description or ""):
                row.description = body.description
                mutated = True
            if body.theme is not None and body.theme.value != row.theme:
                row.theme = body.theme.value
                mutated = True
            if body.status is not None and body.status.value != row.status:
                row.status = body.status.value
                mutated = True
            if mutated:
                row.updated_at = utc_now()
                uow.session.add(row)
                await uow.session.commit()
                await uow.session.refresh(row)

            target_counts, active_inv_counts = await _workspace_counts(uow, [workspace_id])

        return DataEnvelope(data=_workspace_summary(
            row,
            target_count=target_counts.get(workspace_id, 0),
            active_investigation_count=active_inv_counts.get(workspace_id, 0),
        ))

    @router.delete(
        "/workspaces/{workspace_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Delete a workspace (refuses if any targets still belong to it).",
    )
    @limiter.limit("10/minute")
    async def delete_workspace(
        request: Request,
        workspace_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> Response:
        del request
        from .db_models import VRTargetRecord, VRWorkspaceRecord

        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _team_filter(
                    select(VRWorkspaceRecord).where(VRWorkspaceRecord.id == workspace_id),
                    VRWorkspaceRecord, auth,
                )
            )).first()
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Workspace {workspace_id} not found.",
                )
            target_count = (await uow.session.exec(
                select(sa_func.count())
                .select_from(VRTargetRecord)
                .where(VRTargetRecord.workspace_id == workspace_id),
            )).one()
            if int(target_count) > 0:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"Workspace {workspace_id} has {int(target_count)} target(s). "
                        "Move or delete them first."
                    ),
                )
            await uow.session.delete(row)
            await uow.session.commit()

        return Response(status_code=status.HTTP_204_NO_CONTENT)

    # ── Targets (D-50/D-51) ────────────────────────────────────────────

    @router.post(
        "/targets",
        response_model=DataEnvelope[VRTargetSummary],
        status_code=status.HTTP_201_CREATED,
        summary="Create a standalone VR target inside a workspace.",
    )
    @limiter.limit("30/minute")
    async def create_target(
        request: Request,
        body: VRTargetCreate,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRTargetSummary]:
        del request
        import json as _json

        from .db_models import VRTargetRecord, VRWorkspaceRecord

        async with UnitOfWork() as uow:
            workspace = (await uow.session.exec(
                _team_filter(
                    select(VRWorkspaceRecord).where(VRWorkspaceRecord.id == body.workspace_id),
                    VRWorkspaceRecord, auth,
                )
            )).first()
            if workspace is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Workspace {body.workspace_id} not found or not owned by your team.",
                )
            record = VRTargetRecord(
                workspace_id=body.workspace_id,
                team_id=auth.team_id,
                display_name=body.display_name,
                kind=body.kind.value,
                descriptor_json=_json.dumps(body.descriptor),
                primary_language=body.primary_language,
                secondary_languages_json=_json.dumps(list(body.secondary_languages)),
                tags_json=_json.dumps(
                    [{"tag": t, "source": "operator"} for t in body.tags],
                ),
                status="active",
                capability_profile_json="{}",
                enrichment_status="unenriched",
            )
            uow.session.add(record)
            await uow.session.commit()
            await uow.session.refresh(record)

        return DataEnvelope(data=_target_summary(record))

    @router.get(
        "/targets",
        response_model=DataEnvelope[list[VRTargetSummary]],
        summary="List VR targets (filterable by workspace_id + kind + status).",
    )
    @limiter.limit("60/minute")
    async def list_targets(
        request: Request,
        auth: AuthContext = Depends(require_auth),
        workspace_id: str | None = Query(default=None),
        kind: str | None = Query(default=None),
        target_status: str | None = Query(default=None, alias="status"),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> DataEnvelope[list[VRTargetSummary]]:
        del request
        from .db_models import VRTargetRecord

        async with UnitOfWork() as uow:
            base = _team_filter(select(VRTargetRecord), VRTargetRecord, auth)
            count_base = _team_filter(
                select(sa_func.count()).select_from(VRTargetRecord),
                VRTargetRecord, auth,
            )
            if workspace_id is not None:
                base = base.where(VRTargetRecord.workspace_id == workspace_id)
                count_base = count_base.where(VRTargetRecord.workspace_id == workspace_id)
            if kind is not None:
                base = base.where(VRTargetRecord.kind == kind)
                count_base = count_base.where(VRTargetRecord.kind == kind)
            if target_status is not None:
                base = base.where(VRTargetRecord.status == target_status)
                count_base = count_base.where(VRTargetRecord.status == target_status)

            total = (await uow.session.exec(count_base)).one()
            rows = (await uow.session.exec(
                base.order_by(VRTargetRecord.created_at.desc()).offset(offset).limit(limit)
            )).all()

        items = [_target_summary(r) for r in rows]
        return DataEnvelope(
            data=items,
            meta=PaginatedMeta(total=int(total), offset=offset, limit=limit).model_dump(),
        )

    @router.get(
        "/targets/{target_id}",
        response_model=DataEnvelope[dict],
        summary="Get one VR target including raw capability_profile_json.",
    )
    @limiter.limit("120/minute")
    async def get_target(
        request: Request,
        target_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict]:
        del request
        import json as _json

        from .db_models import VRTargetRecord

        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _team_filter(
                    select(VRTargetRecord).where(VRTargetRecord.id == target_id),
                    VRTargetRecord, auth,
                )
            )).first()
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Target {target_id} not found.",
                )

        summary = _target_summary(row)
        return DataEnvelope(data={
            **summary.model_dump(mode="json"),
            "capability_profile": _json.loads(row.capability_profile_json or "{}"),
            "descriptor": _json.loads(row.descriptor_json or "{}"),
        })

    @router.patch(
        "/targets/{target_id}",
        response_model=DataEnvelope[VRTargetSummary],
        summary="Partial update of mutable target fields.",
    )
    @limiter.limit("30/minute")
    async def patch_target(
        request: Request,
        target_id: str,
        body: VRTargetPatch,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRTargetSummary]:
        del request
        import json as _json

        from aila.platform.contracts._common import utc_now

        from .contracts.target import TargetTag, TargetTagSource
        from .db_models import VRTargetRecord

        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _team_filter(
                    select(VRTargetRecord).where(VRTargetRecord.id == target_id),
                    VRTargetRecord, auth,
                )
            )).first()
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Target {target_id} not found.",
                )
            mutated = False
            if body.display_name is not None and body.display_name != row.display_name:
                row.display_name = body.display_name
                mutated = True
            if body.primary_language is not None and body.primary_language != row.primary_language:
                row.primary_language = body.primary_language
                mutated = True
            if body.secondary_languages is not None:
                new_langs_json = _json.dumps(body.secondary_languages)
                if new_langs_json != (row.secondary_languages_json or "[]"):
                    row.secondary_languages_json = new_langs_json
                    mutated = True
            if body.status is not None and body.status.value != row.status:
                row.status = body.status.value
                mutated = True
            if body.tags is not None:
                # Replace operator-supplied tag set. System + pattern tags
                # are persisted in vr_target_tag_index separately.
                serialized = [
                    TargetTag(tag=t, source=TargetTagSource.OPERATOR).model_dump(mode="json")
                    for t in body.tags
                ]
                new_tags_json = _json.dumps(serialized)
                if new_tags_json != (row.tags_json or "[]"):
                    row.tags_json = new_tags_json
                    mutated = True
            if mutated:
                row.updated_at = utc_now()
                uow.session.add(row)
                await uow.session.commit()
                await uow.session.refresh(row)

        return DataEnvelope(data=_target_summary(row))

    @router.delete(
        "/targets/{target_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Delete a target (refuses if any investigations reference it).",
    )
    @limiter.limit("10/minute")
    async def delete_target(
        request: Request,
        target_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> Response:
        del request
        from .db_models import VRInvestigationRecord, VRTargetRecord

        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _team_filter(
                    select(VRTargetRecord).where(VRTargetRecord.id == target_id),
                    VRTargetRecord, auth,
                )
            )).first()
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Target {target_id} not found.",
                )
            inv_count = (await uow.session.exec(
                select(sa_func.count())
                .select_from(VRInvestigationRecord)
                .where(VRInvestigationRecord.target_id == target_id),
            )).one()
            if int(inv_count) > 0:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"Target {target_id} has {int(inv_count)} investigation(s). "
                        "Archive or delete them first."
                    ),
                )
            await uow.session.delete(row)
            await uow.session.commit()

        return Response(status_code=status.HTTP_204_NO_CONTENT)

    # ── Enrichment triggers (M3.T-3 + M3.T-4) ──────────────────────────

    @router.post(
        "/targets/{target_id}/rank",
        response_model=DataEnvelope[dict],
        status_code=status.HTTP_202_ACCEPTED,
        summary="Enqueue function ranking (M3.T-3) for one target.",
    )
    @limiter.limit("10/minute")
    async def enqueue_ranking(
        request: Request,
        target_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict]:
        from aila.api.deps import get_task_queue

        from .db_models import VRTargetRecord
        from .enrichment.workers import run_function_ranking

        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _team_filter(
                    select(VRTargetRecord).where(VRTargetRecord.id == target_id),
                    VRTargetRecord, auth,
                )
            )).first()
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Target {target_id} not found.",
                )

        task_queue = get_task_queue("vr", request)
        handle = await task_queue.submit(
            track="vr",
            fn=run_function_ranking,
            kwargs={"target_id": target_id},
            user_id=auth.user_id,
            group_id=auth.role,
            team_id=auth.team_id,
        )
        return DataEnvelope(data={"task_id": handle.task_id, "target_id": target_id})

    @router.post(
        "/targets/{target_id}/enrich",
        response_model=DataEnvelope[dict],
        status_code=status.HTTP_202_ACCEPTED,
        summary="Enqueue capability profile build (M3.T-4) for one target.",
    )
    @limiter.limit("10/minute")
    async def enqueue_enrichment(
        request: Request,
        target_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict]:
        from aila.api.deps import get_task_queue

        from .db_models import VRTargetRecord
        from .enrichment.workers import run_capability_profile_build

        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _team_filter(
                    select(VRTargetRecord).where(VRTargetRecord.id == target_id),
                    VRTargetRecord, auth,
                )
            )).first()
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Target {target_id} not found.",
                )

        task_queue = get_task_queue("vr", request)
        handle = await task_queue.submit(
            track="vr",
            fn=run_capability_profile_build,
            kwargs={"target_id": target_id},
            user_id=auth.user_id,
            group_id=auth.role,
            team_id=auth.team_id,
        )
        return DataEnvelope(data={"task_id": handle.task_id, "target_id": target_id})

    # ── Investigations (M3.R-1 schema, D-43, D-49/D-50) ───────────────

    @router.post(
        "/investigations",
        response_model=DataEnvelope[VRInvestigationSummary],
        status_code=status.HTTP_201_CREATED,
        summary="Create a new investigation against a target.",
    )
    @limiter.limit("30/minute")
    async def create_investigation(
        request: Request,
        body: VRInvestigationCreate,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRInvestigationSummary]:
        import json as _json

        from aila.api.deps import get_task_queue

        from .db_models import VRInvestigationBranchRecord, VRInvestigationRecord, VRTargetRecord
        from .workflow.task import run_vr_investigate

        async with UnitOfWork() as uow:
            target = (await uow.session.exec(
                _team_filter(
                    select(VRTargetRecord).where(VRTargetRecord.id == body.target_id),
                    VRTargetRecord, auth,
                )
            )).first()
            if target is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Target {body.target_id} not found or not owned by your team.",
                )

            record = VRInvestigationRecord(
                target_id=body.target_id,
                team_id=auth.team_id,
                parent_investigation_id=body.parent_investigation_id,
                secondary_target_refs_json=_json.dumps(list(body.secondary_target_ids)),
                kind=body.kind.value,
                title=body.title,
                initial_question=body.initial_question,
                status=InvestigationStatus.CREATED.value,
                auto_pilot=body.auto_pilot,
                strategy_family=body.strategy_family,
                cost_budget_usd=body.cost_budget_usd,
            )
            uow.session.add(record)
            await uow.session.flush()

            primary_branch = VRInvestigationBranchRecord(
                investigation_id=record.id,
                status=BranchStatus.ACTIVE.value,
                fork_reason="primary",
            )
            uow.session.add(primary_branch)

            await uow.session.commit()
            await uow.session.refresh(record)

        task_queue = get_task_queue("vr", request)
        await task_queue.submit(
            track="vr",
            fn=run_vr_investigate,
            kwargs={"investigation_id": record.id},
            user_id=auth.user_id,
            group_id=auth.role,
            team_id=auth.team_id,
        )

        return DataEnvelope(
            data=_investigation_summary(record, branch_count=1),
        )

    @router.get(
        "/investigations",
        response_model=DataEnvelope[list[VRInvestigationSummary]],
        summary="List investigations (filterable by target_id + kind + status).",
    )
    @limiter.limit("60/minute")
    async def list_investigations(
        request: Request,
        auth: AuthContext = Depends(require_auth),
        target_id: str | None = Query(default=None),
        kind: str | None = Query(default=None),
        investigation_status: str | None = Query(default=None, alias="status"),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> DataEnvelope[list[VRInvestigationSummary]]:
        del request
        from .db_models import VRInvestigationRecord

        async with UnitOfWork() as uow:
            base = _team_filter(select(VRInvestigationRecord), VRInvestigationRecord, auth)
            count_base = _team_filter(
                select(sa_func.count()).select_from(VRInvestigationRecord),
                VRInvestigationRecord, auth,
            )
            if target_id is not None:
                base = base.where(VRInvestigationRecord.target_id == target_id)
                count_base = count_base.where(VRInvestigationRecord.target_id == target_id)
            if kind is not None:
                base = base.where(VRInvestigationRecord.kind == kind)
                count_base = count_base.where(VRInvestigationRecord.kind == kind)
            if investigation_status is not None:
                base = base.where(VRInvestigationRecord.status == investigation_status)
                count_base = count_base.where(VRInvestigationRecord.status == investigation_status)

            total = (await uow.session.exec(count_base)).one()
            rows = (await uow.session.exec(
                base.order_by(VRInvestigationRecord.created_at.desc()).offset(offset).limit(limit)
            )).all()

        items = [_investigation_summary(r) for r in rows]
        return DataEnvelope(
            data=items,
            meta=PaginatedMeta(total=int(total), offset=offset, limit=limit).model_dump(),
        )

    async def _load_investigation(
        investigation_id: str, auth: AuthContext,
    ) -> Any:
        from .db_models import VRInvestigationRecord

        async with UnitOfWork() as uow:
            return (await uow.session.exec(
                _team_filter(
                    select(VRInvestigationRecord).where(
                        VRInvestigationRecord.id == investigation_id,
                    ),
                    VRInvestigationRecord, auth,
                )
            )).first()

    @router.get(
        "/investigations/{investigation_id}",
        response_model=DataEnvelope[VRInvestigationSummary],
        summary="Get investigation detail with aggregated counts.",
    )
    @limiter.limit("120/minute")
    async def get_investigation(
        request: Request,
        investigation_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRInvestigationSummary]:
        del request
        from .db_models import (
            VRInvestigationBranchRecord,
            VRInvestigationMessageRecord,
            VRInvestigationOutcomeRecord,
            VRInvestigationRecord,
        )

        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _team_filter(
                    select(VRInvestigationRecord).where(
                        VRInvestigationRecord.id == investigation_id,
                    ),
                    VRInvestigationRecord, auth,
                )
            )).first()
            if inv is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Investigation {investigation_id} not found.",
                )
            branch_count = (await uow.session.exec(
                select(sa_func.count()).select_from(VRInvestigationBranchRecord)
                .where(VRInvestigationBranchRecord.investigation_id == investigation_id)
            )).one()
            message_count = (await uow.session.exec(
                select(sa_func.count()).select_from(VRInvestigationMessageRecord)
                .where(VRInvestigationMessageRecord.investigation_id == investigation_id)
            )).one()
            outcome_count = (await uow.session.exec(
                select(sa_func.count()).select_from(VRInvestigationOutcomeRecord)
                .where(VRInvestigationOutcomeRecord.investigation_id == investigation_id)
            )).one()

        return DataEnvelope(data=_investigation_summary(
            inv,
            branch_count=int(branch_count),
            message_count=int(message_count),
            outcome_count=int(outcome_count),
        ))

    @router.post(
        "/investigations/{investigation_id}/pause",
        response_model=DataEnvelope[VRInvestigationSummary],
        summary="Operator-initiated pause (D-43 GA-21).",
    )
    @limiter.limit("30/minute")
    async def pause_investigation(
        request: Request,
        investigation_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRInvestigationSummary]:
        del request
        from aila.platform.contracts._common import utc_now

        from .db_models import VRInvestigationRecord

        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _team_filter(
                    select(VRInvestigationRecord).where(
                        VRInvestigationRecord.id == investigation_id,
                    ),
                    VRInvestigationRecord, auth,
                )
            )).first()
            if inv is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Investigation {investigation_id} not found.",
                )
            if inv.status not in {InvestigationStatus.RUNNING.value, InvestigationStatus.CREATED.value}:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Cannot pause investigation in status {inv.status!r}.",
                )
            inv.status = InvestigationStatus.PAUSED.value
            inv.pause_reason = InvestigationPauseReason.OPERATOR.value
            inv.updated_at = utc_now()
            uow.session.add(inv)
            await uow.session.commit()
            await uow.session.refresh(inv)

        return DataEnvelope(data=_investigation_summary(inv))

    @router.post(
        "/investigations/{investigation_id}/resume",
        response_model=DataEnvelope[VRInvestigationSummary],
        summary="Operator-initiated resume (D-43 GA-21).",
    )
    @limiter.limit("30/minute")
    async def resume_investigation(
        request: Request,
        investigation_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRInvestigationSummary]:
        del request
        from aila.platform.contracts._common import utc_now

        from .db_models import VRInvestigationRecord

        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _team_filter(
                    select(VRInvestigationRecord).where(
                        VRInvestigationRecord.id == investigation_id,
                    ),
                    VRInvestigationRecord, auth,
                )
            )).first()
            if inv is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Investigation {investigation_id} not found.",
                )
            if inv.status != InvestigationStatus.PAUSED.value:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Cannot resume investigation in status {inv.status!r}.",
                )
            inv.status = InvestigationStatus.RUNNING.value
            inv.pause_reason = None
            inv.updated_at = utc_now()
            uow.session.add(inv)
            await uow.session.commit()
            await uow.session.refresh(inv)

        return DataEnvelope(data=_investigation_summary(inv))

    @router.post(
        "/investigations/{investigation_id}/messages",
        response_model=DataEnvelope[VRMessageSummary],
        status_code=status.HTTP_201_CREATED,
        summary="Operator sends a message (D-43 conversational UX).",
    )
    @limiter.limit("60/minute")
    async def post_investigation_message(
        request: Request,
        investigation_id: str,
        body: VRMessageCreate,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRMessageSummary]:
        del request
        import json as _json

        from .agents.intent_classifier import classify_intent
        from .db_models import (
            VRInvestigationBranchRecord,
            VRInvestigationMessageRecord,
            VRInvestigationRecord,
        )

        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _team_filter(
                    select(VRInvestigationRecord).where(
                        VRInvestigationRecord.id == investigation_id,
                    ),
                    VRInvestigationRecord, auth,
                )
            )).first()
            if inv is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Investigation {investigation_id} not found.",
                )

            branch_id = body.branch_id
            if branch_id is None:
                primary_branch = (await uow.session.exec(
                    select(VRInvestigationBranchRecord).where(
                        VRInvestigationBranchRecord.investigation_id == investigation_id,
                        VRInvestigationBranchRecord.parent_branch_id.is_(None),
                    ).limit(1)
                )).first()
                if primary_branch is None:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Investigation has no primary branch — DB inconsistency.",
                    )
                branch_id = primary_branch.id

            msg = VRInvestigationMessageRecord(
                investigation_id=investigation_id,
                branch_id=branch_id,
                sender_kind=SenderKind.OPERATOR.value,
                sender_id=auth.user_id,
                payload_kind=PayloadKind.TEXT.value,
                payload_json=_json.dumps({"text": body.text}),
                operator_intent=(
                    body.explicit_intent.value if body.explicit_intent
                    else classify_intent(body.text).value
                ),
            )
            uow.session.add(msg)
            await uow.session.commit()
            await uow.session.refresh(msg)

        return DataEnvelope(data=_message_summary(msg))

    @router.get(
        "/investigations/{investigation_id}/messages",
        response_model=DataEnvelope[list[VRMessageSummary]],
        summary="List messages for an investigation (paginated, branch-filterable).",
    )
    @limiter.limit("120/minute")
    async def list_investigation_messages(
        request: Request,
        investigation_id: str,
        auth: AuthContext = Depends(require_auth),
        branch_id: str | None = Query(default=None),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> DataEnvelope[list[VRMessageSummary]]:
        del request
        inv = await _load_investigation(investigation_id, auth)
        if inv is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation {investigation_id} not found.",
            )
        from .db_models import VRInvestigationMessageRecord

        async with UnitOfWork() as uow:
            stmt = select(VRInvestigationMessageRecord).where(
                VRInvestigationMessageRecord.investigation_id == investigation_id,
            )
            count_stmt = select(sa_func.count()).select_from(
                VRInvestigationMessageRecord
            ).where(VRInvestigationMessageRecord.investigation_id == investigation_id)
            if branch_id is not None:
                stmt = stmt.where(VRInvestigationMessageRecord.branch_id == branch_id)
                count_stmt = count_stmt.where(
                    VRInvestigationMessageRecord.branch_id == branch_id,
                )
            total = (await uow.session.exec(count_stmt)).one()
            rows = (await uow.session.exec(
                stmt.order_by(VRInvestigationMessageRecord.created_at.asc())
                .offset(offset).limit(limit)
            )).all()

        items = [_message_summary(r) for r in rows]
        return DataEnvelope(
            data=items,
            meta=PaginatedMeta(total=int(total), offset=offset, limit=limit).model_dump(),
        )

    @router.get(
        "/investigations/{investigation_id}/messages/stream",
        summary="SSE stream of new investigation messages (live tail).",
        response_class=StreamingResponse,
        responses={
            200: {
                "description": "SSE event stream of new messages as they land.",
                "content": {"text/event-stream": {"schema": {"type": "string"}}},
            },
        },
    )
    @limiter.limit("30/minute")
    async def stream_investigation_messages(
        request: Request,
        investigation_id: str,
        branch_id: str | None = Query(default=None),
        since_iso: str | None = Query(
            default=None,
            description="ISO-8601 timestamp; only messages newer than this are streamed.",
        ),
        auth: AuthContext = Depends(require_auth),
    ) -> StreamingResponse:
        """SSE stream of new investigation messages.

        Polls the message table every ``_SSE_POLL_INTERVAL_S`` seconds for
        rows with ``created_at > cursor`` and emits each as a single
        ``data: <json>`` SSE event. Heartbeat every ``_SSE_HEARTBEAT_S``
        seconds. Terminates when the investigation reaches a terminal
        status or when the connection drops.
        """
        del request
        from datetime import datetime as _dt

        from .db_models import VRInvestigationMessageRecord, VRInvestigationRecord

        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _team_filter(
                    select(VRInvestigationRecord).where(
                        VRInvestigationRecord.id == investigation_id,
                    ),
                    VRInvestigationRecord, auth,
                )
            )).first()
            if inv is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Investigation {investigation_id} not found.",
                )

        if since_iso:
            try:
                cursor = _dt.fromisoformat(since_iso.replace("Z", "+00:00"))
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Invalid since_iso: {since_iso!r}",
                ) from None
        else:
            cursor = utc_now()

        async def _generator() -> AsyncGenerator[str, None]:
            import json as _json

            last_heartbeat = utc_now()
            local_cursor = cursor
            terminal = {
                InvestigationStatus.COMPLETED.value,
                InvestigationStatus.FAILED.value,
                InvestigationStatus.ABANDONED.value,
            }

            yield 'event: open\ndata: {"connected":true}\n\n'

            while True:
                async with UnitOfWork() as poll_uow:
                    stmt = select(VRInvestigationMessageRecord).where(
                        VRInvestigationMessageRecord.investigation_id == investigation_id,
                        VRInvestigationMessageRecord.created_at > local_cursor,
                    )
                    if branch_id:
                        stmt = stmt.where(
                            VRInvestigationMessageRecord.branch_id == branch_id,
                        )
                    stmt = stmt.order_by(
                        VRInvestigationMessageRecord.created_at.asc()
                    ).limit(_SSE_BATCH_LIMIT)
                    rows = (await poll_uow.session.exec(stmt)).all()

                    status_row = (await poll_uow.session.exec(
                        select(VRInvestigationRecord.status).where(
                            VRInvestigationRecord.id == investigation_id,
                        ),
                    )).first()

                for row in rows:
                    summary = _message_summary(row)
                    yield f"data: {_json.dumps(summary.model_dump(mode='json'))}\n\n"
                    if row.created_at and row.created_at > local_cursor:
                        local_cursor = row.created_at

                now = utc_now()
                if (now - last_heartbeat).total_seconds() >= _SSE_HEARTBEAT_S:
                    yield f'event: heartbeat\ndata: {{"ts":"{now.isoformat()}"}}\n\n'
                    last_heartbeat = now

                if status_row in terminal and not rows:
                    yield (
                        f'event: done\ndata: {{"status":"{status_row}"}}\n\n'
                    )
                    return

                await asyncio.sleep(_SSE_POLL_INTERVAL_S)

        return StreamingResponse(
            _generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )
    @router.get(
        "/investigations/{investigation_id}/branches",
        response_model=DataEnvelope[list[VRBranchSummary]],
        summary="List branches for an investigation.",
    )
    @limiter.limit("120/minute")
    async def list_investigation_branches(
        request: Request,
        investigation_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[VRBranchSummary]]:
        del request
        inv = await _load_investigation(investigation_id, auth)
        if inv is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation {investigation_id} not found.",
            )
        from .db_models import VRInvestigationBranchRecord

        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                select(VRInvestigationBranchRecord)
                .where(VRInvestigationBranchRecord.investigation_id == investigation_id)
                .order_by(VRInvestigationBranchRecord.created_at.asc())
            )).all()

        return DataEnvelope(data=[_branch_summary(r) for r in rows])

    @router.get(
        "/investigations/{investigation_id}/outcomes",
        response_model=DataEnvelope[list[VROutcomeSummary]],
        summary="List outcomes for an investigation.",
    )
    @limiter.limit("120/minute")
    async def list_investigation_outcomes(
        request: Request,
        investigation_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[VROutcomeSummary]]:
        del request
        inv = await _load_investigation(investigation_id, auth)
        if inv is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation {investigation_id} not found.",
            )
        from .db_models import VRInvestigationOutcomeRecord

        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                select(VRInvestigationOutcomeRecord)
                .where(VRInvestigationOutcomeRecord.investigation_id == investigation_id)
                .order_by(VRInvestigationOutcomeRecord.created_at.asc())
            )).all()

        return DataEnvelope(data=[_outcome_summary(r) for r in rows])

    # ── Branch operations (M3.R-5, D-41) ──────────────────────────────

    async def _load_branch_or_404(
        investigation_id: str, branch_id: str, auth: AuthContext,
    ) -> tuple[Any, Any]:
        from .db_models import VRInvestigationBranchRecord, VRInvestigationRecord

        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _team_filter(
                    select(VRInvestigationRecord).where(
                        VRInvestigationRecord.id == investigation_id,
                    ),
                    VRInvestigationRecord, auth,
                )
            )).first()
            if inv is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Investigation {investigation_id} not found.",
                )
            branch = (await uow.session.exec(
                select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.id == branch_id,
                    VRInvestigationBranchRecord.investigation_id == investigation_id,
                )
            )).first()
            if branch is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Branch {branch_id} not found in investigation {investigation_id}.",
                )
            return inv, branch

    class _BranchOpBody(BaseModel):
        model_config = ConfigDict(extra="forbid")
        reason: str = Field(default="", max_length=1024)

    class _ForkBody(_BranchOpBody):
        persona_voice: PersonaVoice | None = Field(default=None)
        at_turn: int | None = Field(default=None, ge=0)

    class _MergeBody(_BranchOpBody):
        other_branch_id: str = Field(min_length=1, max_length=64)

    async def _wrap_branch_op_call(
        coro: Any, op_name: str,
    ) -> DataEnvelope[dict]:
        from aila.modules.vr.agents.branch_manager import BranchManagerError

        try:
            result = await coro
        except BranchManagerError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"{op_name}: {exc}",
            ) from exc
        return DataEnvelope(data={
            "op": result.op.value,
            "investigation_id": result.investigation_id,
            "primary_branch_id": result.primary_branch_id,
            "new_branch_id": result.new_branch_id,
            "affected_branch_ids": result.affected_branch_ids or [],
            "reason": result.reason,
        })

    @router.post(
        "/investigations/{investigation_id}/branches/{branch_id}/fork",
        response_model=DataEnvelope[dict],
        status_code=status.HTTP_201_CREATED,
        summary="Fork an ACTIVE branch into a new child branch.",
    )
    @limiter.limit("30/minute")
    async def fork_branch(
        request: Request,
        investigation_id: str,
        branch_id: str,
        body: _ForkBody,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict]:
        del request
        from aila.modules.vr.agents.branch_manager import BranchManager

        await _load_branch_or_404(investigation_id, branch_id, auth)
        mgr = BranchManager(investigation_id=investigation_id)
        return await _wrap_branch_op_call(
            mgr.fork(
                parent_branch_id=branch_id,
                persona_voice=body.persona_voice.value if body.persona_voice else None,
                fork_reason=body.reason,
                at_turn=body.at_turn,
            ),
            "fork",
        )

    @router.post(
        "/investigations/{investigation_id}/branches/{branch_id}/merge",
        response_model=DataEnvelope[dict],
        summary="Merge two ACTIVE branches into a new branch.",
    )
    @limiter.limit("30/minute")
    async def merge_branches(
        request: Request,
        investigation_id: str,
        branch_id: str,
        body: _MergeBody,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict]:
        del request
        from aila.modules.vr.agents.branch_manager import BranchManager

        await _load_branch_or_404(investigation_id, branch_id, auth)
        await _load_branch_or_404(investigation_id, body.other_branch_id, auth)
        mgr = BranchManager(investigation_id=investigation_id)
        return await _wrap_branch_op_call(
            mgr.merge(
                branch_a_id=branch_id,
                branch_b_id=body.other_branch_id,
                merge_reason=body.reason,
            ),
            "merge",
        )

    @router.post(
        "/investigations/{investigation_id}/branches/{branch_id}/promote",
        response_model=DataEnvelope[dict],
        summary="Promote branch to authoritative; sibling ACTIVE branches → ABANDONED.",
    )
    @limiter.limit("30/minute")
    async def promote_branch(
        request: Request,
        investigation_id: str,
        branch_id: str,
        body: _BranchOpBody,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict]:
        del request
        from aila.modules.vr.agents.branch_manager import BranchManager

        await _load_branch_or_404(investigation_id, branch_id, auth)
        mgr = BranchManager(investigation_id=investigation_id)
        return await _wrap_branch_op_call(
            mgr.promote(branch_id=branch_id, reason=body.reason),
            "promote",
        )

    @router.post(
        "/investigations/{investigation_id}/branches/{branch_id}/abandon",
        response_model=DataEnvelope[dict],
        summary="Close a branch without promotion.",
    )
    @limiter.limit("30/minute")
    async def abandon_branch(
        request: Request,
        investigation_id: str,
        branch_id: str,
        body: _BranchOpBody,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict]:
        del request
        from aila.modules.vr.agents.branch_manager import BranchManager

        await _load_branch_or_404(investigation_id, branch_id, auth)
        mgr = BranchManager(investigation_id=investigation_id)
        return await _wrap_branch_op_call(
            mgr.abandon(branch_id=branch_id, reason=body.reason),
            "abandon",
        )

    @router.post(
        "/investigations/{investigation_id}/branches/{branch_id}/pause",
        response_model=DataEnvelope[dict],
        summary="Pause a branch (status ACTIVE → PAUSED).",
    )
    @limiter.limit("30/minute")
    async def pause_branch(
        request: Request,
        investigation_id: str,
        branch_id: str,
        body: _BranchOpBody,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict]:
        del request
        from aila.modules.vr.agents.branch_manager import BranchManager

        await _load_branch_or_404(investigation_id, branch_id, auth)
        mgr = BranchManager(investigation_id=investigation_id)
        return await _wrap_branch_op_call(
            mgr.pause(branch_id=branch_id, reason=body.reason),
            "pause",
        )

    @router.post(
        "/investigations/{investigation_id}/branches/{branch_id}/resume",
        response_model=DataEnvelope[dict],
        summary="Resume a PAUSED branch (status PAUSED → ACTIVE).",
    )
    @limiter.limit("30/minute")
    async def resume_branch(
        request: Request,
        investigation_id: str,
        branch_id: str,
        body: _BranchOpBody,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict]:
        del request
        from aila.modules.vr.agents.branch_manager import BranchManager

        await _load_branch_or_404(investigation_id, branch_id, auth)
        mgr = BranchManager(investigation_id=investigation_id)
        return await _wrap_branch_op_call(
            mgr.resume(branch_id=branch_id, reason=body.reason),
            "resume",
        )

    # ── Pattern catalog (Knowledge Transfer plan GA-41 / GA-44) ────────

    @router.post(
        "/patterns",
        response_model=DataEnvelope[VRPatternSummary],
        status_code=status.HTTP_201_CREATED,
        summary="Create a pattern (operator-manual entry path).",
    )
    @limiter.limit("30/minute")
    async def create_pattern(
        request: Request,
        body: VRPatternCreate,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRPatternSummary]:
        del request
        from aila.modules.vr.services import PatternStore
        from aila.platform.services.knowledge import KnowledgeService

        store = PatternStore(knowledge=KnowledgeService())
        try:
            summary = await store.create(body, team_id=auth.team_id)
        except (OSError, RuntimeError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to create pattern: {exc}",
            ) from exc
        return DataEnvelope(data=summary)

    @router.get(
        "/patterns",
        response_model=DataEnvelope[list[VRPatternSummary]],
        summary="List patterns (filterable by workspace/kind/status/scope).",
    )
    @limiter.limit("60/minute")
    async def list_patterns(
        request: Request,
        workspace_id: str | None = Query(default=None),
        kind: PatternKind | None = Query(default=None),
        pattern_status: PatternStatus | None = Query(
            default=None,
            alias="status",
            description="Pattern lifecycle status (draft/active/archived).",
        ),
        scope: PatternScope | None = Query(default=None),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=200),
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[VRPatternSummary]]:
        del request, auth
        from aila.modules.vr.services import PatternStore
        from aila.platform.services.knowledge import KnowledgeService

        store = PatternStore(knowledge=KnowledgeService())
        items, total = await store.list(
            workspace_id=workspace_id,
            kind=kind,
            status=pattern_status,
            scope=scope,
            offset=offset,
            limit=limit,
        )
        return DataEnvelope(
            data=items,
            meta=PaginatedMeta(
                total=int(total), offset=offset, limit=limit,
            ).model_dump(),
        )

    @router.get(
        "/patterns/applicable",
        response_model=DataEnvelope[list[dict]],
        summary="Retrieve patterns applicable to a target + question (semantic + structured).",
    )
    @limiter.limit("60/minute")
    async def applicable_patterns(
        request: Request,
        workspace_id: str = Query(min_length=1),
        query: str = Query(min_length=1),
        target_kind: str | None = Query(default=None),
        primary_language: str | None = Query(default=None),
        k: int = Query(default=5, ge=1, le=20),
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[dict]]:
        del request
        from aila.modules.vr.services import PatternStore
        from aila.platform.services.knowledge import KnowledgeService

        store = PatternStore(knowledge=KnowledgeService())
        results = await store.applicable(
            workspace_id=workspace_id,
            team_id=auth.team_id,
            query=query,
            target_kind=target_kind,
            primary_language=primary_language,
            k=k,
        )
        return DataEnvelope(
            data=[
                {
                    "pattern": r.pattern.model_dump(mode="json"),
                    "score": r.score,
                    "matched_by": r.matched_by,
                }
                for r in results
            ],
        )

    @router.get(
        "/patterns/{pattern_id}",
        response_model=DataEnvelope[VRPatternSummary],
        summary="Get one pattern by id.",
    )
    @limiter.limit("120/minute")
    async def get_pattern(
        request: Request,
        pattern_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRPatternSummary]:
        del request, auth
        from aila.modules.vr.services import PatternStore
        from aila.platform.services.knowledge import KnowledgeService

        store = PatternStore(knowledge=KnowledgeService())
        summary = await store.get(pattern_id)
        if summary is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Pattern {pattern_id} not found.",
            )
        return DataEnvelope(data=summary)

    @router.patch(
        "/patterns/{pattern_id}",
        response_model=DataEnvelope[VRPatternSummary],
        summary="Operator review + scope promotion. Scope demotion forbidden.",
    )
    @limiter.limit("30/minute")
    async def patch_pattern(
        request: Request,
        pattern_id: str,
        body: VRPatternPatch,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRPatternSummary]:
        del request
        from aila.modules.vr.services import PatternStore, PatternStoreError
        from aila.platform.services.knowledge import KnowledgeService

        store = PatternStore(knowledge=KnowledgeService())
        try:
            summary = await store.patch(pattern_id, body, team_id=auth.team_id)
        except PatternStoreError as exc:
            msg = str(exc)
            if "not found" in msg:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail=msg,
                ) from exc
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail=msg,
            ) from exc
        return DataEnvelope(data=summary)

    # ── Disclosure submissions (Disclosure Lifecycle plan) ─────────────

    @router.get(
        "/disclosure-tracks",
        response_model=DataEnvelope[list[DisclosureTrackInfo]],
        summary="List all available disclosure tracks (built-in + registered).",
    )
    @limiter.limit("120/minute")
    async def list_disclosure_tracks(
        request: Request,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[DisclosureTrackInfo]]:
        del request, auth
        from aila.modules.vr.disclosure import track_info_list

        return DataEnvelope(data=track_info_list())

    @router.post(
        "/disclosures",
        response_model=DataEnvelope[VRDisclosureSubmissionSummary],
        status_code=status.HTTP_201_CREATED,
        summary="Create a disclosure submission for a finding via one track.",
    )
    @limiter.limit("30/minute")
    async def create_disclosure(
        request: Request,
        body: VRDisclosureSubmissionCreate,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRDisclosureSubmissionSummary]:
        del request
        from aila.modules.vr.disclosure import (
            DisclosureService,
            DisclosureServiceError,
        )

        svc = DisclosureService()
        try:
            summary = await svc.create(body, team_id=auth.team_id)
        except DisclosureServiceError as exc:
            msg = str(exc)
            if "not found" in msg or "unknown track" in msg:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail=msg,
                ) from exc
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=msg,
            ) from exc
        return DataEnvelope(data=summary)

    @router.get(
        "/disclosures",
        response_model=DataEnvelope[list[VRDisclosureSubmissionSummary]],
        summary="List disclosure submissions (filterable).",
    )
    @limiter.limit("60/minute")
    async def list_disclosures(
        request: Request,
        finding_id: str | None = Query(default=None),
        workspace_id: str | None = Query(default=None),
        track_id: str | None = Query(default=None),
        submission_status: DisclosureSubmissionStatus | None = Query(
            default=None,
            alias="status",
        ),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=200),
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[VRDisclosureSubmissionSummary]]:
        del request, auth
        from aila.modules.vr.disclosure import DisclosureService

        svc = DisclosureService()
        items, total = await svc.list(
            finding_id=finding_id,
            workspace_id=workspace_id,
            track_id=track_id,
            status=submission_status,
            offset=offset,
            limit=limit,
        )
        return DataEnvelope(
            data=items,
            meta=PaginatedMeta(
                total=int(total), offset=offset, limit=limit,
            ).model_dump(),
        )

    @router.get(
        "/disclosures/{submission_id}",
        response_model=DataEnvelope[VRDisclosureSubmissionSummary],
        summary="Get one disclosure submission by id.",
    )
    @limiter.limit("120/minute")
    async def get_disclosure(
        request: Request,
        submission_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRDisclosureSubmissionSummary]:
        del request, auth
        from aila.modules.vr.disclosure import DisclosureService

        svc = DisclosureService()
        summary = await svc.get(submission_id)
        if summary is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Disclosure submission {submission_id} not found.",
            )
        return DataEnvelope(data=summary)

    @router.patch(
        "/disclosures/{submission_id}",
        response_model=DataEnvelope[VRDisclosureSubmissionSummary],
        summary="State transition + field updates for a disclosure submission.",
    )
    @limiter.limit("30/minute")
    async def patch_disclosure(
        request: Request,
        submission_id: str,
        body: VRDisclosureSubmissionPatch,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRDisclosureSubmissionSummary]:
        del request, auth
        from aila.modules.vr.disclosure import (
            DisclosureService,
            DisclosureServiceError,
        )

        svc = DisclosureService()
        try:
            summary = await svc.patch(submission_id, body)
        except DisclosureServiceError as exc:
            msg = str(exc)
            if "not found" in msg:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail=msg,
                ) from exc
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail=msg,
            ) from exc
        return DataEnvelope(data=summary)

    @router.post(
        "/disclosures/{submission_id}/render",
        response_model=DataEnvelope[RenderedSubmission],
        summary="Re-render the submission body (idempotent).",
    )
    @limiter.limit("60/minute")
    async def render_disclosure(
        request: Request,
        submission_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[RenderedSubmission]:
        del request, auth
        from aila.modules.vr.disclosure import (
            DisclosureService,
            DisclosureServiceError,
        )

        svc = DisclosureService()
        try:
            rendered = await svc.render(submission_id)
        except DisclosureServiceError as exc:
            msg = str(exc)
            if "not found" in msg or "disappeared" in msg:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail=msg,
                ) from exc
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=msg,
            ) from exc
        return DataEnvelope(data=rendered)

    # ── Fuzzing campaigns + crashes (Fuzzing plan) ─────────────────────

    @router.post(
        "/fuzz/campaigns",
        response_model=DataEnvelope[VRFuzzCampaignSummary],
        status_code=status.HTTP_201_CREATED,
        summary="Create a fuzzing campaign for a target.",
    )
    @limiter.limit("30/minute")
    async def create_fuzz_campaign(
        request: Request,
        body: VRFuzzCampaignCreate,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRFuzzCampaignSummary]:
        del request
        from aila.modules.vr.services import FuzzCampaignService, FuzzServiceError

        svc = FuzzCampaignService()
        try:
            summary = await svc.create_campaign(body, team_id=auth.team_id)
        except FuzzServiceError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=str(exc),
            ) from exc
        return DataEnvelope(data=summary)

    @router.get(
        "/fuzz/campaigns",
        response_model=DataEnvelope[list[VRFuzzCampaignSummary]],
        summary="List fuzzing campaigns (filterable).",
    )
    @limiter.limit("60/minute")
    async def list_fuzz_campaigns(
        request: Request,
        target_id: str | None = Query(default=None),
        workspace_id: str | None = Query(default=None),
        campaign_status: CampaignStatus | None = Query(
            default=None, alias="status",
        ),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=200),
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[VRFuzzCampaignSummary]]:
        del request, auth
        from aila.modules.vr.services import FuzzCampaignService

        svc = FuzzCampaignService()
        items, total = await svc.list_campaigns(
            target_id=target_id,
            workspace_id=workspace_id,
            status=campaign_status,
            offset=offset,
            limit=limit,
        )
        return DataEnvelope(
            data=items,
            meta=PaginatedMeta(
                total=int(total), offset=offset, limit=limit,
            ).model_dump(),
        )

    @router.get(
        "/fuzz/campaigns/{campaign_id}",
        response_model=DataEnvelope[VRFuzzCampaignSummary],
        summary="Get one fuzzing campaign by id.",
    )
    @limiter.limit("120/minute")
    async def get_fuzz_campaign(
        request: Request,
        campaign_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRFuzzCampaignSummary]:
        del request, auth
        from aila.modules.vr.services import FuzzCampaignService

        svc = FuzzCampaignService()
        summary = await svc.get_campaign(campaign_id)
        if summary is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Fuzz campaign {campaign_id} not found.",
            )
        return DataEnvelope(data=summary)

    @router.patch(
        "/fuzz/campaigns/{campaign_id}",
        response_model=DataEnvelope[VRFuzzCampaignSummary],
        summary="Update campaign status + progress metrics.",
    )
    @limiter.limit("60/minute")  # progress updates can be frequent
    async def patch_fuzz_campaign(
        request: Request,
        campaign_id: str,
        body: VRFuzzCampaignPatch,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRFuzzCampaignSummary]:
        del request, auth
        from aila.modules.vr.services import FuzzCampaignService, FuzzServiceError

        svc = FuzzCampaignService()
        try:
            summary = await svc.patch_campaign(campaign_id, body)
        except FuzzServiceError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=str(exc),
            ) from exc
        return DataEnvelope(data=summary)

    @router.post(
        "/fuzz/crashes",
        response_model=DataEnvelope[VRFuzzCrashSummary],
        status_code=status.HTTP_201_CREATED,
        summary=(
            "Register a crash. Auto-dedup by stack hash + auto-triage by "
            "crash_type pattern matching."
        ),
    )
    @limiter.limit("120/minute")  # workers may post crashes frequently
    async def register_fuzz_crash(
        request: Request,
        body: VRFuzzCrashCreate,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRFuzzCrashSummary]:
        del request
        from aila.modules.vr.services import FuzzCampaignService, FuzzServiceError

        svc = FuzzCampaignService()
        try:
            summary = await svc.register_crash(body, team_id=auth.team_id)
        except FuzzServiceError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=str(exc),
            ) from exc
        return DataEnvelope(data=summary)

    @router.get(
        "/fuzz/crashes",
        response_model=DataEnvelope[list[VRFuzzCrashSummary]],
        summary="List fuzz crashes (filterable by campaign/verdict/severity).",
    )
    @limiter.limit("60/minute")
    async def list_fuzz_crashes(
        request: Request,
        campaign_id: str | None = Query(default=None),
        verdict: CrashTriageVerdict | None = Query(default=None),
        severity: CrashSeverity | None = Query(default=None),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=200),
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[VRFuzzCrashSummary]]:
        del request, auth
        from aila.modules.vr.services import FuzzCampaignService

        svc = FuzzCampaignService()
        items, total = await svc.list_crashes(
            campaign_id=campaign_id,
            verdict=verdict,
            severity=severity,
            offset=offset,
            limit=limit,
        )
        return DataEnvelope(
            data=items,
            meta=PaginatedMeta(
                total=int(total), offset=offset, limit=limit,
            ).model_dump(),
        )

    @router.get(
        "/fuzz/crashes/{crash_id}",
        response_model=DataEnvelope[VRFuzzCrashSummary],
        summary="Get one fuzz crash by id.",
    )
    @limiter.limit("120/minute")
    async def get_fuzz_crash(
        request: Request,
        crash_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRFuzzCrashSummary]:
        del request, auth
        from aila.modules.vr.services import FuzzCampaignService

        svc = FuzzCampaignService()
        summary = await svc.get_crash(crash_id)
        if summary is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Fuzz crash {crash_id} not found.",
            )
        return DataEnvelope(data=summary)

    # ── Multi-target investigation attachments (v0.4 GA-49) ────────────

    @router.post(
        "/investigations/{investigation_id}/targets",
        response_model=DataEnvelope[VRInvestigationTargetSummary],
        status_code=status.HTTP_201_CREATED,
        summary="Attach a secondary target to an investigation.",
    )
    @limiter.limit("30/minute")
    async def attach_investigation_target(
        request: Request,
        investigation_id: str,
        body: VRInvestigationTargetAttach,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRInvestigationTargetSummary]:
        del request
        from aila.modules.vr.services import (
            MultiTargetService,
            MultiTargetServiceError,
        )

        svc = MultiTargetService()
        try:
            summary = await svc.attach(
                investigation_id=investigation_id,
                target_id=body.target_id,
                role=body.role,
                rationale=body.rationale,
                team_id=auth.team_id,
            )
        except MultiTargetServiceError as exc:
            msg = str(exc)
            if "not found" in msg:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail=msg,
                ) from exc
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail=msg,
            ) from exc
        return DataEnvelope(data=summary)

    @router.get(
        "/investigations/{investigation_id}/targets",
        response_model=DataEnvelope[list[VRInvestigationTargetSummary]],
        summary="List secondary targets attached to an investigation.",
    )
    @limiter.limit("120/minute")
    async def list_investigation_targets(
        request: Request,
        investigation_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[VRInvestigationTargetSummary]]:
        del request, auth
        from aila.modules.vr.services import MultiTargetService

        svc = MultiTargetService()
        items = await svc.list_for_investigation(investigation_id)
        return DataEnvelope(data=items)

    @router.delete(
        "/investigations/{investigation_id}/targets/{target_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Detach a secondary target (primary cannot be detached).",
    )
    @limiter.limit("30/minute")
    async def detach_investigation_target(
        request: Request,
        investigation_id: str,
        target_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> Response:
        del request, auth
        from aila.modules.vr.services import (
            MultiTargetService,
            MultiTargetServiceError,
        )

        svc = MultiTargetService()
        try:
            removed = await svc.detach(investigation_id, target_id)
        except MultiTargetServiceError as exc:
            msg = str(exc)
            if "not found" in msg:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail=msg,
                ) from exc
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail=msg,
            ) from exc
        if not removed:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    f"target {target_id} is not attached to "
                    f"investigation {investigation_id}"
                ),
            )
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    # ── Multi-strategy parallel branches (v0.4 GA-50) ──────────────────

    @router.post(
        "/investigations/{investigation_id}/strategy-branches",
        response_model=DataEnvelope[dict],
        status_code=status.HTTP_201_CREATED,
        summary="Spawn a new branch tagged with a strategy_family.",
    )
    @limiter.limit("30/minute")
    async def spawn_strategy_branch(
        request: Request,
        investigation_id: str,
        body: StrategyBranchSpawn,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict]:
        del request, auth
        from aila.modules.vr.agents.branch_manager import (
            BranchManager,
            BranchManagerError,
        )

        mgr = BranchManager(investigation_id=investigation_id)
        try:
            result = await mgr.spawn_strategy(
                strategy_family=body.strategy_family,
                persona_voice=body.persona_voice.value if body.persona_voice else None,
                rationale=body.rationale,
                parent_branch_id=body.parent_branch_id,
            )
        except BranchManagerError as exc:
            msg = str(exc)
            code = (
                status.HTTP_404_NOT_FOUND
                if "not found" in msg
                else status.HTTP_409_CONFLICT
            )
            raise HTTPException(status_code=code, detail=msg) from exc
        return DataEnvelope(
            data={
                "op": result.op.value,
                "investigation_id": result.investigation_id,
                "new_branch_id": result.new_branch_id,
                "parent_branch_id": (
                    result.affected_branch_ids[0]
                    if result.affected_branch_ids
                    else None
                ),
                "strategy_family": body.strategy_family,
                "reason": result.reason,
            },
        )

    @router.get(
        "/investigations/{investigation_id}/strategy-branches",
        response_model=DataEnvelope[dict],
        summary="Active branches grouped by strategy_family.",
    )
    @limiter.limit("120/minute")
    async def list_strategy_branches(
        request: Request,
        investigation_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict]:
        del request, auth
        from aila.modules.vr.agents.branch_manager import BranchManager

        mgr = BranchManager(investigation_id=investigation_id)
        groups = await mgr.list_active_by_strategy()
        return DataEnvelope(
            data={
                "investigation_id": investigation_id,
                "strategy_groups": groups,
                "total_active_branches": sum(len(v) for v in groups.values()),
            },
        )

    # ── CVE feed (v0.4 GA-51) ──────────────────────────────────────────

    @router.post(
        "/cves",
        response_model=DataEnvelope[dict],
        status_code=status.HTTP_201_CREATED,
        summary=(
            "Ingest a CVE record. Idempotent on cve_id; scans audit memos "
            "for similarity matches on first insert."
        ),
    )
    @limiter.limit("60/minute")
    async def ingest_cve(
        request: Request,
        body: VRCVERecordCreate,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict]:
        del request, auth
        from aila.modules.vr.services import CVEService
        from aila.platform.services.knowledge import KnowledgeService

        svc = CVEService(knowledge=KnowledgeService())
        result = await svc.ingest_cve(body)
        return DataEnvelope(
            data={
                "cve": result.cve.model_dump(mode="json"),
                "inserted": result.inserted,
                "invalidation_events": [
                    e.model_dump(mode="json") for e in result.invalidation_events
                ],
            },
        )

    @router.get(
        "/cves",
        response_model=DataEnvelope[list[CVERecordSummary]],
        summary="List ingested CVE records.",
    )
    @limiter.limit("60/minute")
    async def list_cves(
        request: Request,
        source: CVEFeedSource | None = Query(default=None),
        min_cvss: float | None = Query(default=None, ge=0, le=10),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=200),
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[CVERecordSummary]]:
        del request, auth
        from aila.modules.vr.services import CVEService
        from aila.platform.services.knowledge import KnowledgeService

        svc = CVEService(knowledge=KnowledgeService())
        items, total = await svc.list_cves(
            source=source, min_cvss=min_cvss, offset=offset, limit=limit,
        )
        return DataEnvelope(
            data=items,
            meta=PaginatedMeta(
                total=int(total), offset=offset, limit=limit,
            ).model_dump(),
        )

    @router.get(
        "/cves/{cve_id}",
        response_model=DataEnvelope[CVERecordSummary],
        summary="Get one CVE record by cve_id (e.g. CVE-2026-1234).",
    )
    @limiter.limit("120/minute")
    async def get_cve(
        request: Request,
        cve_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[CVERecordSummary]:
        del request, auth
        from aila.modules.vr.services import CVEService
        from aila.platform.services.knowledge import KnowledgeService

        svc = CVEService(knowledge=KnowledgeService())
        summary = await svc.get(cve_id)
        if summary is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"CVE {cve_id} not found.",
            )
        return DataEnvelope(data=summary)

    return router
