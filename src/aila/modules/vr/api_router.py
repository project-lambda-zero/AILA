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

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, Response, UploadFile, status
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
    AnalysisState,
    BranchStatus,
    CampaignStatus,
    CrashSeverity,
    CrashTriageEvent,
    CrashTriageVerdict,
    CVEFeedSource,
    CVERecordSummary,
    DisclosureStatus,
    DisclosureSubmissionStatus,
    DisclosureTrackInfo,
    EvidenceGraphEdge,
    EvidenceGraphNode,
    EvidenceGraphSnapshot,
    FuzzTelemetryCreate,
    FuzzTelemetryPoint,
    HypothesisProjection,
    HypothesisState,
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
    VREventEnvelope,
    VREventType,
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


def _summary_from_record(
    record: Any,
    finding_count: int = 0,
    *,
    latest_disclosure_status: str | None = None,
    disclosure_submission_count: int = 0,
) -> VRProjectSummary:
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
        operator_id=getattr(record, "created_by", None),
        latest_disclosure_status=latest_disclosure_status,
        disclosure_submission_count=disclosure_submission_count,
        analysis_system_id=getattr(record, "analysis_system_id", None),
        poc_system_id=getattr(record, "poc_system_id", None),
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

    handles = _json.loads(record.mcp_handles_json or "{}")
    uploaded_filename = handles.get("uploaded_filename")
    if not isinstance(uploaded_filename, str):
        uploaded_filename = None

    return VRTargetSummary(
        id=record.id,
        workspace_id=record.workspace_id,
        display_name=record.display_name,
        kind=TargetKind(record.kind),
        descriptor=_json.loads(record.descriptor_json or "{}"),
        uploaded_filename=uploaded_filename,
        primary_language=record.primary_language,
        secondary_languages=_json.loads(record.secondary_languages_json or "[]"),
        status=TargetStatus(record.status),
        analysis_state=AnalysisState(record.analysis_state),
        analysis_state_message=record.analysis_state_message,
        analysis_started_at=(
            record.analysis_started_at.isoformat()
            if record.analysis_started_at else None
        ),
        analysis_completed_at=(
            record.analysis_completed_at.isoformat()
            if record.analysis_completed_at else None
        ),
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
        from .db_models import (
            VRDisclosureSubmissionRecord,
            VRFindingRecord,
            VRProjectRecord,
        )

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
            disclosure_by_project: dict[str, tuple[str | None, int]] = {}
            if rows:
                project_ids = [r.id for r in rows]
                count_rows = (await uow.session.exec(
                    select(VRFindingRecord.project_id, sa_func.count())
                    .where(VRFindingRecord.project_id.in_(project_ids))
                    .group_by(VRFindingRecord.project_id)
                )).all()
                counts_by_project = {pid: int(n) for pid, n in count_rows}

                # Aggregate disclosure submissions by joining findings →
                # disclosure_submissions. The "latest" status is the
                # max(updated_at) row's status per project; the count is
                # the number of submissions across all findings of the
                # project.
                disclosure_rows = (await uow.session.exec(
                    select(
                        VRFindingRecord.project_id,
                        VRDisclosureSubmissionRecord.status,
                        VRDisclosureSubmissionRecord.updated_at,
                    )
                    .join(
                        VRDisclosureSubmissionRecord,
                        VRDisclosureSubmissionRecord.finding_id
                        == VRFindingRecord.id,
                    )
                    .where(VRFindingRecord.project_id.in_(project_ids))
                )).all()
                # Pick the latest per project + count submissions.
                latest: dict[str, tuple[str, Any]] = {}
                count_subs: dict[str, int] = {}
                for pid, sub_status, sub_updated in disclosure_rows:
                    count_subs[pid] = count_subs.get(pid, 0) + 1
                    prev = latest.get(pid)
                    if prev is None or (
                        sub_updated is not None
                        and (prev[1] is None or sub_updated > prev[1])
                    ):
                        latest[pid] = (sub_status, sub_updated)
                disclosure_by_project = {
                    pid: (latest[pid][0], count_subs[pid])
                    for pid in latest
                }

        items = [
            _summary_from_record(
                r,
                counts_by_project.get(r.id, 0),
                latest_disclosure_status=(
                    disclosure_by_project.get(r.id, (None, 0))[0]
                ),
                disclosure_submission_count=(
                    disclosure_by_project.get(r.id, (None, 0))[1]
                ),
            )
            for r in rows
        ]
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
                created_by=auth.user_id,
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
        from .db_models import (
            VRDisclosureSubmissionRecord,
            VRFindingRecord,
            VRProjectRecord,
        )

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

            # Aggregate disclosure submissions across all of the
            # project's findings; the most recently updated submission
            # provides the headline status (mirrors list_projects).
            sub_rows = (await uow.session.exec(
                select(
                    VRDisclosureSubmissionRecord.status,
                    VRDisclosureSubmissionRecord.updated_at,
                )
                .join(
                    VRFindingRecord,
                    VRFindingRecord.id == VRDisclosureSubmissionRecord.finding_id,
                )
                .where(VRFindingRecord.project_id == project_id)
            )).all()
            latest_status: str | None = None
            latest_ts: Any = None
            for sub_status, sub_updated in sub_rows:
                if latest_status is None or (
                    sub_updated is not None
                    and (latest_ts is None or sub_updated > latest_ts)
                ):
                    latest_status = sub_status
                    latest_ts = sub_updated

        return DataEnvelope(
            data=_summary_from_record(
                project,
                finding_count,
                latest_disclosure_status=latest_status,
                disclosure_submission_count=len(sub_rows),
            )
        )

    @router.get(
        "/projects/{project_id}/events",
        summary=(
            "Typed SSE event stream for one project. Multiplexes "
            "message.created / branch.state_changed / outcome.created "
            "across all of the project's investigations and "
            "campaign.crash_found / campaign.progress across its "
            "fuzz campaigns (08_FRONTEND_UX.md §2.1)."
        ),
        response_class=StreamingResponse,
        responses={
            200: {
                "description": "SSE stream of typed VREventEnvelope events.",
                "content": {"text/event-stream": {"schema": {"type": "string"}}},
            },
        },
    )
    @limiter.limit("30/minute")
    async def stream_project_events(
        request: Request,
        project_id: str,
        since_iso: str | None = Query(
            default=None,
            description="ISO-8601 timestamp; only events newer than this are streamed.",
        ),
        auth: AuthContext = Depends(require_auth),
    ) -> StreamingResponse:
        del request
        from datetime import datetime as _dt

        from .db_models import (
            VRFuzzCampaignRecord,
            VRFuzzCrashRecord,
            VRInvestigationBranchRecord,
            VRInvestigationMessageRecord,
            VRInvestigationOutcomeRecord,
            VRInvestigationRecord,
            VRProjectRecord,
        )

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                _team_filter(
                    select(VRProjectRecord).where(
                        VRProjectRecord.id == project_id,
                    ),
                    VRProjectRecord, auth,
                )
            )).first()
            if project is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"VR project {project_id!r} not found.",
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

            open_env = VREventEnvelope(
                type=VREventType.HEARTBEAT,
                ts=utc_now().isoformat(),
                project_id=project_id,
                payload={"connected": True},
            )
            yield (
                "event: open\n"
                f"data: {_json.dumps(open_env.model_dump(mode='json'))}\n\n"
            )

            while True:
                async with UnitOfWork() as poll_uow:
                    # All investigations rooted at this project.
                    inv_ids = [
                        row.id
                        for row in (await poll_uow.session.exec(
                            select(VRInvestigationRecord).where(
                                VRInvestigationRecord.project_id == project_id,
                            )
                        )).all()
                    ]
                    # All campaigns whose target is the project's target.
                    camp_rows = (await poll_uow.session.exec(
                        select(VRFuzzCampaignRecord).where(
                            VRFuzzCampaignRecord.target_id == project.target_id,
                        )
                    )).all() if project.target_id else []
                    camp_ids = [c.id for c in camp_rows]

                    new_messages = (
                        (await poll_uow.session.exec(
                            select(VRInvestigationMessageRecord)
                            .where(
                                VRInvestigationMessageRecord.investigation_id.in_(inv_ids),
                                VRInvestigationMessageRecord.created_at > local_cursor,
                            )
                            .order_by(VRInvestigationMessageRecord.created_at.asc())
                            .limit(_SSE_BATCH_LIMIT)
                        )).all()
                        if inv_ids else []
                    )
                    new_branches = (
                        (await poll_uow.session.exec(
                            select(VRInvestigationBranchRecord)
                            .where(
                                VRInvestigationBranchRecord.investigation_id.in_(inv_ids),
                                VRInvestigationBranchRecord.updated_at > local_cursor,
                            )
                            .order_by(VRInvestigationBranchRecord.updated_at.asc())
                            .limit(_SSE_BATCH_LIMIT)
                        )).all()
                        if inv_ids else []
                    )
                    new_outcomes = (
                        (await poll_uow.session.exec(
                            select(VRInvestigationOutcomeRecord)
                            .where(
                                VRInvestigationOutcomeRecord.investigation_id.in_(inv_ids),
                                VRInvestigationOutcomeRecord.created_at > local_cursor,
                            )
                            .order_by(VRInvestigationOutcomeRecord.created_at.asc())
                            .limit(_SSE_BATCH_LIMIT)
                        )).all()
                        if inv_ids else []
                    )
                    new_crashes = (
                        (await poll_uow.session.exec(
                            select(VRFuzzCrashRecord)
                            .where(
                                VRFuzzCrashRecord.campaign_id.in_(camp_ids),
                                VRFuzzCrashRecord.discovered_at > local_cursor,
                            )
                            .order_by(VRFuzzCrashRecord.discovered_at.asc())
                            .limit(_SSE_BATCH_LIMIT)
                        )).all()
                        if camp_ids else []
                    )

                # Emit each in chronological order across all sources.
                events: list[tuple[Any, str, dict[str, Any]]] = []
                for m in new_messages:
                    is_op = m.sender == SenderKind.OPERATOR.value
                    events.append((
                        m.created_at,
                        (
                            VREventType.OPERATOR_STEERING.value
                            if is_op else VREventType.MESSAGE_CREATED.value
                        ),
                        {
                            "investigation_id": m.investigation_id,
                            "branch_id": m.branch_id,
                            "payload": _message_summary(m).model_dump(mode="json"),
                        },
                    ))
                for b in new_branches:
                    events.append((
                        b.updated_at,
                        VREventType.HYPOTHESIS_STATE_CHANGED.value,
                        {
                            "investigation_id": b.investigation_id,
                            "branch_id": b.id,
                            "payload": _branch_summary(b).model_dump(mode="json"),
                        },
                    ))
                for o in new_outcomes:
                    events.append((
                        o.created_at,
                        VREventType.OUTCOME_CREATED.value,
                        {
                            "investigation_id": o.investigation_id,
                            "payload": {
                                "id": o.id,
                                "kind": o.kind,
                                "branch_id": o.branch_id,
                            },
                        },
                    ))
                for c in new_crashes:
                    events.append((
                        c.discovered_at,
                        VREventType.CAMPAIGN_CRASH_FOUND.value,
                        {
                            "payload": {
                                "id": c.id,
                                "campaign_id": c.campaign_id,
                                "crash_type": c.crash_type,
                                "severity": c.severity,
                                "stack_hash": c.stack_hash,
                            },
                        },
                    ))
                events.sort(key=lambda e: e[0] or utc_now())
                advanced = local_cursor
                for ts_, type_, body in events:
                    envelope = VREventEnvelope(
                        type=VREventType(type_),
                        ts=ts_.isoformat() if ts_ else utc_now().isoformat(),
                        project_id=project_id,
                        investigation_id=body.get("investigation_id"),
                        branch_id=body.get("branch_id"),
                        campaign_id=body.get("payload", {}).get("campaign_id"),
                        payload=body.get("payload", {}),
                    )
                    yield (
                        f"event: {type_}\n"
                        f"data: {_json.dumps(envelope.model_dump(mode='json'))}\n\n"
                    )
                    if ts_ and ts_ > advanced:
                        advanced = ts_
                local_cursor = advanced

                now = utc_now()
                if (now - last_heartbeat).total_seconds() >= _SSE_HEARTBEAT_S:
                    heartbeat_env = VREventEnvelope(
                        type=VREventType.HEARTBEAT,
                        ts=now.isoformat(),
                        project_id=project_id,
                    )
                    yield (
                        "event: heartbeat\n"
                        f"data: {_json.dumps(heartbeat_env.model_dump(mode='json'))}\n\n"
                    )
                    last_heartbeat = now

                await asyncio.sleep(_SSE_POLL_INTERVAL_S)

        return StreamingResponse(
            _generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    @router.delete(
        "/projects/{project_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        summary=(
            "Delete a VR project and all of its findings. Targets created "
            "from this project's spec are NOT deleted — they live in the "
            "workspace independently."
        ),
    )
    @limiter.limit("10/minute")
    async def delete_project(
        request: Request,
        project_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> Response:
        del request
        from .db_models import VRFindingRecord, VRProjectRecord

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(VRProjectRecord).where(VRProjectRecord.id == project_id),
            )).first()
            if project is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"VR project {project_id!r} not found.",
                )
            _require_project_ownership(project, auth)

            findings = (await uow.session.exec(
                select(VRFindingRecord).where(VRFindingRecord.project_id == project_id),
            )).all()
            for f in findings:
                await uow.session.delete(f)
            await uow.session.delete(project)
            await uow.session.commit()

        return Response(status_code=status.HTTP_204_NO_CONTENT)

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
        import json as _json

        from aila.api.deps import get_task_queue

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
            )
            uow.session.add(record)
            await uow.session.commit()
            await uow.session.refresh(record)
            target_id = record.id

        # Auto-enqueue backend ingestion (v0.4.5). Operator does not
        # have to click anything — the dispatch starts immediately.
        try:
            from .workflow.task import run_target_analysis

            task_queue = get_task_queue("vr", request)
            await task_queue.submit(
                track="vr",
                fn=run_target_analysis,
                kwargs={"target_id": target_id},
                user_id=auth.user_id,
                group_id=auth.role,
                team_id=auth.team_id,
            )
        except (OSError, RuntimeError, HTTPException) as exc:
            # Don't fail the create — operator can retry analyze
            # via POST /vr/targets/{id}/analyze. Persist the reason
            # on the row so the UI shows it.
            async with UnitOfWork() as uow:
                row = (await uow.session.exec(
                    select(VRTargetRecord).where(VRTargetRecord.id == target_id),
                )).first()
                if row is not None:
                    row.analysis_state = AnalysisState.FAILED.value
                    row.analysis_state_message = (
                        f"failed to enqueue ingestion: {exc}"
                    )
                    uow.session.add(row)
                    await uow.session.commit()

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
        "/targets/{target_id}/analyze",
        response_model=DataEnvelope[dict],
        status_code=status.HTTP_202_ACCEPTED,
        summary=(
            "Re-run the backend ingestion pipeline for a target. "
            "Idempotent — also runs automatically on target create."
        ),
    )
    @limiter.limit("10/minute")
    async def enqueue_analyze(
        request: Request,
        target_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict]:
        from aila.api.deps import get_task_queue

        from .db_models import VRTargetRecord
        from .workflow.task import run_target_analysis

        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _team_filter(
                    select(VRTargetRecord).where(VRTargetRecord.id == target_id),
                    VRTargetRecord, auth,
                ),
            )).first()
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Target {target_id} not found.",
                )

        task_queue = get_task_queue("vr", request)
        handle = await task_queue.submit(
            track="vr",
            fn=run_target_analysis,
            kwargs={"target_id": target_id},
            user_id=auth.user_id,
            group_id=auth.role,
            team_id=auth.team_id,
        )
        return DataEnvelope(data={"task_id": handle.task_id, "target_id": target_id})


    @router.post(
        "/targets/{target_id}/upload",
        response_model=DataEnvelope[dict],
        status_code=status.HTTP_202_ACCEPTED,
        summary=(
            "Upload a binary artifact for a native_binary / kernel_image / "
            "hypervisor_image / apk / ipa / jar / dotnet_assembly target. "
            "AILA streams the bytes through to the IDA MCP and stores the "
            "returned binary handle in the target. Re-triggers analysis."
        ),
    )
    @limiter.limit("10/minute")
    async def upload_target_artifact(
        request: Request,
        target_id: str,
        file: UploadFile = File(...),
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict]:
        from aila.api.deps import get_task_queue

        from .db_models import VRTargetRecord
        from .tools.ida_bridge import IDABridgeTool
        from .workflow.task import run_target_analysis

        # 1) Resolve target + verify kind is uploadable.
        upload_kinds = {
            "native_binary", "kernel_image", "kernel_module",
            "hypervisor_image", "apk", "ipa", "jar", "dotnet_assembly",
        }
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _team_filter(
                    select(VRTargetRecord).where(VRTargetRecord.id == target_id),
                    VRTargetRecord, auth,
                ),
            )).first()
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Target {target_id} not found.",
                )
            if row.kind not in upload_kinds:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Target kind {row.kind!r} does not accept uploads.",
                )

        # 2) Stream file → IDA MCP /upload. AILA holds bytes in flight but
        #    never writes them to disk (D-33: no work in the platform).
        if not file.filename:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="file.filename is required.",
            )

        import httpx  # noqa: PLC0415  (transit-only proxy; see whitelist)

        bridge = IDABridgeTool()
        base_url = await bridge._resolve_base_url()  # noqa: SLF001
        try:
            async with httpx.AsyncClient(timeout=300.0) as client:
                resp = await client.post(
                    f"{base_url}/upload",
                    files={
                        "file": (
                            file.filename,
                            file.file,
                            file.content_type or "application/octet-stream",
                        ),
                    },
                )
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"IDA MCP at {base_url} unreachable: {exc}",
            ) from exc
        try:
            mcp_result = resp.json()
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"IDA MCP returned non-JSON: {resp.text[:200]}",
            ) from exc
        if resp.status_code >= 400 or mcp_result.get("status") == "error":
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"IDA MCP upload failed: {mcp_result.get('error', resp.text[:200])}",
            )

        binary_id = mcp_result.get("binary_id") or mcp_result.get("data", {}).get("binary_id")
        if not binary_id:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"IDA MCP upload returned no binary_id: {mcp_result!r}",
            )

        # 3) Persist binary_id + filename into _mcp_handles_json (internal).
        #    Operators only see "Ready" — they don't see this id.
        import json as _json
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                select(VRTargetRecord).where(VRTargetRecord.id == target_id),
            )).first()
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Target {target_id} vanished mid-upload.",
                )
            handles = _json.loads(row.mcp_handles_json or "{}")
            handles.update({
                "binary_id": binary_id,
                "uploaded_filename": file.filename,
                "uploaded_sha256": mcp_result.get("sha256"),
            })
            row.mcp_handles_json = _json.dumps(handles)
            uow.session.add(row)
            await uow.session.commit()

        # 4) Re-enqueue analysis so capability profile + ranking refresh.
        task_queue = get_task_queue("vr", request)
        handle = await task_queue.submit(
            track="vr",
            fn=run_target_analysis,
            kwargs={"target_id": target_id},
            user_id=auth.user_id,
            group_id=auth.role,
            team_id=auth.team_id,
        )
        return DataEnvelope(
            data={
                "task_id": handle.task_id,
                "target_id": target_id,
                "uploaded_filename": file.filename,
            },
        )

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

    @router.delete(
        "/investigations/{investigation_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        summary=(
            "Delete an investigation and all of its branches, messages, "
            "outcomes, and target join rows. Patterns referencing this "
            "investigation are de-linked (investigation_id → NULL)."
        ),
    )
    @limiter.limit("10/minute")
    async def delete_investigation(
        request: Request,
        investigation_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> Response:
        del request
        from .db_models import (
            VRInvestigationBranchRecord,
            VRInvestigationMessageRecord,
            VRInvestigationOutcomeRecord,
            VRInvestigationRecord,
            VRInvestigationTargetRecord,
            VRPatternRecord,
        )

        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _team_filter(
                    select(VRInvestigationRecord).where(
                        VRInvestigationRecord.id == investigation_id,
                    ),
                    VRInvestigationRecord, auth,
                ),
            )).first()
            if inv is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Investigation {investigation_id} not found.",
                )

            # De-link patterns (nullable FK).
            patterns = (await uow.session.exec(
                select(VRPatternRecord).where(
                    VRPatternRecord.investigation_id == investigation_id,
                ),
            )).all()
            for p in patterns:
                p.investigation_id = None
                uow.session.add(p)

            # Hard-delete child rows in FK-safe order.
            for model in (
                VRInvestigationMessageRecord,
                VRInvestigationOutcomeRecord,
                VRInvestigationTargetRecord,
                VRInvestigationBranchRecord,
            ):
                rows = (await uow.session.exec(
                    select(model).where(model.investigation_id == investigation_id),
                )).all()
                for r in rows:
                    await uow.session.delete(r)

            await uow.session.delete(inv)
            await uow.session.commit()

        return Response(status_code=status.HTTP_204_NO_CONTENT)

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
                    # Discriminate operator-steering messages from
                    # agent turns so the consumer can branch on the
                    # typed event name without parsing the payload
                    # (08_FRONTEND_UX.md §2.1).
                    is_operator = row.sender == SenderKind.OPERATOR.value
                    event_type = (
                        VREventType.OPERATOR_STEERING
                        if is_operator
                        else VREventType.MESSAGE_CREATED
                    )
                    envelope = VREventEnvelope(
                        type=event_type,
                        ts=(
                            row.created_at.isoformat()
                            if row.created_at else utc_now().isoformat()
                        ),
                        investigation_id=investigation_id,
                        branch_id=row.branch_id,
                        payload=summary.model_dump(mode="json"),
                    )
                    yield (
                        f"event: {event_type.value}\n"
                        f"data: {_json.dumps(envelope.model_dump(mode='json'))}\n\n"
                    )
                    if row.created_at and row.created_at > local_cursor:
                        local_cursor = row.created_at

                now = utc_now()
                if (now - last_heartbeat).total_seconds() >= _SSE_HEARTBEAT_S:
                    heartbeat_env = VREventEnvelope(
                        type=VREventType.HEARTBEAT,
                        ts=now.isoformat(),
                        investigation_id=investigation_id,
                    )
                    yield (
                        "event: heartbeat\n"
                        f"data: {_json.dumps(heartbeat_env.model_dump(mode='json'))}\n\n"
                    )
                    last_heartbeat = now

                if status_row in terminal and not rows:
                    done_env = VREventEnvelope(
                        type=VREventType.DONE,
                        ts=now.isoformat(),
                        investigation_id=investigation_id,
                        payload={"status": status_row},
                    )
                    yield (
                        "event: done\n"
                        f"data: {_json.dumps(done_env.model_dump(mode='json'))}\n\n"
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

    @router.get(
        "/investigations/{investigation_id}/hypotheses",
        response_model=DataEnvelope[list[HypothesisProjection]],
        summary=(
            "Aggregate live + rejected hypotheses across the "
            "investigation's branches (08_FRONTEND_UX.md §2.3)."
        ),
    )
    @limiter.limit("60/minute")
    async def list_investigation_hypotheses(
        request: Request,
        investigation_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[HypothesisProjection]]:
        del request
        import json as _json

        inv = await _load_investigation(investigation_id, auth)
        if inv is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation {investigation_id} not found.",
            )
        from .db_models import VRInvestigationBranchRecord

        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.investigation_id
                    == investigation_id,
                )
            )).all()

        # hyp id → projection (built up as we walk branches)
        live_branches: dict[str, list[str]] = {}
        rejected_branches: dict[str, list[str]] = {}
        claims: dict[str, dict[str, str]] = {}
        rejection_reasons: dict[str, str] = {}

        for b in rows:
            try:
                state = _json.loads(b.case_state_json or "{}")
            except (ValueError, TypeError):
                continue
            for h in state.get("hypotheses", []) or []:
                hid = h.get("id")
                if not hid:
                    continue
                live_branches.setdefault(hid, []).append(b.id)
                claims.setdefault(hid, {
                    "claim": h.get("claim", ""),
                    "why_plausible": h.get("why_plausible", ""),
                    "kill_criterion": h.get("kill_criterion", ""),
                })
            for h in state.get("rejected", []) or []:
                hid = h.get("id")
                if not hid:
                    continue
                rejected_branches.setdefault(hid, []).append(b.id)
                claims.setdefault(hid, {
                    "claim": h.get("claim", ""),
                    "why_plausible": "",
                    "kill_criterion": "",
                })
                if h.get("reason"):
                    rejection_reasons.setdefault(hid, h["reason"])

        all_ids = set(live_branches) | set(rejected_branches)
        items: list[HypothesisProjection] = []
        for hid in sorted(all_ids):
            live = live_branches.get(hid, [])
            rejected = rejected_branches.get(hid, [])
            if live and rejected:
                hstate = HypothesisState.MIXED
            elif rejected:
                hstate = HypothesisState.REJECTED
            else:
                hstate = HypothesisState.LIVE
            c = claims.get(hid, {})
            items.append(HypothesisProjection(
                id=hid,
                claim=c.get("claim", ""),
                why_plausible=c.get("why_plausible", ""),
                kill_criterion=c.get("kill_criterion", ""),
                state=hstate,
                rejection_reason=rejection_reasons.get(hid),
                live_in_branches=live,
                rejected_in_branches=rejected,
            ))

        return DataEnvelope(data=items)

    @router.get(
        "/investigations/{investigation_id}/evidence-graph",
        response_model=DataEnvelope[EvidenceGraphSnapshot],
        summary=(
            "Server-side computed evidence graph for one investigation "
            "with deterministic layout (08_FRONTEND_UX.md §1.9)."
        ),
    )
    @limiter.limit("60/minute")
    async def get_evidence_graph(
        request: Request,
        investigation_id: str,
        layout: str = Query(default="concentric", pattern="^(concentric|grid|radial)$"),
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[EvidenceGraphSnapshot]:
        del request
        import math

        inv = await _load_investigation(investigation_id, auth)
        if inv is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation {investigation_id} not found.",
            )
        from .db_models import (
            VRInvestigationBranchRecord,
            VRInvestigationOutcomeRecord,
        )

        async with UnitOfWork() as uow:
            branches = (await uow.session.exec(
                select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.investigation_id
                    == investigation_id,
                )
            )).all()
            outcomes = (await uow.session.exec(
                select(VRInvestigationOutcomeRecord).where(
                    VRInvestigationOutcomeRecord.investigation_id
                    == investigation_id,
                )
            )).all()

        nodes: list[EvidenceGraphNode] = []
        edges: list[EvidenceGraphEdge] = []

        # Root investigation node at origin.
        nodes.append(EvidenceGraphNode(
            id=f"inv:{investigation_id}",
            kind="investigation",
            label=f"Investigation {investigation_id[:8]}",
            state=inv.status,
            x=0.0,
            y=0.0,
        ))

        # Place branches on inner ring (concentric) / row 1 (grid) /
        # primary spokes (radial).
        radius_branch = 220.0
        n_branches = max(len(branches), 1)
        for i, b in enumerate(branches):
            if layout == "grid":
                x = (i % 4) * 200 - 300
                y = 200.0
            elif layout == "radial":
                angle = (2 * math.pi * i / n_branches) - math.pi / 2
                x = radius_branch * math.cos(angle)
                y = radius_branch * math.sin(angle)
            else:
                angle = (2 * math.pi * i / n_branches) - math.pi / 2
                x = radius_branch * math.cos(angle)
                y = radius_branch * math.sin(angle)
            nodes.append(EvidenceGraphNode(
                id=f"branch:{b.id}",
                kind="branch",
                label=f"branch · {b.status}",
                state=b.status,
                x=x,
                y=y,
                attributes={
                    "persona_voice": b.persona_voice or "",
                    "strategy_family": b.strategy_family or "",
                    "promoted": b.promoted,
                },
            ))
            edges.append(EvidenceGraphEdge(
                source=f"inv:{investigation_id}",
                target=f"branch:{b.id}",
                kind="spawned",
            ))

        # Outcomes on outer ring.
        radius_outcome = 380.0
        n_outcomes = max(len(outcomes), 1)
        for i, o in enumerate(outcomes):
            if layout == "grid":
                x = (i % 4) * 200 - 300
                y = 400.0
            elif layout == "radial":
                angle = (2 * math.pi * i / n_outcomes) - math.pi / 2
                x = radius_outcome * math.cos(angle)
                y = radius_outcome * math.sin(angle)
            else:
                angle = (2 * math.pi * i / n_outcomes) + math.pi / 6
                x = radius_outcome * math.cos(angle)
                y = radius_outcome * math.sin(angle)
            nodes.append(EvidenceGraphNode(
                id=f"outcome:{o.id}",
                kind="outcome",
                label=str(o.kind),
                state=str(o.dispatch_status),
                x=x,
                y=y,
                attributes={
                    "confidence": o.confidence,
                    "branch_id": o.branch_id,
                },
            ))
            # Edge: branch → outcome (when known), else investigation → outcome.
            source_id = (
                f"branch:{o.branch_id}" if o.branch_id else f"inv:{investigation_id}"
            )
            edges.append(EvidenceGraphEdge(
                source=source_id,
                target=f"outcome:{o.id}",
                kind="produced",
            ))

        return DataEnvelope(data=EvidenceGraphSnapshot(
            investigation_id=investigation_id,
            layout=layout,
            nodes=nodes,
            edges=edges,
        ))



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

    @router.delete(
        "/patterns/{pattern_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        summary="Delete a pattern. No cascade — patterns are leaf rows.",
    )
    @limiter.limit("10/minute")
    async def delete_pattern(
        request: Request,
        pattern_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> Response:
        del request
        from .db_models import VRPatternRecord

        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _team_filter(
                    select(VRPatternRecord).where(VRPatternRecord.id == pattern_id),
                    VRPatternRecord, auth,
                ),
            )).first()
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Pattern {pattern_id} not found.",
                )
            await uow.session.delete(row)
            await uow.session.commit()

        return Response(status_code=status.HTTP_204_NO_CONTENT)

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

    @router.delete(
        "/disclosures/{submission_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        summary=(
            "Delete a disclosure submission record. The finding it was for "
            "is left untouched."
        ),
    )
    @limiter.limit("10/minute")
    async def delete_disclosure(
        request: Request,
        submission_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> Response:
        del request, auth
        from .db_models import VRDisclosureSubmissionRecord

        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                select(VRDisclosureSubmissionRecord).where(
                    VRDisclosureSubmissionRecord.id == submission_id,
                ),
            )).first()
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Disclosure submission {submission_id} not found.",
                )
            await uow.session.delete(row)
            await uow.session.commit()

        return Response(status_code=status.HTTP_204_NO_CONTENT)

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

    class _DisclosureSectionsPatch(BaseModel):
        """Operator-edited section bodies (08_FRONTEND_UX.md §1.8)."""

        model_config = ConfigDict(extra="forbid")

        sections: dict[str, str]

    @router.patch(
        "/disclosures/{submission_id}/sections",
        response_model=DataEnvelope[VRDisclosureSubmissionSummary],
        summary=(
            "Replace the structured advisory sections "
            "(summary / technical_details / reproduction / patches / "
            "references). The body is rendered from these sections on "
            "the next POST /disclosures/:id/render."
        ),
    )
    @limiter.limit("30/minute")
    async def patch_disclosure_sections(
        request: Request,
        submission_id: str,
        body: _DisclosureSectionsPatch,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRDisclosureSubmissionSummary]:
        del request, auth
        import json as _json

        from .db_models import VRDisclosureSubmissionRecord
        from .disclosure import DisclosureService

        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                select(VRDisclosureSubmissionRecord).where(
                    VRDisclosureSubmissionRecord.id == submission_id,
                ),
            )).first()
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Disclosure submission {submission_id} not found.",
                )
            row.sections_json = _json.dumps(body.sections)
            row.updated_at = utc_now()
            await uow.session.commit()
            await uow.session.refresh(row)

        svc = DisclosureService()
        summary = await svc.get(submission_id)
        if summary is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Disclosure submission {submission_id} not found.",
            )
        return DataEnvelope(data=summary)

    @router.post(
        "/disclosures/{submission_id}/regenerate",
        response_model=DataEnvelope[VRDisclosureSubmissionSummary],
        summary=(
            "Regenerate the structured sections from the underlying "
            "finding (advisory + PoC). Replaces any operator edits — "
            "frontend prompts before invoking (08_FRONTEND_UX.md §1.8)."
        ),
    )
    @limiter.limit("10/minute")
    async def regenerate_disclosure_sections(
        request: Request,
        submission_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRDisclosureSubmissionSummary]:
        del request, auth
        import json as _json

        from .db_models import (
            VRDisclosureSubmissionRecord,
            VRFindingRecord,
        )
        from .disclosure import DisclosureService

        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                select(VRDisclosureSubmissionRecord).where(
                    VRDisclosureSubmissionRecord.id == submission_id,
                ),
            )).first()
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Disclosure submission {submission_id} not found.",
                )
            finding = (await uow.session.exec(
                select(VRFindingRecord).where(
                    VRFindingRecord.id == row.finding_id,
                ),
            )).first()
            if finding is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=(
                        f"Finding {row.finding_id} backing this submission "
                        f"is missing — cannot regenerate."
                    ),
                )
            now = utc_now()
            sections = {
                "summary": finding.root_cause or "",
                "technical_details": (finding.crash_type or "")
                + ("\n\n" + (finding.asan_report or "") if finding.asan_report else ""),
                "reproduction": finding.poc_code or "",
                "patches": (
                    f"Patch version: {finding.patch_version}"
                    if finding.patch_version else ""
                ),
                "references": (
                    finding.assigned_cve_id
                    or finding.vendor_contact
                    or ""
                ),
            }
            row.sections_json = _json.dumps(sections)
            row.regenerated_from_finding_at = now
            row.updated_at = now
            await uow.session.commit()
            await uow.session.refresh(row)

        svc = DisclosureService()
        summary = await svc.get(submission_id)
        if summary is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Disclosure submission {submission_id} not found.",
            )
        return DataEnvelope(data=summary)


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

    class _LaunchResponse(BaseModel):
        """Output of POST /vr/fuzz/campaigns/{id}/launch."""

        model_config = ConfigDict(extra="forbid")

        campaign_id: str
        status: str
        remote_pid: int | None = None
        remote_corpus_dir: str | None = None
        remote_crashes_dir: str | None = None
        description: str | None = None
        task_id: str | None = None

    @router.post(
        "/fuzz/campaigns/{campaign_id}/launch",
        response_model=DataEnvelope[_LaunchResponse],
        summary=(
            "Enqueue a launcher task that SSHes to the campaign's "
            "analysis_system_id, starts the fuzzer per its engine_id, "
            "and records the remote PID + corpus/crashes dirs. "
            "Idempotent — returns the existing PID when the campaign "
            "is already running."
        ),
    )
    @limiter.limit("10/minute")
    async def launch_fuzz_campaign(
        request: Request,
        campaign_id: str,
        synchronous: bool = Query(
            default=False,
            description=(
                "If true, runs the launcher in-process (blocking up to "
                "the SSH timeouts) and returns the resolved remote PID. "
                "If false (default) enqueues an ARQ task and returns "
                "a task_id; the campaign row is updated when the task "
                "completes."
            ),
        ),
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[_LaunchResponse]:
        from aila.api.deps import get_task_queue
        from aila.modules.vr.services import FuzzCampaignService, FuzzServiceError
        from aila.modules.vr.workflow.task import run_fuzz_campaign_launch

        # Ownership / team-scoping check.
        from .db_models import VRFuzzCampaignRecord
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _team_filter(
                    select(VRFuzzCampaignRecord).where(
                        VRFuzzCampaignRecord.id == campaign_id,
                    ),
                    VRFuzzCampaignRecord, auth,
                ),
            )).first()
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Fuzz campaign {campaign_id} not found.",
                )

        if synchronous:
            svc = FuzzCampaignService()
            try:
                result = await svc.launch_campaign(campaign_id)
            except FuzzServiceError as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=str(exc),
                ) from exc
            return DataEnvelope(data=_LaunchResponse(**result))

        task_queue = get_task_queue("vr", request)
        handle = await task_queue.submit(
            track="vr",
            fn=run_fuzz_campaign_launch,
            kwargs={"campaign_id": campaign_id},
            user_id=auth.user_id,
            group_id=auth.role,
            team_id=auth.team_id,
        )
        return DataEnvelope(
            data=_LaunchResponse(
                campaign_id=campaign_id,
                status="queued",
                task_id=handle.task_id,
            ),
        )

    @router.delete(
        "/fuzz/campaigns/{campaign_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        summary=(
            "Delete a fuzz campaign and all of its crash records. The "
            "underlying target is left untouched. Crashes that were "
            "promoted to findings keep the finding row — the back-link "
            "goes stale."
        ),
    )
    @limiter.limit("10/minute")
    async def delete_fuzz_campaign(
        request: Request,
        campaign_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> Response:
        del request, auth
        from .db_models import VRFuzzCampaignRecord, VRFuzzCrashRecord

        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                select(VRFuzzCampaignRecord).where(VRFuzzCampaignRecord.id == campaign_id),
            )).first()
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Fuzz campaign {campaign_id} not found.",
                )
            crashes = (await uow.session.exec(
                select(VRFuzzCrashRecord).where(VRFuzzCrashRecord.campaign_id == campaign_id),
            )).all()
            for c in crashes:
                await uow.session.delete(c)
            await uow.session.delete(row)
            await uow.session.commit()

        return Response(status_code=status.HTTP_204_NO_CONTENT)

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

    @router.post(
        "/fuzz/crashes/{crash_id}/triage",
        response_model=DataEnvelope[VRFuzzCrashSummary],
        summary=(
            "Append a triage event to a crash's chain "
            "(08_FRONTEND_UX.md §1.6)."
        ),
    )
    @limiter.limit("30/minute")
    async def append_crash_triage(
        request: Request,
        crash_id: str,
        body: CrashTriageEvent,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRFuzzCrashSummary]:
        del request
        import json as _json

        from .db_models import VRFuzzCrashRecord

        async with UnitOfWork() as uow:
            crash = (await uow.session.exec(
                select(VRFuzzCrashRecord).where(VRFuzzCrashRecord.id == crash_id),
            )).first()
            if crash is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Fuzz crash {crash_id} not found.",
                )
            chain: list[Any] = []
            try:
                chain = _json.loads(crash.triage_chain_json or "[]")
                if not isinstance(chain, list):
                    chain = []
            except (ValueError, TypeError):
                chain = []
            chain.append(body.model_dump(mode="json"))
            crash.triage_chain_json = _json.dumps(chain)
            # The latest event drives the current verdict + reason.
            crash.triage_verdict = body.verdict.value
            if body.reason:
                crash.triage_reason = body.reason
            crash.updated_at = utc_now()
            await uow.session.commit()
            await uow.session.refresh(crash)

        del auth
        from aila.modules.vr.services.fuzz_service import _crash_record_to_summary
        return DataEnvelope(data=_crash_record_to_summary(crash))

    @router.get(
        "/fuzz/campaigns/{campaign_id}/telemetry",
        response_model=DataEnvelope[list[FuzzTelemetryPoint]],
        summary=(
            "Time-series telemetry for one fuzz campaign "
            "(08_FRONTEND_UX.md §1.5)."
        ),
    )
    @limiter.limit("120/minute")
    async def list_campaign_telemetry(
        request: Request,
        campaign_id: str,
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=500, ge=1, le=5000),
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[FuzzTelemetryPoint]]:
        del request, auth
        from .db_models import VRFuzzTelemetryRecord

        async with UnitOfWork() as uow:
            count_stmt = (
                select(sa_func.count())
                .select_from(VRFuzzTelemetryRecord)
                .where(VRFuzzTelemetryRecord.campaign_id == campaign_id)
            )
            total = (await uow.session.exec(count_stmt)).one()
            rows = (await uow.session.exec(
                select(VRFuzzTelemetryRecord)
                .where(VRFuzzTelemetryRecord.campaign_id == campaign_id)
                .order_by(VRFuzzTelemetryRecord.measured_at.asc())
                .offset(offset)
                .limit(limit),
            )).all()

        items = [
            FuzzTelemetryPoint(
                id=r.id,
                campaign_id=r.campaign_id,
                measured_at=r.measured_at,
                execs_per_sec=r.execs_per_sec,
                total_execs=r.total_execs,
                corpus_size=r.corpus_size,
                coverage_pct=r.coverage_pct,
                crashes_found=r.crashes_found,
            )
            for r in rows
        ]
        return DataEnvelope(
            data=items,
            meta=PaginatedMeta(
                total=int(total), offset=offset, limit=limit,
            ).model_dump(),
        )

    @router.post(
        "/fuzz/campaigns/{campaign_id}/telemetry",
        response_model=DataEnvelope[FuzzTelemetryPoint],
        status_code=status.HTTP_201_CREATED,
        summary=(
            "Record a telemetry sample for one fuzz campaign. Also "
            "updates the campaign's last_progress_at + roll-up columns "
            "(08_FRONTEND_UX.md §1.5)."
        ),
    )
    @limiter.limit("60/minute")
    async def record_campaign_telemetry(
        request: Request,
        campaign_id: str,
        body: FuzzTelemetryCreate,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[FuzzTelemetryPoint]:
        del request, auth
        from uuid import uuid4 as _uuid4

        from .db_models import VRFuzzCampaignRecord, VRFuzzTelemetryRecord

        async with UnitOfWork() as uow:
            campaign = (await uow.session.exec(
                select(VRFuzzCampaignRecord).where(
                    VRFuzzCampaignRecord.id == campaign_id,
                ),
            )).first()
            if campaign is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Fuzz campaign {campaign_id} not found.",
                )
            now = utc_now()
            row = VRFuzzTelemetryRecord(
                id=str(_uuid4()),
                campaign_id=campaign_id,
                measured_at=now,
                execs_per_sec=body.execs_per_sec,
                total_execs=body.total_execs,
                corpus_size=body.corpus_size,
                coverage_pct=body.coverage_pct,
                crashes_found=body.crashes_found,
            )
            uow.session.add(row)
            # Roll the latest sample onto the campaign row so the
            # campaigns list page renders fresh numbers without
            # joining the telemetry table.
            campaign.last_progress_at = now
            if body.execs_per_sec is not None:
                campaign.execs_per_sec = body.execs_per_sec
            if body.total_execs is not None:
                campaign.total_execs = body.total_execs
            if body.corpus_size is not None:
                campaign.corpus_size = body.corpus_size
            if body.coverage_pct is not None:
                campaign.coverage_pct = body.coverage_pct
            if body.crashes_found is not None:
                campaign.crashes_found = body.crashes_found
            campaign.updated_at = now
            await uow.session.commit()
            await uow.session.refresh(row)

        return DataEnvelope(data=FuzzTelemetryPoint(
            id=row.id,
            campaign_id=row.campaign_id,
            measured_at=row.measured_at,
            execs_per_sec=row.execs_per_sec,
            total_execs=row.total_execs,
            corpus_size=row.corpus_size,
            coverage_pct=row.coverage_pct,
            crashes_found=row.crashes_found,
        ))


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

    # ─── MCP server health + config (operator surface) ────────────────────
    #
    # AILA is orchestration only — every analysis call is forwarded to one
    # of these external MCP servers. The operator needs visibility into
    # which ones are reachable and an ability to retarget them at a
    # different workstation without editing env vars (D-33).

    @router.get(
        "/mcp/servers",
        summary="List configured MCP servers with live health probes.",
    )
    @limiter.limit("60/minute")
    async def list_mcp_servers(
        request: Request,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[dict[str, Any]]]:
        del request, auth
        from aila.modules.vr.services import McpRegistryService

        servers = await McpRegistryService().probe_all()
        return DataEnvelope(data=servers)

    @router.patch(
        "/mcp/servers/{server_id}",
        summary="Update an MCP server's base_url. Re-probes immediately.",
    )
    @limiter.limit("30/minute")
    async def update_mcp_server(
        request: Request,
        server_id: str,
        body: dict[str, Any],
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict[str, Any]]:
        del request, auth
        from aila.modules.vr.services import McpRegistryService

        base_url = (body or {}).get("base_url")
        if not isinstance(base_url, str) or not base_url.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="base_url (string) required.",
            )
        result = await McpRegistryService().update_base_url(server_id, base_url.strip())
        if result is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"MCP server {server_id!r} not registered.",
            )
        return DataEnvelope(data=result)

    @router.get(
        "/mcp/calls",
        summary=(
            "List recent MCP call log entries (most recent first). "
            "Operator-facing audit trail of every forward() through the "
            "audit-mcp and ida-headless bridges."
        ),
    )
    @limiter.limit("60/minute")
    async def list_mcp_calls(
        request: Request,
        auth: AuthContext = Depends(require_auth),
        server_id: str | None = Query(default=None),
        status_filter: str | None = Query(default=None, alias="status"),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> DataEnvelope[list[dict[str, Any]]]:
        del request, auth
        from .db_models import VRMcpCallLogRecord

        async with UnitOfWork() as uow:
            stmt = select(VRMcpCallLogRecord)
            if server_id:
                stmt = stmt.where(VRMcpCallLogRecord.server_id == server_id)
            if status_filter:
                stmt = stmt.where(VRMcpCallLogRecord.status == status_filter)
            stmt = stmt.order_by(VRMcpCallLogRecord.called_at.desc()).offset(offset).limit(limit)  # type: ignore[union-attr]
            rows = (await uow.session.exec(stmt)).all()

        items = [
            {
                "id": r.id,
                "server_id": r.server_id,
                "base_url": r.base_url,
                "action": r.action,
                "status": r.status,
                "http_status": r.http_status,
                "latency_ms": r.latency_ms,
                "error_excerpt": r.error_excerpt,
                "called_at": r.called_at.isoformat() if r.called_at else None,
            }
            for r in rows
        ]
        return DataEnvelope(data=items)

    return router
