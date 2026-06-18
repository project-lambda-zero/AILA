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
import json
import json as _json
import logging
import os as _os
from collections.abc import AsyncGenerator
from typing import Any

import httpx
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func as sa_func
from sqlalchemy import text as sa_text
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select

from aila.api.deps import get_task_queue
from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope, PaginatedMeta
from aila.platform.contracts._common import utc_now
from aila.platform.contracts.auth import AuthContext, require_auth
from aila.platform.llm.cost_record import LLMCostRecord
from aila.platform.services.factory import ServiceFactory
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.platform.uow import UnitOfWork
from aila.storage.db_models import WorkflowStateCursor

from ._task_queue import default_task_queue
from .agents.outcome_dispatcher import OutcomeDispatcher
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
    FuzzProposalDecideAccept,
    FuzzProposalDecideReject,
    FuzzProposalStatus,
    FuzzTelemetryCreate,
    FuzzTelemetryPoint,
    HypothesisProjection,
    HypothesisState,
    InvestigationKind,
    InvestigationPauseReason,
    InvestigationStatus,
    MasvsAuditAggregate,
    MasvsAuditDispatchResponse,
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
    VRFuzzCampaignProposalSummary,
    VRFuzzCampaignSummary,
    VRFuzzCrashCreate,
    VRFuzzCrashSummary,
    VRInvestigationCreate,
    VRInvestigationSummary,
    VRInvestigationTargetAttach,
    VRInvestigationTargetSummary,
    VRMessageCreate,
    VRMessageSummary,
    VROutcomeReviewCreate,
    VROutcomeReviewSummary,
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
from .db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
)
from .workflow.task import run_vr_claim_verifier, run_vr_investigate

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
        return TargetKind.ANDROID_APK
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


class _ReenqueueBody(BaseModel):
    """Optional body for the re-enqueue endpoint.

    Module-scoped (not nested inside ``create_vr_router``) so that the
    forward reference ``_ReenqueueBody | None`` in the route handler's
    body parameter resolves against module globals at OpenAPI schema
    generation time. ``from __future__ import annotations`` defers
    every annotation to string form; pydantic's TypeAdapter then
    evaluates the string against the function's module globals when
    FastAPI builds the route's body validator. A class scoped INSIDE
    ``create_vr_router`` is invisible at that point and pydantic
    raises ``PydanticUserError: '...' is not fully defined`` — which
    fails ``/openapi.json`` with 500 (operator-observed after the
    cutover restart).

    When ``kind`` is supplied, the investigation's kind is updated
    BEFORE the task is submitted. Lets the operator convert a
    finished discovery into a variant_hunt without going through the
    DB, or vice versa. ``strategy_family`` moves with it via the
    kind -> strategy default map in ``_KIND_DEFAULT_STRATEGY``.
    """
    model_config = ConfigDict(extra="forbid")
    kind: InvestigationKind | None = Field(default=None)


class _BranchOpBody(BaseModel):
    """Common base for branch operation bodies (fork / merge).

    Hoisted to module scope so the forward references in route
    handlers resolve under ``from __future__ import annotations``.
    See ``_ReenqueueBody`` above for the full rationale.
    """
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(default="", max_length=1024)


class _ForkBody(_BranchOpBody):
    persona_voice: PersonaVoice | None = Field(default=None)
    at_turn: int | None = Field(default=None, ge=0)


class _MergeBody(_BranchOpBody):
    other_branch_id: str = Field(min_length=1, max_length=64)


class _DisclosureSectionsPatch(BaseModel):
    """Operator-edited section bodies (08_FRONTEND_UX.md §1.8).

    Module-scoped per the same forward-ref resolution rule.
    """
    model_config = ConfigDict(extra="forbid")
    sections: dict[str, str]


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


class _ProposalAcceptResponse(BaseModel):
    """Output of POST /vr/fuzz/proposals/{id}/accept."""
    model_config = ConfigDict(extra="forbid")
    proposal_id: str
    campaign_id: str
    workdir: str
    harness_path: str | None
    seeds_written: int
    dictionary_written: bool
    auto_launched: bool
    build_log: str


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
    # Older finding rows may carry a crash_type the current CrashType
    # enum does not recognise (extensions added by experimental tools,
    # imports from prior schemas, etc). Fall back to None rather than
    # crashing the whole listing on a single rogue value.
    if record.crash_type:
        try:
            crash_type = CrashType(record.crash_type)
        except ValueError:
            crash_type = None
    else:
        crash_type = None
    # Derive evidence count from the underlying JSON list once, so the
    # global findings explorer can render an "evidence" column without
    # forcing every caller to parse the JSON itself.
    import json as _json
    try:
        evidence_list = _json.loads(record.evidence_refs_json or "[]")
    except (TypeError, ValueError):
        evidence_list = []
    evidence_count = (
        len(evidence_list) if isinstance(evidence_list, list) else 0
    )
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
        cvss_score=record.cvss_score,
        cvss_vector=record.cvss_vector,
        cwe_id=record.cwe_id,
        evidence_count=evidence_count,
    )


def _fuzz_proposal_summary(record: Any) -> VRFuzzCampaignProposalSummary:
    """Project a VRFuzzCampaignProposalRecord row → public summary."""
    import json as _json

    from .contracts import SeedCorpusEntry

    def _safe_dict(blob: str | None) -> dict[str, Any]:
        if not blob:
            return {}
        try:
            v = _json.loads(blob)
            return v if isinstance(v, dict) else {}
        except (ValueError, TypeError) as exc:
            _log.warning("_safe_dict failed reason=%s", exc)
            return {}

    seeds_raw = []
    try:
        decoded = _json.loads(record.seed_corpus_json or "[]")
        if isinstance(decoded, list):
            seeds_raw = decoded
    except (ValueError, TypeError):
        seeds_raw = []
    seeds: list[SeedCorpusEntry] = []
    for entry in seeds_raw:
        if not isinstance(entry, dict):
            continue
        fn = entry.get("filename")
        b64 = entry.get("content_base64")
        if not fn or not b64:
            continue
        try:
            seeds.append(SeedCorpusEntry(
                filename=str(fn),
                content_base64=str(b64),
                notes=str(entry.get("notes") or ""),
            ))
        except (TypeError, ValueError):
            continue

    return VRFuzzCampaignProposalSummary(
        id=record.id,
        investigation_id=record.investigation_id,
        outcome_id=record.outcome_id,
        target_id=record.target_id,
        workspace_id=record.workspace_id,
        profile=record.profile,
        rationale=record.rationale or "",
        confidence=record.confidence or "medium",
        target_descriptor=_safe_dict(record.target_descriptor_json),
        suggested_engine_id=record.suggested_engine_id,
        suggested_engine_config=_safe_dict(record.suggested_engine_config_json),
        suggested_strategy_id=record.suggested_strategy_id,
        suggested_duration_hours=record.suggested_duration_hours,
        harness_source=record.harness_source,
        harness_language=record.harness_language,
        harness_build_command=record.harness_build_command,
        harness_target_path=record.harness_target_path,
        seed_corpus=seeds,
        dictionary_content=record.dictionary_content,
        status=FuzzProposalStatus(record.status),
        accepted_campaign_id=record.accepted_campaign_id,
        decided_at=record.decided_at,
        decided_by=record.decided_by,
        decision_reason=record.decision_reason,
        prepare_log=record.prepare_log,
        created_at=record.created_at,
        updated_at=record.updated_at,
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
    # PRD §C-21: surface the androguard-discovered package name so the
    # TargetsPage row label can fall back to it once STATIC_SUMMARY
    # finishes. Storage shape set by services/target_analysis._android_static_summary.
    android_package_name = handles.get("android_mcp_package_name")
    if not isinstance(android_package_name, str) or not android_package_name:
        android_package_name = None

    # APK-specific projection. Per VRTargetSummary.apk_overview: rolls up
    # every key the 5-stage android pipeline writes into mcp_handles_json
    # so the TargetDetailPage Android section has a single dict to render.
    # Kept None when the target isn't android_apk OR no handle yet — the
    # frontend treats None as "section not applicable / not ready".
    apk_overview: dict[str, Any] | None = None
    if record.kind == TargetKind.ANDROID_APK.value:
        # Pull each handle if present. Order mirrors the pipeline so an
        # operator can see how far the chain has progressed.
        overview: dict[str, Any] = {}
        # Per-key projection. NOTE: android_mcp_mobsf_scan (the raw MobSF
        # report) is intentionally NOT projected verbatim — it's a
        # multi-MB JSON blob that bloated vuln_researcher prompts to >1M
        # tokens per turn and OOM'd the LLM proxy. Instead we surface a
        # one-line summary (count + severity buckets) that fits the prompt
        # context. Operators can still query the full report via
        # GET /vr/targets/{id}/mobsf-report (NOT YET IMPLEMENTED — read
        # _mcp_handles_json.android_mcp_mobsf_scan directly from DB for
        # now). Same for android_mcp_static_summary: project the digest,
        # not the full androguard dump.
        for handle_key, out_key in (
            ("android_mcp_apk_sha256", "sha256"),
            ("android_mcp_decoded_dir", "decoded_dir"),
            ("android_mcp_manifest_path", "manifest_path"),
            ("android_mcp_decompiled_dir", "decompiled_dir"),
            ("android_mcp_jadx_root", "jadx_root"),
            ("android_mcp_jadx_class_count", "jadx_class_count"),
            ("audit_mcp_decompiled_index_id", "audit_mcp_index_id"),
            ("audit_mcp_decompiled_indexed_at", "audit_mcp_indexed_at"),
        ):
            value = handles.get(handle_key)
            if value is not None:
                overview[out_key] = value

        # static_summary digest: keep only the load-bearing fields. The full
        # androguard output (34KB+ per-package metadata) is excessive to
        # include in every LLM turn.
        #
        # fix §268 — `android_mcp_static_summary` now stores a pointer
        # to a JSON artifact (`_artifact_path`) plus pre-computed
        # digest fields (counts already as `*_count` keys). The
        # legacy inline form (full payload as a dict) is still
        # accepted; we compute `len()` on the lists when we encounter
        # it so rows ingested before the cutover still project
        # correctly.
        static_full = handles.get("android_mcp_static_summary") or {}
        if isinstance(static_full, dict) and static_full:
            digest: dict[str, Any] = {}
            for k in (
                "package", "version_name", "version_code",
                "min_sdk", "target_sdk", "signing_scheme",
            ):
                if static_full.get(k) is not None:
                    digest[k] = static_full[k]
            # Counts only — don't dump 38 permission strings + 29 exported
            # component class names into every LLM turn.
            for k in (
                "permissions", "dangerous_permissions", "exported_activities",
                "exported_services", "exported_receivers", "exported_providers",
                "native_libs", "certificates",
            ):
                count_key = f"{k}_count"
                v = static_full.get(k)
                if isinstance(v, list):
                    digest[count_key] = len(v)
                elif isinstance(static_full.get(count_key), int):
                    digest[count_key] = static_full[count_key]
            overview["static_summary"] = digest

        # mobsf_scan digest: bucket-count summary. The full report is at
        # most operator-facing — agents don't need it in every prompt.
        #
        # fix §269 — ``android_mcp_mobsf_scan`` now stores a pointer
        # to ``target_artifacts/{target_id}/mobsf_scan.json`` plus a
        # pre-computed digest (``security_score``, ``trackers_detected``,
        # ``findings_by_severity``) and an explicit ``prompt_safe=False``.
        # The legacy inline-full form (rows ingested pre-§269) is still
        # accepted — we recompute the buckets when no pre-computed
        # digest is present.
        mobsf_full = handles.get("android_mcp_mobsf_scan") or {}
        if isinstance(mobsf_full, dict) and mobsf_full:
            if mobsf_full.get("skipped"):
                overview["mobsf_scan"] = {"skipped": True, "reason": mobsf_full.get("reason", "")}
            elif "_artifact_path" in mobsf_full:
                projected: dict[str, Any] = {}
                if mobsf_full.get("security_score") is not None:
                    projected["security_score"] = mobsf_full["security_score"]
                if mobsf_full.get("trackers_detected") is not None:
                    projected["trackers_detected"] = mobsf_full["trackers_detected"]
                buckets = mobsf_full.get("findings_by_severity")
                if isinstance(buckets, dict):
                    projected["findings_by_severity"] = buckets
                overview["mobsf_scan"] = projected
            else:
                buckets = {"high": 0, "warning": 0, "info": 0, "good": 0, "secure": 0}
                for section_key in ("code_analysis", "manifest_analysis", "android_api", "network_security"):
                    section = mobsf_full.get(section_key)
                    if isinstance(section, dict):
                        for finding in section.values():
                            if isinstance(finding, dict):
                                sev = (finding.get("severity") or finding.get("status") or "").lower()
                                if sev in buckets:
                                    buckets[sev] += 1
                overview["mobsf_scan"] = {
                    "security_score": mobsf_full.get("security_score"),
                    "trackers_detected": mobsf_full.get("trackers", {}).get("detected_trackers") if isinstance(mobsf_full.get("trackers"), dict) else None,
                    "findings_by_severity": buckets,
                }

        if overview:
            apk_overview = overview

    # Project per-stage analysis status (migration 060) so UI shows
    # a stage breakdown alongside the rolled-up analysis_state.
    stages_payload: dict[str, Any] | None = None
    try:
        if record.analysis_stages_json and record.analysis_stages_json != "{}":
            stages_payload = _json.loads(record.analysis_stages_json)
    except (ValueError, TypeError):
        stages_payload = None

    return VRTargetSummary(
        id=record.id,
        workspace_id=record.workspace_id,
        display_name=record.display_name,
        kind=TargetKind(record.kind),
        descriptor=_json.loads(record.descriptor_json or "{}"),
        uploaded_filename=uploaded_filename,
        android_package_name=android_package_name,
        apk_overview=apk_overview,
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
        analysis_stages=stages_payload,
        tags=tags,
        created_at=record.created_at.isoformat() if record.created_at else None,
        updated_at=record.updated_at.isoformat() if record.updated_at else None,
    )


def _investigation_summary(
    record: Any,
    branch_count: int = 0,
    message_count: int = 0,
    outcome_count: int = 0,
    primary_outcome_kind: str | None = None,
    primary_outcome_confidence: str | None = None,
    primary_outcome_verdict_head: str | None = None,
    verifier_verdict: str | None = None,
    verifier_confidence: float | None = None,
    live_cost_usd: float | None = None,
) -> VRInvestigationSummary:
    """Project a VRInvestigationRecord row to the public summary.

    ``live_cost_usd`` overrides the stored ``cost_actual_usd`` when
    provided. The stored field has had no writers since inception, so
    every read previously returned $0.00 regardless of actual spend.
    Callers that aggregate ``LLMCostRecord`` per investigation pass the
    sum here so the budget gauge reflects reality.
    """
    import json as _json

    actual_cost = live_cost_usd if live_cost_usd is not None else record.cost_actual_usd
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
        is_favorite=getattr(record, "is_favorite", False),
        strategy_family=record.strategy_family,
        cost_budget_usd=record.cost_budget_usd,
        cost_actual_usd=actual_cost,
        llm_tokens_cost_usd=record.llm_tokens_cost_usd,
        mcp_calls_cost_usd=record.mcp_calls_cost_usd,
        fuzz_infra_cost_usd=record.fuzz_infra_cost_usd,
        branch_count=branch_count,
        message_count=message_count,
        outcome_count=outcome_count,
        primary_outcome_id=record.primary_outcome_id,
        primary_outcome_kind=primary_outcome_kind,
        primary_outcome_confidence=primary_outcome_confidence,
        primary_outcome_verdict_head=primary_outcome_verdict_head,
        verifier_verdict=verifier_verdict,
        verifier_confidence=verifier_confidence,
        linked_campaign_ids=_json.loads(record.linked_campaign_ids_json or "[]"),
        linked_finding_ids=_json.loads(record.linked_finding_ids_json or "[]"),
        started_at=record.started_at,
        stopped_at=record.stopped_at,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


async def _compute_live_investigation_cost(
    uow: Any, investigation_id: str,
) -> float:
    """Aggregate LLMCostRecord.cost_usd over all task runs for this
    investigation. Joins via TaskRecord.kwargs_json containing the
    investigation_id since LLMCostRecord.run_id == TaskRecord.id.

    Returns 0.0 on any error (best-effort — budget gauge degrades to
    the stored zero rather than crashing the read path).
    """
    try:


        # Find all run_ids belonging to this investigation
        task_ids_q = select(TaskRecord.id).where(
            TaskRecord.fn_path.like("%run_vr_investigate%"),
            TaskRecord.kwargs_json.like(f'%"{investigation_id}"%'),
        )
        task_ids = [r for r in (await uow.session.exec(task_ids_q)).all()]
        if not task_ids:
            return 0.0
        sum_q = select(sa_func.coalesce(sa_func.sum(LLMCostRecord.cost_usd), 0.0)).where(
            LLMCostRecord.run_id.in_(task_ids),
        )
        total = (await uow.session.exec(sum_q)).one()
        return float(total)
    except (AttributeError, ImportError, ValueError) as exc:
        _log.warning("_compute_live_investigation_cost failed reason=%s", exc)
        return 0.0


def _branch_summary(
    record: Any,
    cursor_state: str | None = None,
    cursor_archived_state: str | None = None,
) -> VRBranchSummary:
    """Project a VRInvestigationBranchRecord row to summary.

    ``cursor_state`` + ``cursor_archived_state`` come from
    :class:`WorkflowStateCursor` joined by ``run_id == branch.id``.
    Callers that haven't joined the cursor table pass ``None``; the
    UI then falls back to the legacy ``status`` field for paused-state
    detection (which has the Phase B precision loss noted in the
    contract docstring).
    """
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
        cursor_state=cursor_state,
        cursor_archived_state=cursor_archived_state,
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
        state=record.state or "dispatched",  # legacy NULL rows
    )


# Default strategy_family per InvestigationKind. Used both at create-time
# (when the operator omits strategy_family) and on /re-enqueue with an
# explicit kind change so strategy_family always tracks kind's default.
_KIND_DEFAULT_STRATEGY: dict[InvestigationKind, str] = {
    InvestigationKind.DISCOVERY:    "vulnerability_research.discovery_research",
    InvestigationKind.VARIANT_HUNT: "vulnerability_research.variant_hunt",
    InvestigationKind.TRIAGE:       "vulnerability_research.triage",
    InvestigationKind.N_DAY:        "vulnerability_research.nday",
    InvestigationKind.AUDIT:        "vulnerability_research.audit",
}


def _sanitize_filename_part(text: str, *, fallback: str) -> str:
    """Fold a free-form label into a Content-Disposition-safe slug.

    Keeps ASCII alnum plus ``.``, ``_``, ``-`` (the package-id alphabet
    plus the two delimiters operators expect in filenames); every other
    byte folds to ``_``. Strips leading / trailing punctuation so a
    package like ``..weird.`` doesn't generate a hidden file on
    Unix, and caps the slug at 64 chars so the header stays small.
    Returns ``fallback`` when the input is empty or sanitises to the
    empty string.
    """
    if not text:
        return fallback
    out_chars = [
        ch if (ch.isascii() and (ch.isalnum() or ch in "._-")) else "_"
        for ch in text
    ]
    cleaned = "".join(out_chars).strip("._-")
    if not cleaned:
        return fallback
    return cleaned[:64]


def _masvs_report_filename(
    target_summary: VRTargetSummary,
    generated_at_yyyymmdd: str,
) -> str:
    """Build the MASVS report download filename per PRD R-3.

    Format: ``masvs_<package>_<YYYYMMDD>.pdf``. The package label falls
    back through ``apk_overview.static_summary.package`` →
    ``android_package_name`` → the sentinel ``android-apk`` so a target
    that somehow lost its package label still gets a stable filename
    rather than a header the browser refuses to parse.
    """
    package_label: str = ""
    overview = target_summary.apk_overview
    if isinstance(overview, dict):
        static_summary = overview.get("static_summary")
        if isinstance(static_summary, dict):
            maybe_pkg = static_summary.get("package")
            if isinstance(maybe_pkg, str):
                package_label = maybe_pkg.strip()
    if not package_label and target_summary.android_package_name:
        package_label = target_summary.android_package_name.strip()
    sanitized = _sanitize_filename_part(
        package_label, fallback="android-apk",
    )
    return f"masvs_{sanitized}_{generated_at_yyyymmdd}.pdf"


def create_vr_router() -> APIRouter:
    """Construct and return the VR module APIRouter."""
    router = APIRouter(tags=["vr"])

    def _team_filter(stmt: Any, model: Any, auth: AuthContext) -> Any:
        if auth.team_id is not None:
            stmt = stmt.where(model.team_id == auth.team_id)
        return stmt

    async def _team_owned_or_404(
        record_id: str,
        model: Any,
        auth: AuthContext,
        not_found_detail: str,
    ) -> Any:
        """Load a row by id with team-scope enforcement; raise 404 on miss.

        Mirrors the _team_filter pattern: callers that hold a row from
        this helper have already been authorized for the row's team.
        """
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _team_filter(
                    select(model).where(model.id == record_id),
                    model, auth,
                ),
            )).first()
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=not_found_detail,
            )
        return row

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
                    is_op = m.sender_kind == SenderKind.OPERATOR.value
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
                                "kind": o.outcome_kind,
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
        "/findings",
        response_model=DataEnvelope[list[VRFinding]],
        summary="List every finding the caller can see (team-scoped, filterable).",
    )
    @limiter.limit("60/minute")
    async def list_findings_global(
        request: Request,
        auth: AuthContext = Depends(require_auth),
        project_id: str | None = Query(default=None),
        disclosure_status: str | None = Query(default=None),
        crash_type: str | None = Query(default=None),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> DataEnvelope[list[VRFinding]]:
        """Global findings explorer endpoint.

        The project-scoped sibling `GET /projects/{id}/findings` still
        exists for the per-project drill-down; this endpoint is what the
        operator's standalone Findings explorer hits so they can browse
        every finding (across all VR projects in their team) without
        navigating through a project chooser first.

        Tenancy: only rows with team_id matching `auth.team_id` are
        returned. The optional filters narrow the list further but do
        NOT widen the team scope. `limit` defaults to 100 (vs 50 on the
        scoped sibling) because the explorer is the catalogue view.
        """
        del request
        from .db_models import VRFindingRecord

        async with UnitOfWork() as uow:
            stmt = select(VRFindingRecord)
            count_stmt = select(sa_func.count()).select_from(VRFindingRecord)
            if auth.team_id is not None:
                stmt = stmt.where(VRFindingRecord.team_id == auth.team_id)
                count_stmt = count_stmt.where(
                    VRFindingRecord.team_id == auth.team_id,
                )
            if project_id:
                stmt = stmt.where(VRFindingRecord.project_id == project_id)
                count_stmt = count_stmt.where(
                    VRFindingRecord.project_id == project_id,
                )
            if disclosure_status:
                stmt = stmt.where(
                    VRFindingRecord.disclosure_status == disclosure_status,
                )
                count_stmt = count_stmt.where(
                    VRFindingRecord.disclosure_status == disclosure_status,
                )
            if crash_type:
                stmt = stmt.where(VRFindingRecord.crash_type == crash_type)
                count_stmt = count_stmt.where(
                    VRFindingRecord.crash_type == crash_type,
                )

            total = int((await uow.session.exec(count_stmt)).one())
            rows = (await uow.session.exec(
                stmt.order_by(VRFindingRecord.created_at.desc())
                .offset(offset).limit(limit),
            )).all()

        items = [_finding_from_record(r) for r in rows]
        meta = PaginatedMeta(total=total, offset=offset, limit=limit).model_dump()
        return DataEnvelope(data=items, meta=meta)

    @router.get(
        "/findings/{finding_id}",
        response_model=DataEnvelope[VRFinding],
        summary="Get a single finding by id (project-agnostic, team-scoped).",
    )
    @limiter.limit("120/minute")
    async def get_finding_global(
        request: Request,
        finding_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRFinding]:
        """Project-agnostic finding fetch.

        The sibling project-scoped endpoint
        `GET /projects/{project_id}/findings/{finding_id}` keeps
        existing deep-link semantics; this endpoint is what the global
        Findings explorer routes click into so findings with a null
        project_id (stubs auto-created by the disclosure-from-
        investigation flow, or imports that didn't carry a project
        link) still open in the detail page. Tenancy: only the
        caller's team_id sees the row.
        """
        del request
        from .db_models import VRFindingRecord

        async with UnitOfWork() as uow:
            stmt = select(VRFindingRecord).where(
                VRFindingRecord.id == finding_id,
            )
            if auth.team_id is not None:
                stmt = stmt.where(VRFindingRecord.team_id == auth.team_id)
            row = (await uow.session.exec(stmt)).first()
            if row is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Finding {finding_id!r} not found.",
                )
        return DataEnvelope(data=_finding_from_record(row))

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
        summary=(
            "Delete a target. Refuses with 409 if any investigations or "
            "findings reference it. Cascade-deletes stub/log dependents "
            "(vr_projects, vr_target_tag_index, vr_investigation_targets, "
            "vr_mcp_call_log, vr_fuzz_campaign_proposals) in the same "
            "transaction so a stale operator-created project stub does not "
            "block the delete with an FK violation."
        ),
    )
    @limiter.limit("10/minute")
    async def delete_target(
        request: Request,
        target_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> Response:
        del request
        from .db_models import VRFindingRecord, VRInvestigationRecord, VRTargetRecord

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

            # Refuse on real content. A target with investigations or
            # findings is load-bearing; cascading those silently would
            # destroy evidence.
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
            finding_count = (await uow.session.exec(
                select(sa_func.count())
                .select_from(VRFindingRecord)
                .where(VRFindingRecord.target_id == target_id),
            )).one()
            if int(finding_count) > 0:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"Target {target_id} has {int(finding_count)} finding(s). "
                        "Retract or move them before deleting the target."
                    ),
                )

            # Cascade stub + log dependents. None of these tables hold
            # evidence — vr_projects is operator-created scaffolding,
            # vr_target_tag_index is denormalized tag lookup,
            # vr_investigation_targets is a join row (already guarded
            # by the inv_count check above), vr_mcp_call_log is historical
            # audit trail keyed by target, and vr_fuzz_campaign_proposals
            # are auto-generated. Same transaction so partial failure
            # rolls back. Tables that don't exist on this deployment are
            # tolerated (the audit_log + fuzz tables are newer).
            for stub_table in (
                "vr_projects",
                "vr_target_tag_index",
                "vr_investigation_targets",
                "vr_mcp_call_log",
                "vr_fuzz_campaign_proposals",
            ):
                try:
                    await uow.session.execute(
                        sa_text(f"DELETE FROM {stub_table} WHERE target_id = :tid"),
                        {"tid": target_id},
                    )
                except (SQLAlchemyError, OSError, RuntimeError) as exc:
                    # If a deployment lacks one of these tables, log + continue.
                    # The final target delete will surface any real FK still binding.
                    _log.warning(
                        "delete_target: cascade cleanup of %s skipped (%s: %s)",
                        stub_table, type(exc).__name__, str(exc)[:120],
                        exc_info=True,
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
        "/targets/{target_id}/resume-analysis",
        response_model=DataEnvelope[dict],
        status_code=status.HTTP_202_ACCEPTED,
        summary=(
            "Resume target analysis from the last completed stage. "
            "Resets any FAILED stages back to PENDING and re-enqueues "
            "the full ingest → profile → ranking pipeline. Stages "
            "already DONE are skipped (idempotent — StageTracker)."
        ),
    )
    @limiter.limit("10/minute")
    async def resume_target_analysis(
        request: Request,
        target_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict]:
        import json as _json

        from aila.api.deps import get_task_queue
        from aila.modules.vr.contracts.target_stages import StageState
        from aila.modules.vr.services.stage_tracker import (
            parse_stages,
            save_target_stages,
        )

        from ._task_queue import enqueue_downstream_target_stages
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

        # Reset FAILED stages to PENDING so the next analyze run picks
        # them up. DONE stages stay DONE (idempotent skip in tracker).
        # RUNNING stages stay RUNNING — the reaper will fail them on
        # timeout if they're actually dead.
        stages = parse_stages(row.analysis_stages_json)
        reset_count = 0
        for stage_name, status_obj in stages.all_stages():
            if status_obj.state == StageState.FAILED:
                status_obj.state = StageState.PENDING
                status_obj.error = None
                status_obj.started_at = None
                status_obj.completed_at = None
                # Keep attempts counter — operator visibility into retry depth.
                stages.set(stage_name, status_obj)
                reset_count += 1
        await save_target_stages(target_id, stages)

        # Fan out per non-DONE stage. CAPABILITY_PROFILE + FUNCTION_RANKING
        # both depend on INGESTION (need handles/index_id). If ingestion is
        # not yet DONE we enqueue ingestion alone; the worker's
        # run_target_analysis auto-chains the downstream pair when it
        # finishes (see _task_queue.enqueue_downstream_target_stages, also
        # invoked from the end of that task). When ingestion is already
        # DONE we skip straight to fanning out the downstream pair from
        # here so the operator gets immediate progress and skips
        # the ingestion no-op cycle.
        task_queue = get_task_queue("vr", request)
        enqueued: list[dict[str, str]] = []
        ingestion_state = stages.ingestion.state
        if ingestion_state != StageState.DONE:
            handle = await task_queue.submit(
                track="vr",
                fn=run_target_analysis,
                kwargs={"target_id": target_id},
                user_id=auth.user_id,
                group_id=auth.role,
                team_id=auth.team_id,
            )
            enqueued.append({"stage": "ingestion", "task_id": handle.task_id})
        else:
            enqueued.extend(await enqueue_downstream_target_stages(
                target_id,
                task_queue,
                user_id=auth.user_id,
                group_id=auth.role,
                team_id=auth.team_id,
            ))

        # Back-compat: keep ``task_id`` at the top of the payload pointing
        # at the first enqueued task so existing UI/CLI that reads it
        # doesn't break. Empty enqueue list means everything was DONE.
        first_task = enqueued[0]["task_id"] if enqueued else None
        return DataEnvelope(data={
            "task_id": first_task,
            "target_id": target_id,
            "stages_reset": reset_count,
            "enqueued": enqueued,
            "stages": _json.loads(stages.model_dump_json()),
        })

    @router.post(
        "/targets/{target_id}/refresh-source",
        response_model=DataEnvelope[dict],
        status_code=status.HTTP_200_OK,
        summary=(
            "Re-run a target's ingestion. Git-backed kinds "
            "(source_repo / patch_diff / cve) hit audit-mcp's "
            "refresh_index — idempotent when upstream did not "
            "move (returns status=current). android_apk targets "
            "reset every applicable APK stage to PENDING and "
            "re-enqueue the staged-analysis worker (returns "
            "status=rebuilding)."
        ),
    )
    @limiter.limit("10/minute")
    async def refresh_target_source(
        request: Request,
        target_id: str,
        force: bool = False,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict]:
        """Refresh a single target's ingestion artifacts.

        Git-backed kinds (source_repo / patch_diff / cve) must
        already carry an ``audit_mcp_index_id`` handle (i.e.
        INGESTION has completed at least once). Calling refresh
        on a never-indexed target returns 409 with a hint to run
        analysis first.

        For ``kind=android_apk`` targets the call resets every
        applicable APK stage (APK_DECODE / JADX_DECOMPILE /
        INDEX_DECOMPILED / STATIC_SUMMARY / MOBSF_SCAN) back to
        PENDING — leaving any stage currently RUNNING untouched so
        the reaper owns it — and re-enqueues
        ``run_target_analysis`` on the vr worker queue. The
        response carries ``status="rebuilding"`` with the count of
        stages reset and the new task_id.
        """
        import json as _json

        from .db_models import VRTargetRecord
        from .services.mcp_registry import McpRegistryService

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
            try:
                handles = _json.loads(row.mcp_handles_json or "{}")
            except (ValueError, TypeError):
                handles = {}
            try:
                descriptor = _json.loads(row.descriptor_json or "{}")
            except (ValueError, TypeError):
                descriptor = {}
            index_id = (handles.get("audit_mcp_index_id") or "").strip()
            display_name = row.display_name
            kind_str = row.kind
            analysis_stages_json = row.analysis_stages_json

        # Android APK targets follow a different ingestion path (no
        # audit-mcp refresh_index involved). Reset every applicable
        # APK stage back to PENDING — leaving RUNNING stages alone so
        # we don't race a live worker — and re-enqueue
        # ``run_target_analysis`` on the vr worker queue.
        if kind_str == TargetKind.ANDROID_APK.value:
            from aila.api.deps import get_task_queue
            from aila.modules.vr.contracts.target_stages import StageName, StageState
            from aila.modules.vr.services.stage_tracker import (
                parse_stages,
                save_target_stages,
            )

            from .workflow.task import run_target_analysis

            stages = parse_stages(analysis_stages_json)
            android_stage_names = (
                StageName.APK_DECODE,
                StageName.JADX_DECOMPILE,
                StageName.INDEX_DECOMPILED,
                StageName.STATIC_SUMMARY,
                StageName.MOBSF_SCAN,
            )
            reset_count = 0
            for stage_name in android_stage_names:
                status_obj = stages.get(stage_name)
                if status_obj.state == StageState.RUNNING:
                    continue
                status_obj.state = StageState.PENDING
                status_obj.error = None
                status_obj.started_at = None
                status_obj.completed_at = None
                stages.set(stage_name, status_obj)
                reset_count += 1
            await save_target_stages(target_id, stages)

            task_queue = get_task_queue("vr", request)
            handle = await task_queue.submit(
                track="vr",
                fn=run_target_analysis,
                kwargs={"target_id": target_id},
                user_id=auth.user_id,
                group_id=auth.role,
                team_id=auth.team_id,
            )
            apk_path = descriptor.get("apk_path")
            root_path = (
                apk_path
                if isinstance(apk_path, str) and apk_path
                else None
            )
            return DataEnvelope(data={
                "target_id": target_id,
                "display_name": display_name,
                "status": "rebuilding",
                "old_sha": None,
                "new_sha": None,
                "index_id": "",
                "forced": bool(force),
                "root_path": root_path,
                "stages_reset": reset_count,
                "task_id": handle.task_id,
            })
        if not index_id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Target {display_name!r} has no audit-mcp index "
                    "yet — run analysis (POST /targets/{id}/analyze or "
                    "resume-analysis) before refreshing."
                ),
            )

        registry_svc = McpRegistryService()
        # _spec/_resolved_url are 'private' by convention but stable
        # since they back the public /mcp/servers route too.
        spec = registry_svc._spec("audit_mcp")  # noqa: SLF001
        if spec is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="audit_mcp not registered in MCP_SERVERS catalog.",
            )
        base_url, _src = await registry_svc._resolved_url(spec)  # noqa: SLF001

        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(
                    f"{base_url}/tools/refresh_index",
                    json={"index_id": index_id, "force": bool(force)},
                )
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"audit-mcp at {base_url} unreachable: {exc}",
            ) from exc
        try:
            mcp_result = resp.json()
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"audit-mcp returned non-JSON: {resp.text[:200]}",
            ) from exc
        if resp.status_code >= 400 or mcp_result.get("status") == "error":
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=(
                    f"audit-mcp refresh_index failed: "
                    f"{mcp_result.get('error', resp.text[:200])}"
                ),
            )

        # If audit-mcp re-keyed the index (drop + start_index can yield a
        # new id when the deterministic path-based key changes), persist
        # the new handle so subsequent calls find it.
        new_index_id = mcp_result.get("index_id")
        if new_index_id and new_index_id != index_id:
            async with UnitOfWork() as uow:
                refreshed_row = (await uow.session.exec(
                    _team_filter(
                        select(VRTargetRecord).where(VRTargetRecord.id == target_id),
                        VRTargetRecord, auth,
                    ),
                )).first()
                if refreshed_row is not None:
                    try:
                        h = _json.loads(refreshed_row.mcp_handles_json or "{}")
                    except (ValueError, TypeError):
                        h = {}
                    h["audit_mcp_index_id"] = new_index_id
                    refreshed_row.mcp_handles_json = _json.dumps(h)
                    uow.session.add(refreshed_row)

        return DataEnvelope(data={
            "target_id": target_id,
            "display_name": display_name,
            "status": mcp_result.get("status", "unknown"),
            "old_sha": mcp_result.get("old_sha"),
            "new_sha": mcp_result.get("new_sha") or mcp_result.get("sha"),
            "index_id": new_index_id or index_id,
            "forced": bool(force),
            "root_path": mcp_result.get("root_path"),
        })

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
        # android_apk is NOT in this set — it has its dedicated multipart
        # endpoint POST /vr/targets/upload-apk that runs the four-stage
        # ingestion pipeline. This legacy upload path handles raw binary
        # kinds only.
        upload_kinds = {
            "native_binary", "kernel_image", "kernel_module",
            "hypervisor_image", "ipa", "jar", "dotnet_assembly",
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

    @router.post(
        "/targets/upload-apk",
        response_model=DataEnvelope[dict],
        status_code=status.HTTP_201_CREATED,
        summary=(
            "Upload an Android APK and create a new android_apk target. "
            "Streams the bytes to the android-mcp uploads directory "
            "(`~/.android-mcp/uploads/<team_id>/<sha>.apk`, override via "
            "`ANDROID_MCP_UPLOAD_DIR`), creates a VRTargetRecord with "
            "kind=android_apk and an apk_path descriptor, and auto-enqueues "
            "the APK_DECODE / JADX_DECOMPILE / INDEX_DECOMPILED / "
            "STATIC_SUMMARY / MOBSF_SCAN ingestion stages."
        ),
    )
    @limiter.limit("10/minute")
    async def upload_apk_target(
        request: Request,
        workspace_id: str = Form(..., min_length=1, max_length=64),
        display_name: str = Form(..., min_length=1, max_length=255),
        file: UploadFile = File(...),
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict]:
        """Upload an APK as a new ``android_apk`` target (PRD §C-19).

        The endpoint is content-addressed: two uploads with identical
        SHA-256 share the on-disk APK file but still create distinct
        target rows (each row carries its own descriptor + lifecycle).
        ``ANDROID_MCP_UPLOAD_DIR`` overrides the default
        ``~/.android-mcp/uploads`` root so the operator can stage uploads
        on a different volume without symlink tricks.

        Per-stage ingestion (APK_DECODE / JADX_DECOMPILE / INDEX_DECOMPILED
        / STATIC_SUMMARY / MOBSF_SCAN) is dispatched via
        ``run_target_analysis``; ``TargetAnalysisService.analyze()`` routes
        ``android_apk`` through ``_analyze_android_apk`` so each stage runs
        under its own ``StageTracker`` and persists handles in
        ``mcp_handles_json``.
        """
        import hashlib
        import json as _json
        import os
        import tempfile
        from pathlib import Path

        from aila.api.deps import get_task_queue

        from .db_models import VRTargetRecord, VRWorkspaceRecord

        # 1) Validate workspace ownership before touching disk.
        async with UnitOfWork() as uow:
            workspace = (await uow.session.exec(
                _team_filter(
                    select(VRWorkspaceRecord).where(VRWorkspaceRecord.id == workspace_id),
                    VRWorkspaceRecord, auth,
                ),
            )).first()
            if workspace is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=(
                        f"Workspace {workspace_id} not found or not "
                        "owned by your team."
                    ),
                )

        if not file.filename:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="file.filename is required.",
            )
        if not file.filename.lower().endswith(".apk"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Expected an .apk file extension.",
            )

        # 2) Resolve the upload root + per-team subdir. With admin auth
        #    (TEAM-06 god-tier) team_id is None; those uploads land
        #    under a "shared" subdir to avoid clashing with team data.
        upload_root_env = os.environ.get("ANDROID_MCP_UPLOAD_DIR")
        upload_root = (
            Path(upload_root_env)
            if upload_root_env
            else Path.home() / ".android-mcp" / "uploads"
        )
        team_subdir = auth.team_id or "shared"
        team_dir = upload_root / team_subdir
        try:
            team_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to create upload directory {team_dir}: {exc}",
            ) from exc

        # 3) Stream to a temp file in the same directory and hash on the
        #    fly. Atomic rename only after we know the digest — keeps
        #    half-written partials out of the SHA-named slot.
        sha256 = hashlib.sha256()
        fd, tmp_str = tempfile.mkstemp(
            prefix=".upload-", suffix=".apk.partial", dir=str(team_dir),
        )
        tmp_path = Path(tmp_str)
        bytes_written = 0
        try:
            with os.fdopen(fd, "wb") as out:
                while True:
                    chunk = await file.read(1 << 20)  # 1 MiB
                    if not chunk:
                        break
                    sha256.update(chunk)
                    out.write(chunk)
                    bytes_written += len(chunk)
        except OSError as exc:
            tmp_path.unlink(missing_ok=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to persist APK upload: {exc}",
            ) from exc

        if bytes_written == 0:
            tmp_path.unlink(missing_ok=True)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Empty APK upload.",
            )

        digest = sha256.hexdigest()
        apk_path = team_dir / f"{digest}.apk"
        if apk_path.exists():
            # Same content already on disk — discard the duplicate copy.
            tmp_path.unlink(missing_ok=True)
        else:
            try:
                tmp_path.replace(apk_path)
            except OSError as exc:
                tmp_path.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to finalize APK upload at {apk_path}: {exc}",
                ) from exc

        # 4) Create the target row. descriptor.apk_path matches the key
        #    used by the existing `apk` (IDA) kind so the C-20 staged
        #    ingestion can resolve the path with the same lookup.
        descriptor = {
            "apk_path": str(apk_path.resolve()),
            "uploaded_filename": file.filename,
            "uploaded_sha256": digest,
        }
        async with UnitOfWork() as uow:
            record = VRTargetRecord(
                workspace_id=workspace_id,
                team_id=auth.team_id,
                display_name=display_name,
                kind=TargetKind.ANDROID_APK.value,
                descriptor_json=_json.dumps(descriptor),
                primary_language=None,
                secondary_languages_json="[]",
                tags_json="[]",
                status="active",
                capability_profile_json="{}",
            )
            uow.session.add(record)
            await uow.session.commit()
            await uow.session.refresh(record)
            target_id = record.id

        # 5) Enqueue ingestion. Mirrors create_target's "fire-and-fall-
        #    back" pattern: if the queue isn't reachable, persist the
        #    failure on the row so the operator can retry via
        #    POST /vr/targets/{id}/analyze without a 500.
        enqueue_error: str | None = None
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
            enqueue_error = f"failed to enqueue ingestion: {exc}"
            async with UnitOfWork() as uow:
                row = (await uow.session.exec(
                    select(VRTargetRecord).where(VRTargetRecord.id == target_id),
                )).first()
                if row is not None:
                    row.analysis_state = AnalysisState.FAILED.value
                    row.analysis_state_message = enqueue_error
                    uow.session.add(row)
                    await uow.session.commit()

        return DataEnvelope(
            data={
                "target_id": target_id,
                "uploaded_filename": file.filename,
                "uploaded_sha256": digest,
                "apk_path": str(apk_path.resolve()),
                "bytes_written": bytes_written,
                "enqueue_error": enqueue_error,
            },
        )

    @router.post(
        "/targets/{target_id}/masvs-audit",
        response_model=DataEnvelope[MasvsAuditDispatchResponse],
        status_code=status.HTTP_201_CREATED,
        summary=(
            "Dispatch an OWASP MASVS audit against an android_apk target. "
            "Creates one parent VRInvestigation (kind=masvs_audit) + one "
            "child VRInvestigation per L1 control (kind=audit, "
            "parent_investigation_id pointing at the parent). Each child "
            "carries a verification prompt built from the catalog entry "
            "plus the parent target's apk_overview, and is submitted to "
            "the vr ARQ queue via the existing run_vr_investigate task "
            "(D-2). Per-child submit failures land in enqueue_errors so "
            "a transient queue outage on one child does not roll back "
            "the parent + sibling rows."
        ),
    )
    @limiter.limit("6/minute")
    async def dispatch_masvs_audit(
        request: Request,
        target_id: str,
        response: Response,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[MasvsAuditDispatchResponse]:
        """Fan one MASVS audit out into per-control child investigations.

        Refuses with 409 when the target is not an ``android_apk`` or
        when ``STATIC_SUMMARY`` has not yet populated
        ``apk_overview.static_summary`` — the per-control prompt builder
        needs at least the package name / version / decompiled-index id
        cells for a useful scout brief.

        Per-child ARQ submission (D-2) runs in a best-effort loop after
        the parent + children commit: each child id either lands in the
        ``vr`` queue via ``run_vr_investigate`` or surfaces in the
        response's ``enqueue_errors`` map. Partial failures do NOT roll
        back the records — the operator can retry an individual child
        via ``POST /vr/investigations/{id}/re-enqueue``.

        Idempotency (D-3): when the target already has an active MASVS
        audit parent (``kind=masvs_audit``, status in CREATED / RUNNING /
        PAUSED) whose catalog version matches the current
        :data:`aila.modules.vr.masvs.CATALOG_VERSION`, the endpoint
        returns that parent's ids verbatim with ``idempotent_reuse=True``
        and HTTP 200 — no second parent or sibling children are
        materialized, and the ARQ queue is not re-touched. A parent in
        a terminal status (COMPLETED / FAILED / ABANDONED) does NOT
        block a fresh dispatch: an operator deliberately re-running an
        audit expects a new batch against the latest target state.
        """
        import json as _json

        from aila.api.deps import get_task_queue
        from aila.modules.vr.masvs import (
            CATALOG_VERSION,
            MASVS_CONTROLS,
            MasvsLevel,
            MasvsSeedBuilder,
        )

        from .db_models import (
            VRInvestigationBranchRecord,
            VRInvestigationRecord,
            VRTargetRecord,
        )
        from .workflow.task import run_vr_investigate

        async with UnitOfWork() as uow:
            target = (await uow.session.exec(
                _team_filter(
                    select(VRTargetRecord).where(VRTargetRecord.id == target_id),
                    VRTargetRecord, auth,
                ),
            )).first()
            if target is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=(
                        f"Target {target_id} not found or not owned by your team."
                    ),
                )
            if target.kind != TargetKind.ANDROID_APK.value:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"Target {target_id} kind is {target.kind!r}; MASVS "
                        "audit applies to android_apk targets only."
                    ),
                )

            target_summary = _target_summary(target)
            apk_overview = target_summary.apk_overview
            static_summary: dict[str, Any] = {}
            if isinstance(apk_overview, dict):
                maybe_static = apk_overview.get("static_summary")
                if isinstance(maybe_static, dict):
                    static_summary = maybe_static
            if not static_summary:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"Target {target_id} has not completed the "
                        "STATIC_SUMMARY ingestion stage; the MASVS "
                        "dispatcher needs the package / version / "
                        "decompiled-index cells before fanning out."
                    ),
                )

            # D-3 idempotency: same target + same catalog version with
            # an existing parent in a non-terminal status returns that
            # parent verbatim, with response status 200 and
            # ``idempotent_reuse=True`` so the client can distinguish a
            # reuse from a fresh dispatch. The catalog-version match
            # parses each candidate's secondary_target_refs_json rather
            # than running a JSON-shaped LIKE — secondary_target_refs_json
            # is a Text column on every backend, and the candidate set
            # per (target, kind, active status) is tiny (typically 0 or
            # 1). Terminal parents (COMPLETED / FAILED / ABANDONED) are
            # excluded so an operator can re-run an audit after the
            # previous batch finished.
            _active_parent_statuses = (
                InvestigationStatus.CREATED.value,
                InvestigationStatus.RUNNING.value,
                InvestigationStatus.PAUSED.value,
            )
            candidate_parents = (await uow.session.exec(
                _team_filter(
                    select(VRInvestigationRecord)
                    .where(VRInvestigationRecord.target_id == target.id)
                    .where(
                        VRInvestigationRecord.kind
                        == InvestigationKind.MASVS_AUDIT.value,
                    )
                    .where(
                        VRInvestigationRecord.parent_investigation_id.is_(
                            None,
                        ),
                    )
                    .where(
                        VRInvestigationRecord.status.in_(
                            _active_parent_statuses,
                        ),
                    )
                    .order_by(VRInvestigationRecord.created_at.desc()),
                    VRInvestigationRecord, auth,
                ),
            )).all()
            existing_parent: VRInvestigationRecord | None = None
            for candidate in candidate_parents:
                try:
                    refs = _json.loads(
                        candidate.secondary_target_refs_json or "[]",
                    )
                except ValueError:
                    continue
                if not isinstance(refs, list):
                    continue
                for ref in refs:
                    if (
                        isinstance(ref, dict)
                        and ref.get("masvs_spec_version") == CATALOG_VERSION
                    ):
                        existing_parent = candidate
                        break
                if existing_parent is not None:
                    break
            if existing_parent is not None:
                existing_children = (await uow.session.exec(
                    select(VRInvestigationRecord)
                    .where(
                        VRInvestigationRecord.parent_investigation_id
                        == existing_parent.id,
                    )
                    .order_by(VRInvestigationRecord.created_at.asc()),
                )).all()
                response.status_code = status.HTTP_200_OK
                return DataEnvelope(
                    data=MasvsAuditDispatchResponse(
                        parent_investigation_id=existing_parent.id,
                        child_investigation_ids=[
                            c.id for c in existing_children
                        ],
                        total_controls=len(existing_children),
                        masvs_spec_version=CATALOG_VERSION,
                        cost_budget_total_usd=existing_parent.cost_budget_usd,
                        enqueue_errors={},
                        idempotent_reuse=True,
                    ),
                )

            l1_controls = tuple(
                c for c in MASVS_CONTROLS if c.level == MasvsLevel.L1
            )
            if not l1_controls:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=(
                        "MASVS catalog has zero L1 controls; refusing to "
                        "dispatch an empty audit. Check "
                        "aila.modules.vr.masvs.catalog.MASVS_CONTROLS."
                    ),
                )

            package_label = static_summary.get("package")
            if not isinstance(package_label, str) or not package_label.strip():
                package_label = target.display_name
            child_budget_usd = 50.0
            total_budget_usd = child_budget_usd * len(l1_controls)

            parent = VRInvestigationRecord(
                target_id=target.id,
                team_id=auth.team_id,
                secondary_target_refs_json=_json.dumps(
                    [{"masvs_spec_version": CATALOG_VERSION}],
                ),
                kind=InvestigationKind.MASVS_AUDIT.value,
                title=f"MASVS audit: {package_label}",
                initial_question=(
                    f"MASVS audit batch parent — {len(l1_controls)} child "
                    "investigations dispatched, one per OWASP MASVS L1 "
                    f"control (catalog {CATALOG_VERSION}). See child "
                    "investigations for per-control evidence and verdicts."
                ),
                status=InvestigationStatus.CREATED.value,
                auto_pilot=False,
                strategy_family="vulnerability_research.masvs_audit",
                cost_budget_usd=total_budget_usd,
            )
            uow.session.add(parent)
            await uow.session.flush()

            child_ids: list[str] = []
            for control in l1_controls:
                child_title = f"MASVS {control.id}: {control.title[:200]}"
                child_question = MasvsSeedBuilder.build(
                    control,
                    apk_overview if isinstance(apk_overview, dict) else None,
                )
                child = VRInvestigationRecord(
                    target_id=target.id,
                    team_id=auth.team_id,
                    parent_investigation_id=parent.id,
                    secondary_target_refs_json=_json.dumps([
                        {
                            "masvs_control_id": control.id,
                            "masvs_spec_version": CATALOG_VERSION,
                        },
                    ]),
                    kind=InvestigationKind.AUDIT.value,
                    title=child_title[:255],
                    initial_question=child_question,
                    status=InvestigationStatus.CREATED.value,
                    auto_pilot=True,
                    strategy_family=_KIND_DEFAULT_STRATEGY[
                        InvestigationKind.AUDIT
                    ],
                    cost_budget_usd=child_budget_usd,
                )
                uow.session.add(child)
                await uow.session.flush()
                child_ids.append(child.id)

                primary_branch = VRInvestigationBranchRecord(
                    investigation_id=child.id,
                    status=BranchStatus.ACTIVE.value,
                    fork_reason="primary",
                    # Phase E §177/§178 — every primary branch carries
                    # the lead-researcher persona ('halvar'). Without
                    # this, alembic 064 defaults the NULL write to
                    # 'unspecified' and the frontend renders "Unnamed
                    # branch" for every fresh investigation.
                    persona_voice=PersonaVoice.HALVAR.value,
                )
                uow.session.add(primary_branch)

            await uow.session.commit()
            await uow.session.refresh(parent)

        # D-2: submit each child to the vr ARQ queue via the existing
        # run_vr_investigate task — same code path as a one-off
        # /vr/investigations dispatch. The full scout / critic / verifier
        # chain then runs against each child with the standard
        # android_apk tool surface (android_mcp + audit_mcp against the
        # jadx-decompiled index). Submission happens AFTER the commit so
        # the worker can always find the row; a transient queue outage
        # leaves the children in CREATED status with a captured error
        # rather than rolling back the parent + sibling rows.
        # APK MASVS audits are throttled: fan-out of N=46 children all
        # streaming through OmniRoute simultaneously was OOM-ing the
        # local LLM proxy (~9.7 GB available, Node default heap ~4 GB,
        # each agent's streaming buffers add up). Operator-tunable batch
        # size keeps only MASVS_AUDIT_BATCH_SIZE children in flight at
        # any given moment for android_apk targets; the masvs parent
        # reconciler enqueues the next batch when slots free up.
        #
        # Source-repo / cve / patch-diff targets continue to fan-out-all
        # because their per-child LLM cost is small enough to not strain
        # the proxy (no jadx graph traversal, no 64K-token contexts).
        # Operator-tunable batch size; deferred import per file convention.
        try:
            _batch_size_raw = int(
                _os.environ.get("MASVS_AUDIT_BATCH_SIZE", "5"),
            )
        except ValueError:
            _batch_size_raw = 5
        masvs_batch_size = max(1, min(_batch_size_raw, len(child_ids)))
        is_apk = target.kind == TargetKind.ANDROID_APK.value
        initial_batch = child_ids[:masvs_batch_size] if is_apk else child_ids
        deferred = child_ids[masvs_batch_size:] if is_apk else []

        enqueue_errors: dict[str, str] = {}
        try:
            task_queue = get_task_queue("vr", request)
        except HTTPException as exc:
            err_msg = f"task queue unavailable: {exc.detail}"
            _log.warning(
                "MASVS audit %s could not acquire the vr task queue: %s; "
                "all %d children remain in CREATED status awaiting "
                "/re-enqueue.", parent.id, exc.detail, len(child_ids),
            )
            enqueue_errors = {cid: err_msg for cid in child_ids}
        else:
            for cid in initial_batch:
                try:
                    await task_queue.submit(
                        track="vr",
                        fn=run_vr_investigate,
                        kwargs={"investigation_id": cid},
                        user_id=auth.user_id,
                        group_id=auth.role,
                        team_id=auth.team_id,
                    )
                except (OSError, RuntimeError, HTTPException) as exc:
                    err_msg = f"failed to enqueue: {exc}"
                    enqueue_errors[cid] = err_msg
                    _log.warning(
                        "MASVS audit %s child %s failed to enqueue: %s",
                        parent.id, cid, exc,
                    )
            if deferred:
                _log.info(
                    "MASVS audit %s (APK) batched: enqueued %d/%d children, "
                    "%d deferred (parent reconciler will enqueue as slots free). "
                    "batch_size=%d via MASVS_AUDIT_BATCH_SIZE env.",
                    parent.id, len(initial_batch), len(child_ids),
                    len(deferred), masvs_batch_size,
                )

        return DataEnvelope(
            data=MasvsAuditDispatchResponse(
                parent_investigation_id=parent.id,
                child_investigation_ids=child_ids,
                total_controls=len(l1_controls),
                masvs_spec_version=CATALOG_VERSION,
                cost_budget_total_usd=total_budget_usd,
                enqueue_errors=enqueue_errors,
            ),
        )

    @router.get(
        "/targets/{target_id}/masvs-report",
        summary=(
            "Download the MASVS audit report PDF for one parent "
            "investigation. Aggregates every child outcome through the "
            "S-4 verdict mapper, renders the per-group ReportLab PDF "
            "(cover + executive summary + per-control subsections), "
            "and streams it back with Content-Type application/pdf and "
            "Content-Disposition attachment. Partial reports are "
            "valid — children still in flight render as INCONCLUSIVE "
            "rows so an operator can hand the CISO a checkpoint copy "
            "without waiting for the full ~60min batch."
        ),
        response_class=Response,
        responses={
            200: {
                "description": "PDF report ready for download.",
                "content": {
                    "application/pdf": {
                        "schema": {"type": "string", "format": "binary"},
                    },
                },
            },
        },
    )
    @limiter.limit("10/minute")
    async def export_masvs_report(
        request: Request,
        target_id: str,
        audit_id: str = Query(
            ...,
            description=(
                "Parent VRInvestigation id (kind=masvs_audit) returned "
                "by POST /vr/targets/{target_id}/masvs-audit."
            ),
        ),
        auth: AuthContext = Depends(require_auth),
    ) -> Response:
        """Stream the MASVS audit PDF for ``audit_id`` under ``target_id``.

        Refuses with:

        * **404** when the target is not visible to the caller's team,
          when the parent investigation does not exist, or when it
          exists but points at a different target (a defensive guard so
          an operator with cross-target audit ids can't accidentally
          download a report under the wrong target context).
        * **409** when the parent exists but its ``kind`` is not
          ``masvs_audit``. The renderer is specific to MASVS batches —
          a one-off audit investigation has its own
          ``GET /investigations/{id}/report.pdf`` route.

        The PDF is rendered synchronously via ReportLab; the render is
        pushed onto a worker thread via :func:`asyncio.to_thread` so a
        large aggregate (~46 L1 controls plus subsections) doesn't
        block the event loop while reportlab walks the flow.
        """
        del request

        from aila.modules.vr.reporting.masvs_report import (
            build_pdf,
            collect_findings,
        )

        from .db_models import VRInvestigationRecord, VRTargetRecord

        async with UnitOfWork() as uow:
            target = (await uow.session.exec(
                _team_filter(
                    select(VRTargetRecord).where(
                        VRTargetRecord.id == target_id,
                    ),
                    VRTargetRecord, auth,
                ),
            )).first()
            if target is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=(
                        f"Target {target_id} not found or not owned "
                        "by your team."
                    ),
                )
            parent = (await uow.session.exec(
                _team_filter(
                    select(VRInvestigationRecord).where(
                        VRInvestigationRecord.id == audit_id,
                    ),
                    VRInvestigationRecord, auth,
                ),
            )).first()
            if parent is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=(
                        f"MASVS audit {audit_id} not found or not "
                        "owned by your team."
                    ),
                )
            if parent.kind != InvestigationKind.MASVS_AUDIT.value:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"Investigation {audit_id} kind={parent.kind!r}; "
                        "MASVS report requires a parent investigation "
                        "with kind='masvs_audit'."
                    ),
                )
            if parent.target_id != target_id:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=(
                        f"MASVS audit {audit_id} does not belong to "
                        f"target {target_id}."
                    ),
                )
            target_summary = _target_summary(target)

        try:
            aggregate = await collect_findings(audit_id)
        except ValueError as exc:
            # collect_findings re-validates parent kind / existence; a
            # race between the lookup above and the aggregate query
            # (parent deleted mid-request) surfaces as 404 so the
            # caller gets the same shape as the up-front guard.
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc

        handles_dict: dict[str, Any] = {}
        try:
            if target.mcp_handles_json:
                handles_dict = json.loads(target.mcp_handles_json)
        except (ValueError, TypeError):
            handles_dict = {}

        # PDF renders cached _report_section if present on the outcome
        # payload (populated by the report-writer agent as part of
        # the workflow lifecycle, NOT inline here). When no cached
        # section is present, the renderer falls back to the raw
        # agent_summary. The PDF endpoint never makes LLM calls.
        # build_pdf is sync (CPU-bound ReportLab render). The
        # investigation-report endpoint follows the same pattern —
        # render directly on the event loop. The aggregate is bounded
        # (≤53 L1 verdicts), so the render stays well inside ASGI
        # request-budget territory.
        pdf_bytes = build_pdf(aggregate, target_summary, handles=handles_dict)

        filename = _masvs_report_filename(
            target_summary,
            aggregate.generated_at.strftime("%Y%m%d"),
        )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{filename}"'
                ),
                "Cache-Control": "no-store",
            },
        )

    @router.get(
        "/targets/{target_id}/masvs-audit-aggregate",
        response_model=DataEnvelope[MasvsAuditAggregate],
        summary=(
            "Return the structured MASVS audit aggregate as JSON. "
            "Drives the operator-facing per-control table (U-2): one "
            "verdict row per child investigation, grouped by MASVS "
            "control group, with verifier confidence and evidence "
            "links. Same aggregation pipeline the PDF report uses — "
            "partial aggregates are valid (children still in flight "
            "render as INCONCLUSIVE)."
        ),
    )
    @limiter.limit("30/minute")
    async def get_masvs_audit_aggregate(
        request: Request,
        target_id: str,
        audit_id: str = Query(
            ...,
            description=(
                "Parent VRInvestigation id (kind=masvs_audit) returned "
                "by POST /vr/targets/{target_id}/masvs-audit."
            ),
        ),
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[MasvsAuditAggregate]:
        """Return the JSON aggregate for ``audit_id`` under ``target_id``.

        Refuses with the same shape as the PDF report endpoint so a
        frontend can rely on consistent error semantics across the
        two surfaces:

        * **404** when the target is not visible to the caller's team,
          when the parent investigation does not exist, or when it
          exists but points at a different target (defensive guard
          against pasted audit ids under the wrong target context).
        * **409** when the parent exists but its ``kind`` is not
          ``masvs_audit`` — the aggregator is specific to MASVS
          batches.

        Aggregation is forwarded to :func:`collect_findings`. The
        endpoint does *not* materialize the PDF — clients that want
        the PDF call ``GET /vr/targets/{id}/masvs-report`` instead.
        """
        del request

        from aila.modules.vr.reporting.masvs_report import collect_findings

        from .db_models import VRInvestigationRecord, VRTargetRecord

        async with UnitOfWork() as uow:
            target = (await uow.session.exec(
                _team_filter(
                    select(VRTargetRecord).where(
                        VRTargetRecord.id == target_id,
                    ),
                    VRTargetRecord, auth,
                ),
            )).first()
            if target is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=(
                        f"Target {target_id} not found or not owned "
                        "by your team."
                    ),
                )
            parent = (await uow.session.exec(
                _team_filter(
                    select(VRInvestigationRecord).where(
                        VRInvestigationRecord.id == audit_id,
                    ),
                    VRInvestigationRecord, auth,
                ),
            )).first()
            if parent is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=(
                        f"MASVS audit {audit_id} not found or not "
                        "owned by your team."
                    ),
                )
            if parent.kind != InvestigationKind.MASVS_AUDIT.value:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"Investigation {audit_id} kind={parent.kind!r}; "
                        "MASVS aggregate requires a parent investigation "
                        "with kind='masvs_audit'."
                    ),
                )
            if parent.target_id != target_id:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=(
                        f"MASVS audit {audit_id} does not belong to "
                        f"target {target_id}."
                    ),
                )

        try:
            aggregate = await collect_findings(audit_id)
        except ValueError as exc:
            # collect_findings re-validates parent kind / existence; a
            # race between the lookup above and the aggregate query
            # (parent deleted mid-request) surfaces as 404 so the
            # caller gets the same shape as the up-front guard.
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc

        return DataEnvelope(data=aggregate)

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

            # Derive strategy_family from kind when caller didn't pick
            # one explicitly. Without this, VARIANT_HUNT investigations
            # silently used discovery_research (the Pydantic default),
            # so the variant-hunt system prompt + dispatcher rules
            # never fired.
            resolved_strategy = (
                body.strategy_family
                or _KIND_DEFAULT_STRATEGY.get(body.kind, "vulnerability_research.discovery_research")
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
                strategy_family=resolved_strategy,
                cost_budget_usd=body.cost_budget_usd,
            )
            uow.session.add(record)
            await uow.session.flush()

            primary_branch = VRInvestigationBranchRecord(
                investigation_id=record.id,
                status=BranchStatus.ACTIVE.value,
                fork_reason="primary",
                # fix §177/§178 — primary persona is HALVAR (lead
                # researcher). Auto-deliberation siblings cover the
                # other 5 personas (noor/maddie/yuki/renzo/wei).
                persona_voice=PersonaVoice.HALVAR.value,
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
        summary="List investigations (filterable by target_id, kind, status, q).",
    )
    @limiter.limit("60/minute")
    async def list_investigations(
        request: Request,
        auth: AuthContext = Depends(require_auth),
        target_id: str | None = Query(default=None),
        kind: str | None = Query(default=None),
        investigation_status: str | None = Query(default=None, alias="status"),
        q: str | None = Query(default=None, description="Case-insensitive title substring filter."),
        favorites: bool = Query(default=False, description="Restrict to is_favorite=true rows."),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=500),
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
            if q is not None and q.strip():
                pattern = f"%{q.strip()}%"
                base = base.where(VRInvestigationRecord.title.ilike(pattern))
                count_base = count_base.where(VRInvestigationRecord.title.ilike(pattern))
            if favorites:
                base = base.where(VRInvestigationRecord.is_favorite.is_(True))
                count_base = count_base.where(VRInvestigationRecord.is_favorite.is_(True))

            total = (await uow.session.exec(count_base)).one()
            rows = (await uow.session.exec(
                base.order_by(VRInvestigationRecord.created_at.desc()).offset(offset).limit(limit)
            )).all()

        # Batch-load counts + primary outcome details so the list page
        # shows real numbers and the canonical verdict per row without
        # an N+1 round-trip to the detail endpoint. Previous behavior
        # passed 0 for every count, so even completed investigations
        # appeared empty on the list — and there was no way to see at
        # a glance whether an investigation had landed a finding.
        if rows:

            row_ids = [r.id for r in rows]
            primary_ids = {r.id: r.primary_outcome_id for r in rows if r.primary_outcome_id}

            async with UnitOfWork() as uow:
                br_pairs = (await uow.session.exec(
                    select(
                        VRInvestigationBranchRecord.investigation_id,
                        sa_func.count(),
                    )
                    .where(VRInvestigationBranchRecord.investigation_id.in_(row_ids))
                    .group_by(VRInvestigationBranchRecord.investigation_id),
                )).all()
                br_counts = {iid: int(c) for iid, c in br_pairs}
                msg_pairs = (await uow.session.exec(
                    select(
                        VRInvestigationMessageRecord.investigation_id,
                        sa_func.count(),
                    )
                    .where(VRInvestigationMessageRecord.investigation_id.in_(row_ids))
                    .group_by(VRInvestigationMessageRecord.investigation_id),
                )).all()
                msg_counts = {iid: int(c) for iid, c in msg_pairs}
                oc_pairs = (await uow.session.exec(
                    select(
                        VRInvestigationOutcomeRecord.investigation_id,
                        sa_func.count(),
                    )
                    .where(VRInvestigationOutcomeRecord.investigation_id.in_(row_ids))
                    .group_by(VRInvestigationOutcomeRecord.investigation_id),
                )).all()
                oc_counts = {iid: int(c) for iid, c in oc_pairs}
                outcome_rows: list[Any] = []
                if primary_ids:
                    outcome_rows = (await uow.session.exec(
                        select(VRInvestigationOutcomeRecord)
                        .where(VRInvestigationOutcomeRecord.id.in_(list(primary_ids.values()))),
                    )).all()
                primary_by_inv: dict[str, Any] = {}
                for o in outcome_rows:
                    primary_by_inv[o.investigation_id] = o

            items = []
            for r in rows:
                primary = primary_by_inv.get(r.id)
                verdict_head: str | None = None
                verifier_verdict: str | None = None
                verifier_confidence: float | None = None
                if primary is not None:
                    try:
                        payload = _json.loads(primary.payload_json or "{}")
                    except (ValueError, TypeError):
                        payload = {}
                    ps = payload.get("panel_summary")
                    if isinstance(ps, dict):
                        verdict_head = ((ps.get("narrative") or "").splitlines() or [""])[0][:140]
                    if not verdict_head:
                        verdict_head = ((payload.get("answer") or "").splitlines() or [""])[0][:140]
                    vr = payload.get("verifier_report")
                    if isinstance(vr, dict):
                        verifier_verdict = str(vr.get("verdict") or "") or None
                        vc = vr.get("confidence")
                        if isinstance(vc, (int, float)):
                            verifier_confidence = float(vc)
                items.append(_investigation_summary(
                    r,
                    branch_count=br_counts.get(r.id, 0),
                    message_count=msg_counts.get(r.id, 0),
                    outcome_count=oc_counts.get(r.id, 0),
                    primary_outcome_kind=primary.outcome_kind if primary else None,
                    primary_outcome_confidence=primary.confidence if primary else None,
                    primary_outcome_verdict_head=verdict_head or None,
                    verifier_verdict=verifier_verdict,
                    verifier_confidence=verifier_confidence,
                ))
        else:
            items = []

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

            primary_outcome_kind: str | None = None
            primary_outcome_confidence: str | None = None
            primary_outcome_verdict_head: str | None = None
            verifier_verdict: str | None = None
            verifier_confidence: float | None = None
            if inv.primary_outcome_id:
                primary = (await uow.session.exec(
                    select(VRInvestigationOutcomeRecord).where(
                        VRInvestigationOutcomeRecord.id == inv.primary_outcome_id,
                    ),
                )).first()
                if primary is not None:
                    primary_outcome_kind = primary.outcome_kind
                    primary_outcome_confidence = primary.confidence
                    try:
                        payload = _json.loads(primary.payload_json or "{}")
                    except (ValueError, TypeError):
                        payload = {}
                    ps = payload.get("panel_summary")
                    if isinstance(ps, dict):
                        primary_outcome_verdict_head = (
                            (ps.get("narrative") or "").splitlines() or [""]
                        )[0][:140]
                    if not primary_outcome_verdict_head:
                        primary_outcome_verdict_head = (
                            (payload.get("answer") or "").splitlines() or [""]
                        )[0][:140] or None
                    vr = payload.get("verifier_report")
                    if isinstance(vr, dict):
                        verifier_verdict = str(vr.get("verdict") or "") or None
                        vc = vr.get("confidence")
                        if isinstance(vc, (int, float)):
                            verifier_confidence = float(vc)

        # Live cost — aggregate LLMCostRecord by run_id matching this
        # investigation's TaskRecord ids. The stored cost_actual_usd has
        # no writers so without this override every read returned $0
        # regardless of actual spend, making the budget gauge decorative.
        async with UnitOfWork() as uow_cost:
            live_cost = await _compute_live_investigation_cost(uow_cost, investigation_id)
        return DataEnvelope(data=_investigation_summary(
            inv,
            branch_count=int(branch_count),
            message_count=int(message_count),
            outcome_count=int(outcome_count),
            primary_outcome_kind=primary_outcome_kind,
            primary_outcome_confidence=primary_outcome_confidence,
            primary_outcome_verdict_head=primary_outcome_verdict_head,
            verifier_verdict=verifier_verdict,
            verifier_confidence=verifier_confidence,
            live_cost_usd=live_cost,
        ))

    @router.patch(
        "/investigations/{investigation_id}/favorite",
        response_model=DataEnvelope[VRInvestigationSummary],
        summary="Toggle or set is_favorite on an investigation.",
    )
    @limiter.limit("60/minute")
    async def toggle_investigation_favorite(
        request: Request,
        investigation_id: str,
        is_favorite: bool = Query(default=None, description="Explicit set; omit to toggle."),
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRInvestigationSummary]:
        del request

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
            inv.is_favorite = (not inv.is_favorite) if is_favorite is None else bool(is_favorite)
            inv.updated_at = utc_now()
            uow.session.add(inv)
            await uow.commit()
            await uow.session.refresh(inv)

        return DataEnvelope(data=_investigation_summary(inv))

    @router.post(
        "/investigations/{investigation_id}/verify",
        summary=(
            "Manually trigger the claim verifier on this investigation's "
            "canonical outcome. Clears any prior verifier_report and "
            "re-enqueues run_vr_claim_verifier. Useful when prior "
            "verifier runs hit truncation / had stale prompts / etc."
        ),
    )
    @limiter.limit("20/minute")
    async def reverify_investigation(
        request: Request,
        investigation_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        del request


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
            oc = (await uow.session.exec(
                select(VRInvestigationOutcomeRecord)
                .where(VRInvestigationOutcomeRecord.investigation_id == investigation_id)
                .order_by(VRInvestigationOutcomeRecord.created_at.asc())
                .limit(1)
            )).first()
            if oc is None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Investigation has no canonical outcome yet — nothing to verify.",
                )
            try:
                payload = _json.loads(oc.payload_json or "{}")
            except (ValueError, TypeError):
                payload = {}
            had_prior = payload.pop("verifier_report", None) is not None
            oc.payload_json = _json.dumps(payload)
            uow.session.add(oc)
            await uow.commit()
            team_id = inv.team_id

        task_queue = default_task_queue()
        handle = await task_queue.submit(
            track="vr",
            fn=run_vr_claim_verifier,
            kwargs={"investigation_id": investigation_id},
            user_id=auth.user_id,
            group_id="manual_reverify",
            team_id=team_id,
        )
        return {
            "task_id": str(handle),
            "canonical_outcome_id": oc.id,
            "cleared_prior_report": had_prior,
        }

    class PromoteOutcomeResponse(BaseModel):
        """Result of promoting an assessment_report -> direct_finding."""

        outcome_id: str
        promoted_to: str
        dispatch_status: str
        dispatch_target: str | None
        reason: str

    @router.post(
        "/investigations/{investigation_id}/outcomes/{outcome_id}/promote-to-finding",
        response_model=DataEnvelope[PromoteOutcomeResponse],
        summary=(
            "Promote an outcome currently bucketed as ASSESSMENT_REPORT "
            "(skipped by the dispatcher because there is no downstream) "
            "to DIRECT_FINDING, then re-dispatch. Creates a vr_findings "
            "row, auto-enqueues run_vr_draft_poc on variant-child "
            "investigations (PoC writer self-gates on verifier verdict), "
            "and stamps payload.promoted_from with the prior kind + "
            "operator note for audit trail."
        ),
    )
    @limiter.limit("10/minute")
    async def promote_outcome_to_finding(
        request: Request,
        investigation_id: str,
        outcome_id: str,
        body: dict | None = None,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[PromoteOutcomeResponse]:
        del request



        reason_note = ""
        if isinstance(body, dict):
            reason_note = str(body.get("reason") or "")[:500]

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
            oc = (await uow.session.exec(
                select(VRInvestigationOutcomeRecord)
                .where(VRInvestigationOutcomeRecord.id == outcome_id)
                .where(VRInvestigationOutcomeRecord.investigation_id == investigation_id)
            )).first()
            if oc is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=(
                        f"Outcome {outcome_id} not found on investigation "
                        f"{investigation_id}."
                    ),
                )
            if oc.outcome_kind != OutcomeKind.ASSESSMENT_REPORT.value:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"Outcome is {oc.outcome_kind} — only "
                        f"assessment_report outcomes can be promoted to "
                        f"direct_finding (other kinds already have their "
                        f"own dispatch path)."
                    ),
                )
            try:
                payload = _json.loads(oc.payload_json or "{}")
            except (ValueError, TypeError):
                payload = {}
            payload["promoted_from"] = {
                "kind": OutcomeKind.ASSESSMENT_REPORT.value,
                "at": utc_now().isoformat(),
                "by_user_id": auth.user_id,
                "reason": reason_note,
                "prior_dispatch_status": oc.dispatch_status,
            }
            oc.outcome_kind = OutcomeKind.DIRECT_FINDING.value
            oc.payload_json = _json.dumps(payload)
            # Clear dispatch status so the dispatcher will re-route the
            # outcome through _dispatch_direct_finding from scratch
            # (creates vr_findings row, auto-enqueues PoC writer on
            # variant-child investigations).
            oc.dispatch_status = OutcomeDispatchStatus.PENDING.value
            oc.dispatch_target = None
            uow.session.add(oc)
            await uow.commit()

        dispatcher = OutcomeDispatcher(knowledge=ServiceFactory().knowledge)
        result = await dispatcher.dispatch(outcome_id)
        return DataEnvelope(data=PromoteOutcomeResponse(
            outcome_id=outcome_id,
            promoted_to=OutcomeKind.DIRECT_FINDING.value,
            dispatch_status=result.dispatch_status.value,
            dispatch_target=result.dispatch_target,
            reason=result.reason,
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

            # Hard-delete child rows in FK-safe order. Branches have
            # self-FKs (parent_branch_id, merged_into_branch_id) that
            # cause the per-row DELETE to fail with FK violation when
            # PostgreSQL processes the batch in arbitrary order. Null
            # those out FIRST in a separate flush so the subsequent
            # branch DELETEs succeed regardless of ordering.
            branch_rows = (await uow.session.exec(
                select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.investigation_id == investigation_id,
                ),
            )).all()
            for b in branch_rows:
                if b.parent_branch_id is not None:
                    b.parent_branch_id = None
                if b.merged_into_branch_id is not None:
                    b.merged_into_branch_id = None
                uow.session.add(b)
            await uow.session.flush()

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
        """Operator-initiated pause via cursor SSOT (Phase B).

        Dispatches the atomic pause_investigation_atomic() task body,
        which performs one transaction:
          - SELECT FOR UPDATE every active branch's cursor
          - flip current_state -> '__paused__' (archive prior state)
          - cancel TaskRecord rows in queued/running
          - flip inv.status -> PAUSED derived projection
        Followed by best-effort ARQ purge after commit.

        Replaces the prior 3-source-of-truth pattern (inv.status +
        TaskRecord.status + arq:in-progress key) per Phase B closing
        §32/§33/§35/§47.
        """
        del request
        from .db_models import VRInvestigationRecord
        from .workflow.pause_resume import (
            PauseInvestigationError,
            pause_investigation_atomic,
        )

        # Team filter: confirm the auth context can see this row before
        # the atomic op runs. The atomic op itself doesn't enforce team
        # filter (it's an internal helper).
        async with UnitOfWork() as uow:
            inv_check = (await uow.session.exec(
                _team_filter(
                    select(VRInvestigationRecord).where(
                        VRInvestigationRecord.id == investigation_id,
                    ),
                    VRInvestigationRecord, auth,
                )
            )).first()
            if inv_check is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Investigation {investigation_id} not found.",
                )

        try:
            summary = await pause_investigation_atomic(
                investigation_id,
                user_id=auth.user_id,
                reason=InvestigationPauseReason.OPERATOR.value,
            )
        except PauseInvestigationError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc

        _log.info(
            "pause_investigation inv=%s paused_cursors=%d "
            "cancelled_tasks=%d noop=%s",
            investigation_id,
            summary["paused_cursors"],
            summary["cancelled_tasks"],
            summary["noop"],
        )

        # Re-load the inv row for the response envelope.
        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                select(VRInvestigationRecord).where(
                    VRInvestigationRecord.id == investigation_id,
                )
            )).first()
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
        """Operator-initiated resume via cursor SSOT (Phase B).

        Dispatches resume_investigation_atomic() which performs one
        transaction:
          - SELECT FOR UPDATE every cursor with current_state='__paused__'
            tied to this investigation's branches
          - restore archived_state -> current_state, clear archive
          - flip inv.status -> RUNNING
        Then fans out one run_vr_investigate ARQ task PER resumed
        cursor so every branch (not just the primary) ticks again.
        Closes §34.
        """
        from aila.api.deps import get_task_queue

        from .db_models import VRInvestigationRecord
        from .workflow.pause_resume import (
            ResumeInvestigationError,
            resume_investigation_atomic,
        )

        # Team filter first.
        async with UnitOfWork() as uow:
            inv_check = (await uow.session.exec(
                _team_filter(
                    select(VRInvestigationRecord).where(
                        VRInvestigationRecord.id == investigation_id,
                    ),
                    VRInvestigationRecord, auth,
                )
            )).first()
            if inv_check is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Investigation {investigation_id} not found.",
                )

        task_queue = get_task_queue("vr", request)
        try:
            summary = await resume_investigation_atomic(
                investigation_id,
                user_id=auth.user_id,
                task_queue=task_queue,
                auth_user_id=auth.user_id,
                auth_role=auth.role,
                auth_team_id=auth.team_id,
            )
        except ResumeInvestigationError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc

        _log.info(
            "resume_investigation inv=%s resumed_cursors=%d submitted_tasks=%d",
            investigation_id,
            summary["resumed_cursors"],
            summary["submitted_tasks"],
        )

        # Re-load the inv row for response envelope.
        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                select(VRInvestigationRecord).where(
                    VRInvestigationRecord.id == investigation_id,
                )
            )).first()
        return DataEnvelope(data=_investigation_summary(inv))

    @router.post(
        "/investigations/{investigation_id}/reopen",
        response_model=DataEnvelope[VRInvestigationSummary],
        summary=(
            "Reopen a terminal investigation and push it back through "
            "the workflow. Accepts COMPLETED / FAILED / ABANDONED. "
            "Non-destructive: existing branches + messages + outcomes "
            "are preserved as a historical record. Spawns ONE fresh "
            "primary branch with closed_reason='operator_reopen' "
            "tagging on the prior primaries, flips investigation back "
            "to RUNNING, and enqueues run_vr_investigate for the new "
            "branch. Use when an audit closed prematurely (auto-synth "
            "no_finding, rejected outcome, all branches abandoned via "
            "stale-detector during an LLM outage) and the operator "
            "wants another pass."
        ),
    )
    @limiter.limit("10/minute")
    async def reopen_investigation(
        request: Request,
        investigation_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRInvestigationSummary]:


        _reopenable = (
            InvestigationStatus.COMPLETED.value,
            InvestigationStatus.FAILED.value,
            InvestigationStatus.ABANDONED.value,
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
            if inv.status not in _reopenable:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"Cannot reopen investigation in status {inv.status!r}; "
                        f"reopen accepts: {', '.join(_reopenable)}. Use "
                        f"POST /investigations/{{id}}/resume for paused, or "
                        f"/cancel + new dispatch to restart from scratch."
                    ),
                )

            now = utc_now()
            inv.status = InvestigationStatus.RUNNING.value
            inv.pause_reason = None
            inv.stopped_at = None
            inv.updated_at = now
            # Clear primary_outcome_id so investigation_emit treats the
            # next branch's terminal_submit as a fresh outcome to land,
            # not as a redundant re-close of the already-approved one.
            # The old outcome row stays in vr_investigation_outcomes
            # for audit trail (and as a contribution to the eventual
            # multi-outcome synthesis) but the investigation no longer
            # points to it as the canonical answer. Without this, the
            # operator-reopen task's first emit pass sees a complete
            # primary outcome, resolves to COMPLETED with no active
            # siblings (turn_count > 0 excludes the brand-new branch
            # itself), and immediately re-closes the investigation —
            # observed live on inv 70f454ad-..., 3 seconds between
            # /reopen API call and inv.status flipping back to
            # COMPLETED. Operator reopens are explicit intent to
            # discard the prior verdict; the old outcome row stays as
            # history but the inv pointer is reset.
            prior_outcome_id = inv.primary_outcome_id
            inv.primary_outcome_id = None
            uow.session.add(inv)

            # Abandon any prior halvar branches still in a non-terminal
            # state (active, paused, created) before spawning the new
            # one. Without this, repeated reopen/re-enqueue cycles
            # accumulate multiple halvar branches on the same
            # investigation — each cycle (operator pause → reopen, or
            # crashed-then-reenqueued) leaves the prior halvar alive,
            # and downstream consumers (parent_reconciler's branch
            # priority, sibling-consensus quorum, BranchTreePage)
            # double-count. Branches in already-terminal states
            # (abandoned, completed, failed) stay untouched — those
            # are real history.
            from aila.modules.vr.contracts.branch import BranchStatus as _BS  # noqa: PLC0415
            _live_halvars = (await uow.session.exec(
                select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.investigation_id == inv.id,
                    VRInvestigationBranchRecord.persona_voice == PersonaVoice.HALVAR.value,
                    VRInvestigationBranchRecord.status.in_((  # type: ignore[attr-defined]
                        _BS.ACTIVE.value, _BS.PAUSED.value, _BS.CREATED.value,
                    )),
                ),
            )).all()
            new_branch = VRInvestigationBranchRecord(
                investigation_id=inv.id,
                status=BranchStatus.ACTIVE.value,
                fork_reason=f"operator_reopen:{auth.user_id}",
                # fix §177/§178 — reopen creates a fresh primary that
                # carries the lead-researcher persona; without this,
                # the reopened investigation's frontend shows "Unnamed
                # branch" until auto-deliberation populates siblings.
                persona_voice=PersonaVoice.HALVAR.value,
            )
            uow.session.add(new_branch)
            await uow.session.flush()
            for _prior in _live_halvars:
                _prior.status = _BS.ABANDONED.value
                _prior.closed_reason = f"superseded_by_reopen:{new_branch.id}"
                _prior.closed_at = now
                _prior.updated_at = now
                uow.session.add(_prior)
            await uow.session.commit()
            await uow.session.refresh(inv)
            await uow.session.refresh(new_branch)

            _log.info(
                "reopen_investigation inv=%s by=%s new_branch=%s "
                "prior_outcome_id=%s (cleared primary pointer; row "
                "preserved for audit)",
                inv.id, auth.user_id, new_branch.id,
                prior_outcome_id or "none",
            )

        # Submit fresh task for the new branch — same code path as
        # dispatcher / resume. Goes through the regular vr ARQ queue
        # and picks up the existing investigation state (case_state
        # on existing branches stays put; the new branch starts at
        # turn 0 with no carried state).
        task_queue = get_task_queue("vr", request)
        await task_queue.submit(
            track="vr",
            fn=run_vr_investigate,
            kwargs={
                "investigation_id": investigation_id,
                "branch_id": new_branch.id,
            },
            user_id=auth.user_id,
            group_id=auth.role,
            team_id=auth.team_id,
        )

        return DataEnvelope(data=_investigation_summary(inv))

    @router.post(
        "/investigations/{investigation_id}/reset",
        response_model=DataEnvelope[VRInvestigationSummary],
        summary=(
            "Hard-reset an investigation to its initial state. Deletes "
            "all messages + outcomes + non-root branches, resets the "
            "root branch(es) to turn 0 with empty case state, flips "
            "investigation back to CREATED. Operator can then "
            "re-enqueue to start over with the same target + strategy "
            "but a fresh reasoning history. DESTRUCTIVE — no soft-undo."
        ),
    )
    @limiter.limit("5/minute")
    async def reset_investigation(
        request: Request,
        investigation_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRInvestigationSummary]:
        del request


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
            # Refuse to reset a running investigation — operator must
            # pause first so the engine isn't writing while we wipe.
            if inv.status == InvestigationStatus.RUNNING.value:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "Cannot reset a RUNNING investigation. Pause it "
                        "first via POST /pause, then call reset."
                    ),
                )

            branches = (await uow.session.exec(
                select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.investigation_id == investigation_id,
                ),
            )).all()
            branch_ids = [b.id for b in branches]

            # 1) Delete every message on every branch (full reasoning wipe).
            for bid in branch_ids:
                msgs = (await uow.session.exec(
                    select(VRInvestigationMessageRecord).where(
                        VRInvestigationMessageRecord.branch_id == bid,
                    ),
                )).all()
                for m in msgs:
                    await uow.session.delete(m)

            # 2) Delete every outcome for this investigation.
            outcomes = (await uow.session.exec(
                select(VRInvestigationOutcomeRecord).where(
                    VRInvestigationOutcomeRecord.investigation_id == investigation_id,
                ),
            )).all()
            for o in outcomes:
                await uow.session.delete(o)

            # 3) Drop forked branches; reset root branches to turn 0. A root
            # branch is one whose parent_branch_id was NULL in the original
            # data — that's the only invariant. `fork_reason` is free-form
            # ('primary', 'auto_deliberation:maddie', etc.) and unsafe to
            # match by string. Capture root-ness BEFORE we null self-FKs.
            root_branch_ids = {b.id for b in branches if b.parent_branch_id is None}

            # Null self-FKs on every branch first (forks point at root via
            # parent_branch_id; merged_into_branch_id may also be set).
            # PostgreSQL processes bulk delete rows in arbitrary order so
            # any unbroken self-FK can trip a ForeignKeyViolation. Same
            # pattern as the delete fix in 3df57b4.
            for b in branches:
                if b.parent_branch_id is not None:
                    b.parent_branch_id = None
                if b.merged_into_branch_id is not None:
                    b.merged_into_branch_id = None
                uow.session.add(b)
            await uow.session.flush()

            reset_count = 0
            for b in branches:
                if b.id in root_branch_ids:
                    b.turn_count = 0
                    b.case_state_json = "{}"
                    b.branch_cost_usd = 0.0
                    # closed_reason is NOT NULL with server_default="";
                    # passing None tripped NotNullViolationError in PG.
                    b.closed_reason = ""
                    b.closed_at = None
                    b.promoted = False
                    b.status = "active"
                    b.updated_at = utc_now()
                    uow.session.add(b)
                    reset_count += 1
                else:
                    await uow.session.delete(b)

            # 4) Reset investigation row itself. message_count + outcome_count
            # are projections derived at summary time (count from the message /
            # outcome tables), not stored columns — they update implicitly once
            # the deletes above commit.
            inv.status = InvestigationStatus.CREATED.value
            inv.pause_reason = None
            inv.updated_at = utc_now()
            uow.session.add(inv)

            await uow.session.commit()
            await uow.session.refresh(inv)

        return DataEnvelope(data=_investigation_summary(inv))


    @router.post(
        "/investigations/{investigation_id}/re-enqueue",
        response_model=DataEnvelope[VRInvestigationSummary],
        summary=(
            "Re-enqueue the run_vr_investigate ARQ task for this "
            "investigation. Useful when a prior run dead-lettered and "
            "the row needs to start fresh without creating a new "
            "investigation. Resets status to CREATED before submission."
        ),
    )
    @limiter.limit("10/minute")
    async def reenqueue_investigation(
        request: Request,
        investigation_id: str,
        body: _ReenqueueBody | None = None,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRInvestigationSummary]:
        from aila.api.deps import get_task_queue
        from aila.platform.contracts._common import utc_now

        from .db_models import VRInvestigationRecord
        from .workflow.task import run_vr_investigate

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
            # Always sync strategy_family to kind's default when the
            # operator re-enqueues with an explicit kind — covers both
            # 'change the kind' and 'fix a mismatch where the strategy
            # was stuck on the wrong default from earlier create-time
            # bug'. Without this, an investigation created with
            # kind=variant_hunt but strategy_family=discovery_research
            # (the pre-006047d default-fallback bug) couldn't be
            # repaired without a direct DB edit.
            if body and body.kind is not None:
                inv.kind = body.kind.value
                inv.strategy_family = _KIND_DEFAULT_STRATEGY[body.kind]
            inv.status = InvestigationStatus.CREATED.value
            inv.pause_reason = None
            inv.updated_at = utc_now()
            uow.session.add(inv)

            # Cancel any stale run_vr_investigate TaskRecord still in
            # queued/running/waiting for THIS investigation. Without
            # this, TaskQueue.submit() (SEC-07 dedup, queue.py L128)
            # returns the existing handle when input_hash matches —
            # and the matching hash is exactly (fn=run_vr_investigate,
            # kwargs={investigation_id: <id>}). When a previous worker
            # crashed leaving its TaskRecord in 'running' without a
            # live arq job, every re-enqueue silently no-op'd. Operator
            # sees status=created, clicks 'Start', nothing happens.

            stale_q = select(TaskRecord).where(
                TaskRecord.fn_path.like("%run_vr_investigate%"),
                TaskRecord.status.in_(["queued", "running", "waiting"]),
                TaskRecord.kwargs_json.like(f'%"{investigation_id}"%'),
            )
            stale_rows = (await uow.session.exec(stale_q)).all()
            for row in stale_rows:
                row.status = TaskStatus.CANCELLED.value
                uow.session.add(row)

            # Branch cleanup is handled by investigation_setup's
            # _spawn_persona_siblings_and_enqueue which now searches ALL
            # branches by persona (not just current primary's children),
            # reuses the best branch per persona, and abandons duplicates.
            # Also wipe __crashed__ cursors for this investigation so the
            # workflow engine starts fresh on next dispatch. Without this,
            # crashed cursors persist forever and re-enqueue fires a new
            # TaskRecord but the engine refuses to resume cleanly. I had
            # to manually DELETE 219 such orphan crashed cursors today.
            try:
                await uow.session.exec(  # type: ignore[call-arg]
                    sa_text(
                        "DELETE FROM workflow_state_cursor "
                        "WHERE current_state = '__crashed__' "
                        "AND run_id IN (SELECT id FROM taskrecord "
                        "WHERE kwargs_json LIKE :pat)"
                    ).bindparams(pat=f'%"{investigation_id}"%')
                )
            except (SQLAlchemyError, OSError, RuntimeError) as exc:
                logging.getLogger(__name__).warning(
                    "re-enqueue: cursor cleanup failed: %s", exc,
                    exc_info=True,
                )
            await uow.session.commit()
            await uow.session.refresh(inv)
        # (committed before submit so the next submit() sees a clean
        # dedup table — same UoW would race with the dedup_session
        # opened inside TaskQueue.submit.)

        task_queue = get_task_queue("vr", request)
        await task_queue.submit(
            track="vr",
            fn=run_vr_investigate,
            kwargs={"investigation_id": investigation_id},
            user_id=auth.user_id,
            group_id=auth.role,
            team_id=auth.team_id,
        )
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
        limit: int = Query(default=10000, ge=1, le=50000),
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
        "/investigations/{investigation_id}/report.pdf",
        summary=(
            "Enterprise-grade PDF report for a completed (or in-flight) "
            "investigation. Calls the writer agent for prose synthesis "
            "then renders via ReportLab. Returns application/pdf with "
            "Content-Disposition: attachment."
        ),
        response_class=Response,
        responses={
            200: {
                "description": "PDF report ready for download.",
                "content": {"application/pdf": {"schema": {"type": "string", "format": "binary"}}},
            },
        },
    )
    @limiter.limit("10/minute")
    async def export_investigation_report(
        request: Request,
        investigation_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> Response:
        del request

        from aila.modules.vr.reporting.pdf_report import render_investigation_pdf

        inv = await _load_investigation(investigation_id, auth)
        if inv is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation {investigation_id} not found.",
            )
        try:
            pdf_bytes = await render_investigation_pdf(investigation_id)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Report writer unavailable: {exc}",
            ) from exc

        safe_title = (inv.title or "investigation").replace(" ", "_")[:80]
        filename = f"AILA_VR_{safe_title}_{investigation_id[:8]}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Cache-Control": "no-store",
            },
        )

    @router.post(
        "/findings/{finding_id}/draft-poc",
        response_model=DataEnvelope[dict],
        summary=(
            "Trigger PocWriter to draft an exploit / PoC for this "
            "finding. Runs asynchronously via the VR worker; result "
            "lands on VRFindingRecord.poc_code when complete. Safe "
            "to call multiple times — each call overwrites the "
            "previous draft."
        ),
    )
    @limiter.limit("5/minute")
    async def trigger_poc_draft(
        request: Request,
        finding_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[dict]:
        del request

        from aila.modules.vr._task_queue import default_task_queue
        from aila.modules.vr.db_models import VRFindingRecord
        from aila.modules.vr.workflow.task import run_vr_draft_poc

        async with UnitOfWork() as uow:
            finding = (await uow.session.exec(
                _team_filter(
                    select(VRFindingRecord).where(VRFindingRecord.id == finding_id),
                    VRFindingRecord, auth,
                ),
            )).first()
        if finding is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Finding {finding_id} not found.",
            )
        task_queue = default_task_queue()
        handle = await task_queue.submit(
            track="vr",
            fn=run_vr_draft_poc,
            kwargs={
                "finding_id": finding_id,
                "investigation_id": finding.investigation_id_source or "",
            },
            user_id=auth.user_id,
            group_id="vr_poc_writer",
            team_id=auth.team_id,
        )
        return DataEnvelope(data={
            "finding_id": finding_id,
            "task_id": str(getattr(handle, "task_id", "")),
            "status": "queued",
        })

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
                    is_operator = row.sender_kind == SenderKind.OPERATOR.value
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
            branch_ids = [r.id for r in rows]
            cursors_by_run: dict[str, tuple[str | None, str | None]] = {}
            if branch_ids:
                cursor_rows = (await uow.session.exec(
                    select(
                        WorkflowStateCursor.run_id,
                        WorkflowStateCursor.current_state,
                        WorkflowStateCursor.archived_state,
                    ).where(WorkflowStateCursor.run_id.in_(branch_ids))
                )).all()
                for cr in cursor_rows:
                    run_id = cr[0] if hasattr(cr, "__getitem__") else cr.run_id
                    cur = cr[1] if hasattr(cr, "__getitem__") else cr.current_state
                    arc = cr[2] if hasattr(cr, "__getitem__") else cr.archived_state
                    cursors_by_run[str(run_id)] = (cur, arc)

        return DataEnvelope(data=[
            _branch_summary(
                r,
                cursor_state=cursors_by_run.get(r.id, (None, None))[0],
                cursor_archived_state=cursors_by_run.get(r.id, (None, None))[1],
            )
            for r in rows
        ])

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

    @router.post(
        "/investigations/{investigation_id}/outcomes/{outcome_id}/reviews",
        response_model=DataEnvelope[VROutcomeReviewSummary],
        status_code=status.HTTP_201_CREATED,
        summary=(
            "Submit a sibling review on a draft outcome. Quorum is "
            "evaluated after the upsert; when state flips to APPROVED "
            "the dispatcher is fired automatically and remaining active "
            "sibling branches are halted."
        ),
    )
    @limiter.limit("60/minute")
    async def create_outcome_review(
        request: Request,
        investigation_id: str,
        outcome_id: str,
        body: VROutcomeReviewCreate,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VROutcomeReviewSummary]:
        del request
        inv = await _load_investigation(investigation_id, auth)
        if inv is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation {investigation_id} not found.",
            )
        from .services.outcome_review import (
            OUTCOME_STATE_APPROVED,
            evaluate_quorum,
            upsert_review,
        )

        try:
            row = await upsert_review(
                outcome_id=outcome_id,
                reviewer_branch_id=body.reviewer_branch_id,
                vote=body.vote,
                comment=body.comment,
                suggested_edits=body.suggested_edits,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

        # Evaluate quorum after every review insert. When the state
        # flips to APPROVED, fire the dispatcher inline so the outcome
        # ships immediately rather than waiting for the next worker
        # poll. Best-effort: dispatch errors are logged but don't
        # roll back the review.
        try:
            quorum = await evaluate_quorum(outcome_id)
        except (OSError, TimeoutError, RuntimeError, ValueError):
            quorum = None

        if quorum is not None and quorum.new_state == OUTCOME_STATE_APPROVED:
            try:
                from aila.platform.services.factory import ServiceFactory

                from .agents.outcome_dispatcher import OutcomeDispatcher
                dispatcher = OutcomeDispatcher(
                    knowledge=ServiceFactory().knowledge,
                )
                await dispatcher.dispatch(outcome_id)
            except (OSError, TimeoutError, RuntimeError, ValueError):
                pass  # logged inside dispatcher

        import json as _json
        return DataEnvelope(data=VROutcomeReviewSummary(
            id=row.id,
            outcome_id=row.outcome_id,
            reviewer_branch_id=row.reviewer_branch_id,
            reviewer_persona=row.reviewer_persona,
            vote=row.vote,
            comment=row.comment,
            suggested_edits=_json.loads(row.suggested_edits_json or "{}"),
            created_at=row.created_at,
        ))

    @router.get(
        "/investigations/{investigation_id}/outcomes/{outcome_id}/reviews",
        response_model=DataEnvelope[list[VROutcomeReviewSummary]],
        summary=(
            "List sibling reviews for one outcome (most recent first). "
            "Vote counts are surfaced via the outcome summary itself; "
            "this endpoint returns the per-review detail including "
            "comments and suggested edits."
        ),
    )
    @limiter.limit("120/minute")
    async def list_outcome_reviews(
        request: Request,
        investigation_id: str,
        outcome_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[VROutcomeReviewSummary]]:
        del request
        inv = await _load_investigation(investigation_id, auth)
        if inv is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation {investigation_id} not found.",
            )
        import json as _json

        from .db_models import VRInvestigationOutcomeReviewRecord

        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                select(VRInvestigationOutcomeReviewRecord)
                .where(
                    VRInvestigationOutcomeReviewRecord.outcome_id == outcome_id,
                )
                .order_by(VRInvestigationOutcomeReviewRecord.created_at.desc())
            )).all()

        return DataEnvelope(data=[
            VROutcomeReviewSummary(
                id=r.id,
                outcome_id=r.outcome_id,
                reviewer_branch_id=r.reviewer_branch_id,
                reviewer_persona=r.reviewer_persona,
                vote=r.vote,
                comment=r.comment,
                suggested_edits=_json.loads(r.suggested_edits_json or "{}"),
                created_at=r.created_at,
            )
            for r in rows
        ])

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
        resolved_branches: dict[str, list[str]] = {}
        claims: dict[str, dict[str, str]] = {}
        rejection_reasons: dict[str, str] = {}
        resolution_notes: dict[str, str] = {}

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
            for h in state.get("resolved", []) or []:
                hid = h.get("id")
                if not hid:
                    continue
                resolved_branches.setdefault(hid, []).append(b.id)
                claims.setdefault(hid, {
                    "claim": h.get("claim", ""),
                    "why_plausible": "",
                    "kill_criterion": "",
                })
                if h.get("note"):
                    resolution_notes.setdefault(hid, h["note"])

        all_ids = set(live_branches) | set(rejected_branches) | set(resolved_branches)
        items: list[HypothesisProjection] = []
        for hid in sorted(all_ids):
            live = live_branches.get(hid, [])
            rejected = rejected_branches.get(hid, [])
            resolved = resolved_branches.get(hid, [])
            # State precedence:
            #   live + (rejected or resolved on other branch) → MIXED
            #   any rejected and nothing else → REJECTED
            #   any resolved and nothing else → RESOLVED
            #   live only → LIVE
            #   rejected + resolved (no live) → REJECTED (more specific)
            distinct_states = (
                (1 if live else 0)
                + (1 if rejected else 0)
                + (1 if resolved else 0)
            )
            if distinct_states >= 2:
                hstate = HypothesisState.MIXED
            elif rejected:
                hstate = HypothesisState.REJECTED
            elif resolved:
                hstate = HypothesisState.RESOLVED
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
                resolution_note=resolution_notes.get(hid),
                live_in_branches=live,
                rejected_in_branches=rejected,
                resolved_in_branches=resolved,
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
                label=str(o.outcome_kind),
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
        del request
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
            team_id=auth.team_id,
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
        del request
        from aila.modules.vr.services import PatternStore
        from aila.platform.services.knowledge import KnowledgeService

        store = PatternStore(knowledge=KnowledgeService())
        summary = await store.get(pattern_id, team_id=auth.team_id)
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
        del request
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
        del request
        from aila.modules.vr.disclosure import DisclosureService

        svc = DisclosureService()
        items, total = await svc.list(
            finding_id=finding_id,
            workspace_id=workspace_id,
            track_id=track_id,
            status=submission_status,
            offset=offset,
            team_id=auth.team_id,
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
        del request
        from aila.modules.vr.disclosure import DisclosureService

        from .db_models import VRDisclosureSubmissionRecord

        await _team_owned_or_404(
            submission_id, VRDisclosureSubmissionRecord, auth,
            f"Disclosure submission {submission_id} not found.",
        )
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
        del request
        from aila.modules.vr.disclosure import (
            DisclosureService,
            DisclosureServiceError,
        )

        from .db_models import VRDisclosureSubmissionRecord

        await _team_owned_or_404(
            submission_id, VRDisclosureSubmissionRecord, auth,
            f"Disclosure submission {submission_id} not found.",
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
        del request
        from .db_models import VRDisclosureSubmissionRecord

        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _team_filter(
                    select(VRDisclosureSubmissionRecord).where(
                        VRDisclosureSubmissionRecord.id == submission_id,
                    ),
                    VRDisclosureSubmissionRecord, auth,
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
        del request
        from aila.modules.vr.disclosure import (
            DisclosureService,
            DisclosureServiceError,
        )

        from .db_models import VRDisclosureSubmissionRecord

        await _team_owned_or_404(
            submission_id, VRDisclosureSubmissionRecord, auth,
            f"Disclosure submission {submission_id} not found.",
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
        del request
        import json as _json

        from .db_models import VRDisclosureSubmissionRecord
        from .disclosure import DisclosureService

        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _team_filter(
                    select(VRDisclosureSubmissionRecord).where(
                        VRDisclosureSubmissionRecord.id == submission_id,
                    ),
                    VRDisclosureSubmissionRecord, auth,
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
        del request
        import json as _json

        from .db_models import (
            VRDisclosureSubmissionRecord,
            VRFindingRecord,
        )
        from .disclosure import DisclosureService

        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _team_filter(
                    select(VRDisclosureSubmissionRecord).where(
                        VRDisclosureSubmissionRecord.id == submission_id,
                    ),
                    VRDisclosureSubmissionRecord, auth,
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
        del request
        from aila.modules.vr.services import FuzzCampaignService

        svc = FuzzCampaignService()
        items, total = await svc.list_campaigns(
            target_id=target_id,
            workspace_id=workspace_id,
            status=campaign_status,
            offset=offset,
            limit=limit,
            team_id=auth.team_id,
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
        del request
        from aila.modules.vr.services import FuzzCampaignService

        from .db_models import VRFuzzCampaignRecord

        await _team_owned_or_404(
            campaign_id, VRFuzzCampaignRecord, auth,
            f"Fuzz campaign {campaign_id} not found.",
        )
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
        del request
        from aila.modules.vr.services import FuzzCampaignService, FuzzServiceError

        from .db_models import VRFuzzCampaignRecord

        await _team_owned_or_404(
            campaign_id, VRFuzzCampaignRecord, auth,
            f"Fuzz campaign {campaign_id} not found.",
        )
        svc = FuzzCampaignService()
        try:
            summary = await svc.patch_campaign(campaign_id, body)
        except FuzzServiceError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=str(exc),
            ) from exc
        return DataEnvelope(data=summary)


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
        del request
        from .db_models import VRFuzzCampaignRecord, VRFuzzCrashRecord

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
            crashes = (await uow.session.exec(
                select(VRFuzzCrashRecord).where(VRFuzzCrashRecord.campaign_id == campaign_id),
            )).all()
            for c in crashes:
                await uow.session.delete(c)
            await uow.session.delete(row)
            await uow.session.commit()

        return Response(status_code=status.HTTP_204_NO_CONTENT)

    # ── Fuzz campaign proposals (operator-in-the-loop) ─────────────

    @router.get(
        "/fuzz/proposals",
        response_model=DataEnvelope[list[VRFuzzCampaignProposalSummary]],
        summary=(
            "List fuzz campaign proposals emitted by reasoning agents. "
            "Filterable by investigation_id, target_id, or status."
        ),
    )
    @limiter.limit("120/minute")
    async def list_fuzz_proposals(
        request: Request,
        investigation_id: str | None = Query(default=None),
        target_id: str | None = Query(default=None),
        status_filter: FuzzProposalStatus | None = Query(
            default=None, alias="status",
        ),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=200),
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[VRFuzzCampaignProposalSummary]]:
        del request
        from .db_models import VRFuzzCampaignProposalRecord

        async with UnitOfWork() as uow:
            stmt = _team_filter(
                select(VRFuzzCampaignProposalRecord),
                VRFuzzCampaignProposalRecord, auth,
            )
            count_stmt = _team_filter(
                select(sa_func.count()).select_from(
                    VRFuzzCampaignProposalRecord,
                ),
                VRFuzzCampaignProposalRecord, auth,
            )
            if investigation_id:
                stmt = stmt.where(
                    VRFuzzCampaignProposalRecord.investigation_id
                    == investigation_id,
                )
                count_stmt = count_stmt.where(
                    VRFuzzCampaignProposalRecord.investigation_id
                    == investigation_id,
                )
            if target_id:
                stmt = stmt.where(
                    VRFuzzCampaignProposalRecord.target_id == target_id,
                )
                count_stmt = count_stmt.where(
                    VRFuzzCampaignProposalRecord.target_id == target_id,
                )
            if status_filter is not None:
                stmt = stmt.where(
                    VRFuzzCampaignProposalRecord.status
                    == status_filter.value,
                )
                count_stmt = count_stmt.where(
                    VRFuzzCampaignProposalRecord.status
                    == status_filter.value,
                )
            total = (await uow.session.exec(count_stmt)).one()
            rows = (await uow.session.exec(
                stmt.order_by(VRFuzzCampaignProposalRecord.created_at.desc())
                .offset(offset).limit(limit)
            )).all()

        items = [_fuzz_proposal_summary(r) for r in rows]
        return DataEnvelope(
            data=items,
            meta=PaginatedMeta(
                total=int(total), offset=offset, limit=limit,
            ).model_dump(),
        )

    @router.get(
        "/fuzz/proposals/{proposal_id}",
        response_model=DataEnvelope[VRFuzzCampaignProposalSummary],
        summary="Get one fuzz campaign proposal by id.",
    )
    @limiter.limit("120/minute")
    async def get_fuzz_proposal(
        request: Request,
        proposal_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRFuzzCampaignProposalSummary]:
        del request
        from .db_models import VRFuzzCampaignProposalRecord

        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _team_filter(
                    select(VRFuzzCampaignProposalRecord).where(
                        VRFuzzCampaignProposalRecord.id == proposal_id,
                    ),
                    VRFuzzCampaignProposalRecord, auth,
                ),
            )).first()
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Fuzz proposal {proposal_id} not found.",
                )
        return DataEnvelope(data=_fuzz_proposal_summary(row))


    @router.post(
        "/fuzz/proposals/{proposal_id}/accept",
        response_model=DataEnvelope[_ProposalAcceptResponse],
        summary=(
            "Accept a pending fuzz proposal. ProposalPreparer SSHes "
            "the workstation, writes the harness + seeds + dict, runs "
            "the build, creates a campaign row, and (default) auto-"
            "launches the fuzzer. The operator can override any of "
            "the resolved defaults in the body."
        ),
    )
    @limiter.limit("10/minute")
    async def accept_fuzz_proposal(
        request: Request,
        proposal_id: str,
        body: FuzzProposalDecideAccept,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[_ProposalAcceptResponse]:
        del request
        from aila.modules.vr.services.proposal_preparer import (
            ProposalPrepareError,
            ProposalPreparer,
        )

        preparer = ProposalPreparer()
        try:
            result = await preparer.accept(
                proposal_id, body,
                team_id=auth.team_id, user_id=auth.user_id,
            )
        except ProposalPrepareError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        return DataEnvelope(data=_ProposalAcceptResponse(
            proposal_id=result.proposal_id,
            campaign_id=result.campaign_id,
            workdir=result.workdir,
            harness_path=result.harness_path,
            seeds_written=result.seeds_written,
            dictionary_written=result.dictionary_written,
            auto_launched=result.auto_launched,
            build_log=result.build_log,
        ))

    @router.post(
        "/fuzz/proposals/{proposal_id}/reject",
        response_model=DataEnvelope[VRFuzzCampaignProposalSummary],
        summary="Reject a pending fuzz proposal — reason recorded.",
    )
    @limiter.limit("30/minute")
    async def reject_fuzz_proposal(
        request: Request,
        proposal_id: str,
        body: FuzzProposalDecideReject,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[VRFuzzCampaignProposalSummary]:
        del request
        from aila.modules.vr.services.proposal_preparer import (
            ProposalPrepareError,
            ProposalPreparer,
        )

        preparer = ProposalPreparer()
        try:
            row = await preparer.reject(
                proposal_id,
                body.decision_reason,
                team_id=auth.team_id,
                user_id=auth.user_id,
            )
        except ProposalPrepareError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        return DataEnvelope(data=_fuzz_proposal_summary(row))


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
        del request
        from aila.modules.vr.services import FuzzCampaignService

        svc = FuzzCampaignService()
        items, total = await svc.list_crashes(
            campaign_id=campaign_id,
            verdict=verdict,
            severity=severity,
            offset=offset,
            limit=limit,
            team_id=auth.team_id,
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
        del request
        from aila.modules.vr.services import FuzzCampaignService

        from .db_models import VRFuzzCrashRecord

        await _team_owned_or_404(
            crash_id, VRFuzzCrashRecord, auth,
            f"Fuzz crash {crash_id} not found.",
        )
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
                _team_filter(
                    select(VRFuzzCrashRecord).where(
                        VRFuzzCrashRecord.id == crash_id,
                    ),
                    VRFuzzCrashRecord, auth,
                ),
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
        limit: int = Query(default=10000, ge=1, le=50000),
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[FuzzTelemetryPoint]]:
        del request
        from .db_models import VRFuzzCampaignRecord, VRFuzzTelemetryRecord


        await _team_owned_or_404(
            campaign_id, VRFuzzCampaignRecord, auth,
            f"Fuzz campaign {campaign_id} not found.",
        )
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
        del request
        from uuid import uuid4 as _uuid4

        from .db_models import VRFuzzCampaignRecord, VRFuzzTelemetryRecord

        async with UnitOfWork() as uow:
            campaign = (await uow.session.exec(
                _team_filter(
                    select(VRFuzzCampaignRecord).where(
                        VRFuzzCampaignRecord.id == campaign_id,
                    ),
                    VRFuzzCampaignRecord, auth,
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
        del request
        from aila.modules.vr.services import MultiTargetService

        inv = await _load_investigation(investigation_id, auth)
        if inv is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation {investigation_id} not found.",
            )
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
        del request
        from aila.modules.vr.services import (
            MultiTargetService,
            MultiTargetServiceError,
        )

        inv = await _load_investigation(investigation_id, auth)
        if inv is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation {investigation_id} not found.",
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
        del request
        from aila.modules.vr.agents.branch_manager import (
            BranchManager,
            BranchManagerError,
        )

        inv = await _load_investigation(investigation_id, auth)
        if inv is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation {investigation_id} not found.",
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
        del request
        from aila.modules.vr.agents.branch_manager import BranchManager

        inv = await _load_investigation(investigation_id, auth)
        if inv is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation {investigation_id} not found.",
            )
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
        del request
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
        del request
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
        del request
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
        del request
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
        del request
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
        del request
        from .db_models import VRMcpCallLogRecord

        async with UnitOfWork() as uow:
            stmt = select(VRMcpCallLogRecord)
            stmt = _team_filter(stmt, VRMcpCallLogRecord, auth)
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
