"""Outcome dispatcher (M3.R-8).

Routes accepted VRInvestigationOutcomeRecord rows to their downstream
artifacts. v0.3 v1 ships handlers for the 3 outcome kinds whose
downstream consumers already exist in the codebase:

  AUDIT_MEMO          → KnowledgeService.store with namespace
                        ``vr.audit_memo.workspace.<workspace_id>``
                        (platform pgvector + HNSW + FTS infra per D-38)
  DIRECT_FINDING      → vr_findings row creation (linking to project +
                        target). Investigations without a linked project
                        skip this dispatch and emit a SKIPPED status
                        with a clear reason.
  VARIANT_HUNT_ORDER  → spawn child VRInvestigationRecord with
                        parent_investigation_id set, kind=variant_hunt,
                        and enqueue the run_vr_investigate task

The other 8 outcome kinds (AssessmentReport, StrategyDescriptor,
ProfileSpecDraft, ConfigDelta, PatchAssessmentReport, CrashTriageReport,
CampaignLaunch, SubInvestigation) currently have no downstream consumer
built. They get dispatch_status=SKIPPED with reason
'no_downstream_consumer_yet' — these handlers land per-kind as the
relevant downstream subsystems ship (CampaignLaunch needs the v0.3
fuzzing module; SubInvestigation needs M3.R-5 branching).
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from sqlmodel import select as _select

from aila.modules.vr.contracts import OutcomeDispatchStatus, OutcomeKind
from aila.modules.vr.contracts.investigation import (
    InvestigationKind,
    InvestigationStatus,
)
from aila.modules.vr.db_models import (
    VRFindingRecord,
    VRInvestigationBranchRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
    VRTargetRecord,
)
from aila.platform.contracts._common import utc_now
from aila.platform.services.knowledge import KnowledgeService
from aila.platform.uow import UnitOfWork

__all__ = [
    "OutcomeDispatchResult",
    "OutcomeDispatcher",
]

_log = logging.getLogger(__name__)


@dataclass(slots=True)
class OutcomeDispatchResult:
    """Result of dispatching one outcome."""

    outcome_id: str
    outcome_kind: OutcomeKind
    dispatch_status: OutcomeDispatchStatus
    dispatch_target: str | None
    reason: str = ""


# Outcome kinds whose downstream consumers don't yet exist in v0.3 v1.
# Listed explicitly so the dispatcher emits SKIPPED with a real reason
# rather than silently doing nothing.
_NOT_YET_DISPATCHABLE: dict[OutcomeKind, str] = {
    OutcomeKind.ASSESSMENT_REPORT: "assessment_reports_are_terminal_no_downstream",
    OutcomeKind.STRATEGY_DESCRIPTOR: "no_strategy_registry_consumer_yet",
    OutcomeKind.PROFILE_SPEC_DRAFT: "no_profile_registry_consumer_yet",
    OutcomeKind.CONFIG_DELTA: "no_config_consumer_yet",
    OutcomeKind.PATCH_ASSESSMENT_REPORT: "no_nday_workflow_consumer_yet",
    OutcomeKind.CRASH_TRIAGE_REPORT: "no_crash_triage_consumer_yet",
    OutcomeKind.CAMPAIGN_LAUNCH: "no_fuzz_module_consumer_yet",
    OutcomeKind.SUB_INVESTIGATION: "needs_M3R5_branching_first",
}


class OutcomeDispatcher:
    """Routes accepted outcomes to their downstream artifacts.

    Construction takes only the KnowledgeService — the other handlers
    use direct DB writes through UnitOfWork plus the platform task
    queue for child-investigation spawning. Tests can inject a fake
    KnowledgeService with the same ``store(namespace, content, ...)``
    coroutine signature.
    """

    def __init__(self, knowledge: KnowledgeService | Any) -> None:
        self._knowledge = knowledge

    async def dispatch(self, outcome_id: str) -> OutcomeDispatchResult:
        """Dispatch one outcome and update its dispatch_status."""
        async with UnitOfWork() as uow:
            outcome = (await uow.session.exec(
                _select(VRInvestigationOutcomeRecord).where(
                    VRInvestigationOutcomeRecord.id == outcome_id,
                )
            )).first()
            if outcome is None:
                raise ValueError(f"outcome {outcome_id} not found")
            outcome_kind = OutcomeKind(outcome.outcome_kind)
            payload = json.loads(outcome.payload_json or "{}")
            investigation_id = outcome.investigation_id

        try:
            if outcome_kind == OutcomeKind.AUDIT_MEMO:
                result = await self._dispatch_audit_memo(
                    outcome_id, investigation_id, payload, outcome,
                )
            elif outcome_kind == OutcomeKind.DIRECT_FINDING:
                result = await self._dispatch_direct_finding(
                    outcome_id, investigation_id, payload,
                )
            elif outcome_kind == OutcomeKind.VARIANT_HUNT_ORDER:
                result = await self._dispatch_variant_hunt_order(
                    outcome_id, investigation_id, payload,
                )
            elif outcome_kind in _NOT_YET_DISPATCHABLE:
                result = OutcomeDispatchResult(
                    outcome_id=outcome_id,
                    outcome_kind=outcome_kind,
                    dispatch_status=OutcomeDispatchStatus.SKIPPED,
                    dispatch_target=None,
                    reason=_NOT_YET_DISPATCHABLE[outcome_kind],
                )
            else:
                result = OutcomeDispatchResult(
                    outcome_id=outcome_id,
                    outcome_kind=outcome_kind,
                    dispatch_status=OutcomeDispatchStatus.SKIPPED,
                    dispatch_target=None,
                    reason=f"unknown_outcome_kind:{outcome_kind.value}",
                )
        except (OSError, TimeoutError, RuntimeError, ValueError) as exc:
            _log.warning(
                "outcome_dispatcher FAILED outcome_id=%s kind=%s err=%s",
                outcome_id, outcome_kind.value, exc,
            )
            result = OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=outcome_kind,
                dispatch_status=OutcomeDispatchStatus.FAILED,
                dispatch_target=None,
                reason=f"{type(exc).__name__}: {exc}",
            )

        await self._update_outcome_status(result)
        _log.info(
            "outcome_dispatcher RESULT outcome_id=%s kind=%s status=%s target=%s reason=%s",
            result.outcome_id, result.outcome_kind.value,
            result.dispatch_status.value, result.dispatch_target, result.reason,
        )
        return result

    async def _dispatch_audit_memo(
        self,
        outcome_id: str,
        investigation_id: str,
        payload: dict[str, Any],
        outcome: VRInvestigationOutcomeRecord,
    ) -> OutcomeDispatchResult:
        """AUDIT_MEMO → KnowledgeService.store with workspace-scoped namespace.

        Pulls workspace_id from the target row (target.workspace_id).
        Investigations whose target has no workspace are not currently
        produceable (workspace_id is NOT NULL on vr_targets), so this
        path always finds one.
        """
        target_row, _ = await self._load_target_for_investigation(investigation_id)

        claim = str(payload.get("claim") or payload.get("answer") or "").strip()
        if not claim:
            return OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=OutcomeKind.AUDIT_MEMO,
                dispatch_status=OutcomeDispatchStatus.FAILED,
                dispatch_target=None,
                reason="empty_claim",
            )

        target_signature = str(
            payload.get("target_signature")
            or _compute_target_signature(target_row.id, payload),
        )
        region_descriptor = str(payload.get("region_descriptor") or "")
        scope = str(payload.get("scope") or "workspace")
        workspace_id = target_row.workspace_id

        namespace = _audit_memo_namespace(scope, workspace_id, target_row.team_id)
        content = (
            f"{region_descriptor}\n\n{claim}" if region_descriptor else claim
        )

        store_result = await self._knowledge.store(
            namespace=namespace,
            content=content,
            metadata={
                "investigation_id": investigation_id,
                "target_id": target_row.id,
                "workspace_id": workspace_id,
                "target_signature": target_signature,
                "region_descriptor": region_descriptor,
                "evidence_refs": payload.get("evidence_refs") or [],
                "confidence": outcome.confidence,
                "scope": scope,
                "pivot_history": payload.get("pivot_history") or [],
                "outcome_id": outcome_id,
            },
            dedup_key=target_signature,
        )
        entry_id = store_result.get("entry_id")

        return OutcomeDispatchResult(
            outcome_id=outcome_id,
            outcome_kind=OutcomeKind.AUDIT_MEMO,
            dispatch_status=OutcomeDispatchStatus.DISPATCHED,
            dispatch_target=f"knowledge_entry:{entry_id}",
            reason=f"namespace={namespace} operation={store_result.get('operation')}",
        )

    async def _dispatch_direct_finding(
        self,
        outcome_id: str,
        investigation_id: str,
        payload: dict[str, Any],
    ) -> OutcomeDispatchResult:
        """DIRECT_FINDING → vr_findings row.

        Investigations without project_id skip this dispatch (vr_findings
        requires project_id under current schema). Operator can manually
        promote later by linking the investigation to a project, OR a
        future commit makes project_id nullable for standalone findings.
        """
        target_row, inv = await self._load_target_for_investigation(investigation_id)

        if not inv.project_id:
            return OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=OutcomeKind.DIRECT_FINDING,
                dispatch_status=OutcomeDispatchStatus.SKIPPED,
                dispatch_target=None,
                reason="investigation_has_no_project_id",
            )

        crash_type = payload.get("crash_type")
        vulnerable_function = payload.get("vulnerable_function")
        root_cause = payload.get("answer") or payload.get("reasoning") or ""
        crash_signature = payload.get("crash_signature")
        poc_code = payload.get("poc_code")

        async with UnitOfWork() as uow:
            finding = VRFindingRecord(
                project_id=inv.project_id,
                target_id=target_row.id,
                team_id=inv.team_id,
                crash_type=crash_type[:64] if isinstance(crash_type, str) else None,
                crash_signature=(
                    crash_signature[:128] if isinstance(crash_signature, str) else None
                ),
                root_cause=str(root_cause),
                vulnerable_function=(
                    vulnerable_function[:255]
                    if isinstance(vulnerable_function, str) else None
                ),
                poc_code=str(poc_code) if isinstance(poc_code, str) else None,
                poc_language=(
                    str(payload.get("poc_language", "python"))[:32]
                    if poc_code else None
                ),
                evidence_refs_json=json.dumps(payload.get("evidence_refs") or []),
            )
            uow.session.add(finding)
            await uow.session.commit()
            await uow.session.refresh(finding)
            finding_id = finding.id

            inv_row = (await uow.session.exec(
                _select(VRInvestigationRecord).where(
                    VRInvestigationRecord.id == investigation_id,
                )
            )).first()
            if inv_row is not None:
                ids = json.loads(inv_row.linked_finding_ids_json or "[]")
                if finding_id not in ids:
                    ids.append(finding_id)
                inv_row.linked_finding_ids_json = json.dumps(ids)
                inv_row.updated_at = utc_now()
                uow.session.add(inv_row)
                await uow.session.commit()

        return OutcomeDispatchResult(
            outcome_id=outcome_id,
            outcome_kind=OutcomeKind.DIRECT_FINDING,
            dispatch_status=OutcomeDispatchStatus.DISPATCHED,
            dispatch_target=f"vr_finding:{finding_id}",
            reason=f"crash_type={crash_type} fn={vulnerable_function}",
        )

    async def _dispatch_variant_hunt_order(
        self,
        outcome_id: str,
        investigation_id: str,
        payload: dict[str, Any],
    ) -> OutcomeDispatchResult:
        """VARIANT_HUNT_ORDER → spawn child investigation.

        The child investigation inherits the parent's target by default
        but can override via payload.target_id. Default budget is 50%
        of parent's budget per D-43 GA-28.
        """
        target_row, parent = await self._load_target_for_investigation(investigation_id)

        child_target_id = str(payload.get("target_id") or target_row.id)
        if child_target_id != target_row.id:
            async with UnitOfWork() as uow:
                child_target = (await uow.session.exec(
                    _select(VRTargetRecord).where(VRTargetRecord.id == child_target_id)
                )).first()
                if child_target is None:
                    return OutcomeDispatchResult(
                        outcome_id=outcome_id,
                        outcome_kind=OutcomeKind.VARIANT_HUNT_ORDER,
                        dispatch_status=OutcomeDispatchStatus.FAILED,
                        dispatch_target=None,
                        reason=f"override_target_id_not_found:{child_target_id}",
                    )

        child_title = str(payload.get("title") or f"Variant hunt: {parent.title}")
        child_question = str(
            payload.get("question") or payload.get("hypothesis")
            or f"Find variants of the issue identified in {parent.title}",
        )
        child_budget = float(
            payload.get("cost_budget_usd") or (parent.cost_budget_usd * 0.5),
        )

        async with UnitOfWork() as uow:
            child = VRInvestigationRecord(
                target_id=child_target_id,
                team_id=parent.team_id,
                parent_investigation_id=parent.id,
                kind=InvestigationKind.VARIANT_HUNT.value,
                title=child_title[:255],
                initial_question=child_question,
                status=InvestigationStatus.CREATED.value,
                auto_pilot=parent.auto_pilot,
                strategy_family="vulnerability_research.variant_hunt",
                cost_budget_usd=child_budget,
            )
            uow.session.add(child)
            await uow.session.flush()

            primary_branch = VRInvestigationBranchRecord(
                investigation_id=child.id,
                status="active",
                fork_reason="primary",
            )
            uow.session.add(primary_branch)
            await uow.session.commit()
            await uow.session.refresh(child)
            child_id = child.id

        return OutcomeDispatchResult(
            outcome_id=outcome_id,
            outcome_kind=OutcomeKind.VARIANT_HUNT_ORDER,
            dispatch_status=OutcomeDispatchStatus.DISPATCHED,
            dispatch_target=f"vr_investigation:{child_id}",
            reason=f"target_id={child_target_id} budget=${child_budget:.2f}",
        )

    async def _load_target_for_investigation(
        self, investigation_id: str,
    ) -> tuple[VRTargetRecord, VRInvestigationRecord]:
        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                _select(VRInvestigationRecord).where(
                    VRInvestigationRecord.id == investigation_id,
                )
            )).first()
            if inv is None:
                raise ValueError(f"investigation {investigation_id} not found")
            target = (await uow.session.exec(
                _select(VRTargetRecord).where(VRTargetRecord.id == inv.target_id)
            )).first()
            if target is None:
                raise ValueError(
                    f"target {inv.target_id} for investigation {investigation_id} not found",
                )
            return target, inv

    async def _update_outcome_status(self, result: OutcomeDispatchResult) -> None:
        async with UnitOfWork() as uow:
            outcome = (await uow.session.exec(
                _select(VRInvestigationOutcomeRecord).where(
                    VRInvestigationOutcomeRecord.id == result.outcome_id,
                )
            )).first()
            if outcome is None:
                return
            outcome.dispatch_status = result.dispatch_status.value
            outcome.dispatch_target = result.dispatch_target
            uow.session.add(outcome)
            await uow.commit()


def _audit_memo_namespace(
    scope: str,
    workspace_id: str | None,
    team_id: str | None,
) -> str:
    """Build the KnowledgeService namespace per the D-38 / M3.R-1 scope ladder."""
    scope_norm = scope.lower()
    if scope_norm == "global":
        return "vr.audit_memo.global"
    if scope_norm == "team" and team_id:
        return f"vr.audit_memo.team.{team_id}"
    if scope_norm == "workspace" and workspace_id:
        return f"vr.audit_memo.workspace.{workspace_id}"
    if workspace_id:
        return f"vr.audit_memo.workspace.{workspace_id}"
    return "vr.audit_memo.global"


def _compute_target_signature(target_id: str, payload: dict[str, Any]) -> str:
    """Default target_signature when the engine didn't supply one.

    SHA256 over (target_id + region_descriptor) keeps it deterministic
    so re-running the same audit hits dedup_key.
    """
    region = str(payload.get("region_descriptor") or "")
    raw = f"{target_id}|{region}".encode()
    if not region:
        # No region descriptor — fall back to a random sig so multiple
        # audit memos against the same target don't dedup over each other.
        return f"{target_id}|{uuid4()}"
    return hashlib.sha256(raw).hexdigest()
