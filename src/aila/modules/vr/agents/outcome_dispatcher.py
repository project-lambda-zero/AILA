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
import re
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from sqlmodel import select as _select

from aila.modules.vr._task_queue import (
    default_task_queue as _build_default_task_queue,
)
from aila.modules.vr._task_queue import (
    enqueue_vr_nday,
)
from aila.modules.vr.contracts import OutcomeDispatchStatus, OutcomeKind
from aila.modules.vr.contracts.investigation import (
    InvestigationKind,
    InvestigationStatus,
)
from aila.modules.vr.db_models import (
    VRFindingRecord,
    VRFuzzCampaignProposalRecord,
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
    "OutcomeDispatcherError",
]

_log = logging.getLogger(__name__)


# Accepted ways for an agent to declare it has exhausted the variant
# search on a kind=variant_hunt investigation. Matches "VARIANT DEAD",
# "VARIANT IS DEAD", "DEAD VARIANT", "NO VARIANT EXISTS/FOUND",
# "VARIANT NOT FOUND", "VARIANT ABSENT", "NO (NEW|FURTHER) VARIANT(S)",
# "NO ADJACENT VARIANT(S)". Checked against the first 400 chars of the
# answer (upper-cased). Without this broad matching the gate forced
# the agent into a strict literal prefix and rejected semantically
# equivalent declarations, triggering an infinite re-enqueue loop.
_VARIANT_EXHAUSTION_PATTERN = re.compile(
    r"\b("
    r"NO\s+(?:FURTHER|NEW|ADJACENT|REMAINING|OTHER)\s+VARIANTS?"
    r"|NO\s+VARIANT\s+(?:EXISTS?|FOUND|REMAINS?|CANDIDATES?)"
    r"|VARIANT\s+(?:IS\s+)?DEAD"
    r"|DEAD\s+VARIANT"
    r"|VARIANT\s+(?:NOT\s+FOUND|ABSENT|EXHAUSTED)"
    r"|VARIANT\s+HUNT\s+(?:EXHAUSTED|COMPLETE|CONCLUDED)"
    r"|EXHAUSTIVE\s+(?:NEGATIVE|SEARCH)"
    r")\b"
)


class OutcomeDispatcherError(Exception):
    """Raised on fatal dispatcher failures (NULL state, unknown state,
    handler exceptions). Surfacing rather than silently SKIPPING gives
    the caller a chance to record FAILED + retry, instead of marking
    the outcome dispatched-with-empty-result.
    """


# fix §237 — variant-hunt fork-time guards. MAX_VARIANT_DEPTH bounds
# the recursion chain so a runaway agent can't fork variants of variants
# of variants forever. VARIANT_MIN_BUDGET_USD prevents spawning a child
# whose $-budget can't pay for even a single round of reasoning.
MAX_VARIANT_DEPTH = 5
VARIANT_MIN_BUDGET_USD = 5.0

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
def _str_or_none(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return s or None




def _canonical_descriptor_key(descriptor: dict[str, Any] | None) -> str:
    """Canonical key for fuzz campaign proposal descriptor (fix §263).

    Old code computed the key from a 3-field fallback chain
    (``harness or function or function_name``) inline at both the
    read site (matching old rows) and the write site (new row). Any
    drift between the two formulas — case, whitespace, key choice —
    silently broke the supersede match. Single normalization function
    so both sides land on the same string.

    Order of preference matches the original code: explicit harness
    name > function symbol > legacy ``function_name``. Whitespace
    stripped and lower-cased so cosmetic differences don't break
    supersede.
    """
    if not isinstance(descriptor, dict):
        return ""
    for key in ("harness", "function", "function_name"):
        raw = descriptor.get(key)
        if isinstance(raw, str):
            value = raw.strip().lower()
            if value:
                return value
    return ""


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None



_NOT_YET_DISPATCHABLE: dict[OutcomeKind, str] = {
    OutcomeKind.ASSESSMENT_REPORT: "assessment_reports_are_terminal_no_downstream",
    OutcomeKind.STRATEGY_DESCRIPTOR: "no_strategy_registry_consumer_yet",
    OutcomeKind.CONFIG_DELTA: "no_config_consumer_yet",
    OutcomeKind.CRASH_TRIAGE_REPORT: "no_crash_triage_consumer_yet",
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

    def __init__(
        self,
        knowledge: KnowledgeService | Any,
        task_queue_factory: Any | None = None,
    ) -> None:
        self._knowledge = knowledge
        # Callable returning a TaskQueue-shaped object with
        # ``submit(track, fn, kwargs, user_id, group_id, team_id)``.
        # Default: build a platform TaskQueue lazily from ConfigRegistry.
        # Tests inject their own callable returning a fake.
        self._task_queue_factory: Any = (
            task_queue_factory or _build_default_task_queue
        )

    async def dispatch(self, outcome_id: str) -> OutcomeDispatchResult:
        """Dispatch one outcome and update its dispatch_status.

        Refuses any outcome whose ``state`` is not ``'approved'``:
        draft outcomes are still waiting on sibling review; rejected
        outcomes were vetoed and must not ship; dispatched outcomes
        already shipped (re-dispatch is a no-op). The state machine
        lives in ``aila.modules.vr.services.outcome_review``.
        """
        from aila.modules.vr.services.outcome_review import (  # noqa: PLC0415
            OUTCOME_STATE_APPROVED,
            OUTCOME_STATE_DISPATCHED,
            OUTCOME_STATE_DRAFT,
            OUTCOME_STATE_REJECTED,
        )

        async with UnitOfWork() as uow:
            outcome = (await uow.session.exec(
                _select(VRInvestigationOutcomeRecord).where(
                    VRInvestigationOutcomeRecord.id == outcome_id,
                )
            )).first()
            if outcome is None:
                raise ValueError(f"outcome {outcome_id} not found")
            if outcome.state is None:
                # fix §182 — legacy NULL state masked the bug where a row
                # skipped the draft→approved→dispatched lifecycle entirely.
                # Treat as a hard error so the operator sees it instead of
                # the row silently being marked "already_dispatched".
                raise OutcomeDispatcherError(
                    f"outcome.state is NULL outcome_id={outcome_id}",
                )
            state = outcome.state
            outcome_kind = OutcomeKind(outcome.outcome_kind)
            payload = json.loads(outcome.payload_json or "{}")
            investigation_id = outcome.investigation_id

        if state == OUTCOME_STATE_DRAFT:
            _log.info(
                "outcome_dispatcher SKIP_DRAFT outcome_id=%s kind=%s "
                "(awaiting sibling quorum)",
                outcome_id, outcome_kind.value,
            )
            return OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=outcome_kind,
                dispatch_status=OutcomeDispatchStatus.SKIPPED,
                dispatch_target=None,
                reason="draft_awaiting_sibling_quorum",
            )
        if state == OUTCOME_STATE_REJECTED:
            _log.info(
                "outcome_dispatcher SKIP_REJECTED outcome_id=%s kind=%s",
                outcome_id, outcome_kind.value,
            )
            return OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=outcome_kind,
                dispatch_status=OutcomeDispatchStatus.SKIPPED,
                dispatch_target=None,
                reason="rejected_by_sibling_review",
            )
        if state == OUTCOME_STATE_DISPATCHED:
            _log.info(
                "outcome_dispatcher SKIP_DISPATCHED outcome_id=%s kind=%s "
                "(already shipped)",
                outcome_id, outcome_kind.value,
            )
            return OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=outcome_kind,
                dispatch_status=OutcomeDispatchStatus.SKIPPED,
                dispatch_target=None,
                reason="already_dispatched",
            )
        if state != OUTCOME_STATE_APPROVED:
            # fix §183 — supersedes §185. An unknown state means the
            # outcome lifecycle is corrupted; SKIPPED is silent and
            # hides the corruption. Raise so the worker logs the
            # traceback and the caller marks the outcome FAILED.
            _log.error(
                "outcome_dispatcher UNKNOWN_STATE outcome_id=%s state=%s kind=%s",
                outcome_id, state, outcome_kind.value,
            )
            raise OutcomeDispatcherError(
                f"unknown outcome state outcome_id={outcome_id} state={state!r}",
            )
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
            elif outcome_kind == OutcomeKind.CAMPAIGN_LAUNCH:
                result = await self._dispatch_campaign_launch(
                    outcome_id, investigation_id, payload, outcome,
                )
            elif outcome_kind == OutcomeKind.PROFILE_SPEC_DRAFT:
                result = await self._dispatch_profile_spec_draft(
                    outcome_id, investigation_id, payload, outcome,
                )
            elif outcome_kind == OutcomeKind.PATCH_ASSESSMENT_REPORT:
                result = await self._dispatch_patch_assessment_report(
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
        except Exception:
            # fix §184 — narrow except masked UnboundLocalError on
            # `result` when an unexpected exception escaped before
            # `result` was assigned. Catch everything, log with the
            # full traceback, and reraise so the caller can mark the
            # outcome FAILED instead of leaving a half-state with a
            # phantom `result`.
            _log.exception(
                "outcome_dispatcher FAILED outcome_id=%s kind=%s",
                outcome_id, outcome_kind.value,
            )
            raise

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

        Standalone investigations (no project_id) write a finding row
        with ``project_id=NULL`` per migration 057. Operator can link
        the finding to a project later — listings filter by
        ``project_id IS NULL`` to surface orphans.
        """
        target_row, inv = await self._load_target_for_investigation(investigation_id)

        # fix §239 — variant-hunt advisory now stamps every DIRECT_FINDING
        # outcome, not only kind=variant_hunt investigations. AUDIT and
        # NDAY children were silently skipping the stamp; operators saw
        # blank advisories on findings spawned through those paths. The
        # advisory remains informational — `exhaustion_declared` when the
        # agent's answer text declares variants are dead/absent (regex
        # match), `no_orders_no_exhaustion_phrase` when neither orders
        # nor a clear exhaustion phrase exist, `orders_present` when the
        # payload carries one or more variant_hunt_orders.
        raw_orders = payload.get("variant_hunt_orders")
        if isinstance(raw_orders, dict):
            order_count = 1
        elif isinstance(raw_orders, list):
            order_count = sum(1 for r in raw_orders if isinstance(r, dict))
        else:
            order_count = 0
        if order_count > 0:
            advisory = "orders_present"
        else:
            answer_text = (payload.get("answer") or "").strip().upper()
            declares_exhaustion = bool(
                _VARIANT_EXHAUSTION_PATTERN.search(answer_text[:400]),
            )
            advisory = (
                "exhaustion_declared"
                if declares_exhaustion
                else "no_orders_no_exhaustion_phrase"
            )
        _log.info(
            "direct_finding variant_hunt_advisory inv=%s outcome=%s inv_kind=%s flag=%s",
            investigation_id, outcome_id, inv.kind, advisory,
        )
        # Stamp the outcome payload so the operator + synthesis prompt
        # can see the advisory without changing the outcome_kind or
        # blocking dispatch.
        async with UnitOfWork() as uow:
            out_row = (await uow.session.exec(
                _select(VRInvestigationOutcomeRecord).where(
                    VRInvestigationOutcomeRecord.id == outcome_id,
                ),
            )).first()
            if out_row is not None:
                try:
                    stored = json.loads(out_row.payload_json or "{}")
                except (ValueError, TypeError):
                    stored = {}
                stored["variant_hunt_advisory"] = advisory
                out_row.payload_json = json.dumps(stored)
                uow.session.add(out_row)
                await uow.session.commit()

        crash_type = payload.get("crash_type")
        vulnerable_function = payload.get("vulnerable_function")
        root_cause = payload.get("answer") or payload.get("reasoning") or ""
        crash_signature = payload.get("crash_signature")
        poc_code = payload.get("poc_code")

        # fix §186 + §235 — single UoW atomically inserts the finding
        # and links it to the investigation. Old code committed after
        # the insert and again after the link update; a crash between
        # the two left an orphan VRFindingRecord with no inv pointer.
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
            await uow.session.flush()
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

        # fix §236 — variant spawn loop is non-atomic across child
        # investigations (each _spawn_variant_child has its own UoW +
        # ARQ enqueue). A crash mid-loop used to leave N children alive
        # with no record of what was already spawned, so re-dispatching
        # the outcome forked another N → 2N. Record each spawned id back
        # to the outcome payload as we go; re-dispatch skips already-
        # spawned indices.
        spawned_indices: set[int] = set(
            payload.get("_spawned_variant_indices") or [],
        )
        spawned_children: list[str] = list(
            payload.get("_spawned_variant_child_ids") or [],
        )
        spawn_errors: list[str] = []
        variants = payload.get("variant_hunt_orders")
        # fix §238 — agents occasionally emit `variant_hunt_orders` as a
        # single dict instead of a list of dicts (when there's exactly
        # one order). Coerce to list. Anything that isn't a dict or list
        # gets dropped with an explicit log so silent corruption shows up.
        if isinstance(variants, dict):
            variants = [variants]
        elif variants is not None and not isinstance(variants, list):
            _log.warning(
                "variant_hunt_orders has unexpected type=%s inv=%s outcome=%s",
                type(variants).__name__, investigation_id, outcome_id,
            )
            variants = None
        if isinstance(variants, list):
            for idx, raw in enumerate(variants):
                if not isinstance(raw, dict):
                    _log.warning(
                        "variant_hunt_orders[%d] non-dict type=%s dropped "
                        "inv=%s outcome=%s",
                        idx, type(raw).__name__, investigation_id, outcome_id,
                    )
                    continue
                if idx in spawned_indices:
                    continue
                try:
                    child_id = await self._spawn_variant_child(
                        parent=inv,
                        parent_target_id=target_row.id,
                        payload=raw,
                    )
                    spawned_children.append(child_id)
                    spawned_indices.add(idx)
                    await self._persist_variant_spawn(
                        outcome_id=outcome_id,
                        variant_index=idx,
                        child_id=child_id,
                    )
                except (ValueError, RuntimeError) as exc:
                    spawn_errors.append(f"{type(exc).__name__}:{exc}")
        # Variant-child auto-PoC: when this DIRECT_FINDING came from
        # a variant-hunt child investigation (parent_investigation_id
        # is set) AND the agent didn't supply poc_code, queue the
        # PoC writer asynchronously. The finding lands now; poc_code
        # populates when the writer task completes. Skip when the
        # finding already carries operator-supplied poc_code so we
        # don't overwrite their work.
        poc_queued: str | None = None
        is_variant_child = bool(inv.parent_investigation_id)
        if is_variant_child and not payload.get("poc_code"):
            try:
                poc_queued = await self._queue_poc_writer(
                    finding_id=finding_id,
                    investigation_id=investigation_id,
                    team_id=inv.team_id,
                )
            except (ValueError, RuntimeError) as exc:
                spawn_errors.append(f"poc_queue_failed:{type(exc).__name__}:{exc}")

        reason_parts = [f"crash_type={crash_type}", f"fn={vulnerable_function}"]
        if spawned_children:
            reason_parts.append(f"variants_spawned={len(spawned_children)}")
        if poc_queued:
            reason_parts.append(f"poc_task={poc_queued}")
        if spawn_errors:
            reason_parts.append(f"variant_errors={'; '.join(spawn_errors)[:200]}")
        return OutcomeDispatchResult(
            outcome_id=outcome_id,
            outcome_kind=OutcomeKind.DIRECT_FINDING,
            dispatch_status=OutcomeDispatchStatus.DISPATCHED,
            dispatch_target=f"vr_finding:{finding_id}",
            reason=" ".join(reason_parts),
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
        # fix §234 — parent.cost_budget_usd is sometimes None (legacy
        # rows or operator-set ad-hoc investigations); `None * 0.5`
        # raised TypeError outside the narrow except filter, which
        # blew up dispatch with no result row. Use $5 as parent floor
        # and ensure the child gets at least $5 to do meaningful work.
        parent_budget = float(parent.cost_budget_usd or 5.0)
        child_budget = float(
            payload.get("cost_budget_usd") or (parent_budget * 0.5),
        )
        if child_budget < 5.0:
            child_budget = 5.0

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

    async def _spawn_variant_child(
        self,
        *,
        parent: VRInvestigationRecord,
        parent_target_id: str,
        payload: dict[str, Any],
    ) -> str:
        """Create a child variant-hunt investigation row + primary branch.

        Shared between two paths:
          - Standalone ``VARIANT_HUNT_ORDER`` outcome (one variant
            per outcome row)
          - Bundled ``variant_hunt_orders`` list inside a
            ``DIRECT_FINDING`` payload (one outcome row spawns N
            children atomically — needed because the reasoning loop
            terminates on the first submit)

        Returns the new investigation id. Raises ``ValueError`` when
        the payload references a missing override target.
        """
        child_target_id = str(payload.get("target_id") or parent_target_id)
        if child_target_id != parent_target_id:
            async with UnitOfWork() as uow:
                child_target = (await uow.session.exec(
                    _select(VRTargetRecord).where(VRTargetRecord.id == child_target_id),
                )).first()
                if child_target is None:
                    raise ValueError(f"override_target_id_not_found:{child_target_id}")

        child_title = str(payload.get("title") or f"Variant hunt: {parent.title}")[:255]
        child_question = str(
            payload.get("question") or payload.get("hypothesis")
            or f"Find variants of the issue identified in {parent.title}",
        )
        # fix §237 — fork-time guards. depth from payload (default 1 =
        # spawning level; child operates at depth+1). Refuse if either
        # the depth limit OR the minimum budget would be violated.
        # Defensive None handling for parent.cost_budget_usd (fix §234).
        depth = int(payload.get("depth") or 1)
        if depth + 1 > MAX_VARIANT_DEPTH:
            raise ValueError(
                f"variant_depth_exceeded:depth={depth} max={MAX_VARIANT_DEPTH}",
            )
        parent_budget = float(parent.cost_budget_usd or VARIANT_MIN_BUDGET_USD)
        child_budget = float(
            payload.get("cost_budget_usd") or (parent_budget * 0.5),
        )
        if child_budget < VARIANT_MIN_BUDGET_USD:
            raise ValueError(
                f"variant_budget_below_floor:${child_budget:.2f} "
                f"min=${VARIANT_MIN_BUDGET_USD:.2f}",
            )
        child_depth = depth + 1
        # Stamp the depth marker into initial_question so the agent (and
        # downstream variant_hunt_orders emitter) can read it back and
        # propagate `depth=child_depth` into each grandchild order.
        child_question = f"[variant-depth={child_depth}] {child_question}"

        async with UnitOfWork() as uow:
            child = VRInvestigationRecord(
                target_id=child_target_id,
                team_id=parent.team_id,
                parent_investigation_id=parent.id,
                kind=InvestigationKind.VARIANT_HUNT.value,
                title=child_title,
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
            child_team_id = child.team_id

        # Enqueue the run_vr_investigate task so the child actually
        # executes — without this the child investigation sits in
        # status=CREATED forever waiting for someone to drive it.
        # Same pattern as the API's create_investigation endpoint.
        try:
            from aila.modules.vr._task_queue import default_task_queue  # noqa: PLC0415
            from aila.modules.vr.workflow.task import run_vr_investigate  # noqa: PLC0415
            task_queue = default_task_queue()
            await task_queue.submit(
                track="vr",
                fn=run_vr_investigate,
                kwargs={"investigation_id": child_id},
                user_id="system",
                group_id="vr_variant_child",
                team_id=child_team_id,
            )
        except (OSError, RuntimeError, TimeoutError, ImportError) as exc:
            _log.warning(
                "_spawn_variant_child: enqueue failed child=%s err=%s",
                child_id, exc,
            )
        return child_id

    async def _persist_variant_spawn(
        self,
        *,
        outcome_id: str,
        variant_index: int,
        child_id: str,
    ) -> None:
        """Stamp a spawned variant child into the outcome payload.

        Persists ``_spawned_variant_indices`` (list[int]) and
        ``_spawned_variant_child_ids`` (list[str]) inside the outcome's
        payload_json so re-dispatch can skip already-spawned variants
        instead of forking duplicates (fix §236).
        """
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _select(VRInvestigationOutcomeRecord).where(
                    VRInvestigationOutcomeRecord.id == outcome_id,
                ),
            )).first()
            if row is None:
                return
            try:
                stored = json.loads(row.payload_json or "{}")
            except (ValueError, TypeError):
                stored = {}
            indices = list(stored.get("_spawned_variant_indices") or [])
            ids = list(stored.get("_spawned_variant_child_ids") or [])
            if variant_index not in indices:
                indices.append(variant_index)
            if child_id not in ids:
                ids.append(child_id)
            stored["_spawned_variant_indices"] = indices
            stored["_spawned_variant_child_ids"] = ids
            row.payload_json = json.dumps(stored)
            uow.session.add(row)
            await uow.session.commit()

    async def _queue_poc_writer(
        self,
        *,
        finding_id: str,
        investigation_id: str,
        team_id: str | None,
    ) -> str:
        """Submit a background task to draft a PoC for ``finding_id``.

        Returns the task id. The task runs ``PocWriter`` against the
        finding's investigation facts and UPDATEs the VRFindingRecord
        with ``poc_code`` + ``poc_language`` when done. We don't
        block dispatch on PoC generation (writer call is ~10-30s of
        LLM time) — finding lands immediately, PoC trickles in.
        """
        from aila.modules.vr._task_queue import default_task_queue  # noqa: PLC0415
        from aila.modules.vr.workflow.task import run_vr_draft_poc  # noqa: PLC0415

        task_queue = default_task_queue()
        handle = await task_queue.submit(
            track="vr",
            fn=run_vr_draft_poc,
            kwargs={
                "finding_id": finding_id,
                "investigation_id": investigation_id,
            },
            user_id="system",
            group_id="vr_poc_writer",
            team_id=team_id,
        )
        return str(getattr(handle, "task_id", finding_id))

    async def _dispatch_campaign_launch(
        self,
        outcome_id: str,
        investigation_id: str,
        payload: dict[str, Any],
        outcome: VRInvestigationOutcomeRecord,
    ) -> OutcomeDispatchResult:
        """CAMPAIGN_LAUNCH → ``vr_fuzz_campaign_proposals`` row.

        The reasoning agent emits a fully prepared proposal: profile,
        rationale, target descriptor, suggested engine + strategy +
        duration + config, plus the harness source, build command,
        seed corpus, and (optionally) a dictionary. The dispatcher
        persists the row in ``pending`` status; the operator approves
        or rejects via ``POST /vr/fuzz/proposals/{id}/{accept,reject}``.
        Until accepted, no campaign row exists and no fuzzer runs.

        Required payload fields:
          - profile: str
          - target_descriptor: dict (at least ``harness`` / ``function``)
        Recommended (operator can fill in on accept if missing):
          - suggested_engine_id, suggested_strategy_id,
            suggested_engine_config, suggested_duration_hours
          - harness_source, harness_language, harness_build_command,
            harness_target_path
          - seed_corpus: list[{filename, content_base64, notes?}]
          - dictionary_content
        """

        target_row, _ = await self._load_target_for_investigation(investigation_id)
        profile = str(payload.get("profile") or "").strip()
        target_descriptor = payload.get("target_descriptor") or {}
        if not profile or not target_descriptor:
            return OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=OutcomeKind.CAMPAIGN_LAUNCH,
                dispatch_status=OutcomeDispatchStatus.FAILED,
                dispatch_target=None,
                reason="missing_profile_or_target_descriptor",
            )

        # fix §262 + §263 — canonical descriptor key + row-level lock.
        # Old code computed the descriptor key inline twice (once for
        # the new row, once per old row) with no shared canonicalizer,
        # so trivial cosmetic differences ("MyHarness" vs "myharness")
        # silently broke supersede. _canonical_descriptor_key now owns
        # the normalization. The SELECT now requests row-level FOR
        # UPDATE locks on matching pending rows so a concurrent
        # dispatch can't supersede the same rows twice.
        descriptor_key = _canonical_descriptor_key(target_descriptor)

        async with UnitOfWork() as uow:
            if descriptor_key:
                old_rows = (await uow.session.exec(
                    _select(VRFuzzCampaignProposalRecord).where(
                        VRFuzzCampaignProposalRecord.investigation_id
                        == investigation_id,
                        VRFuzzCampaignProposalRecord.target_id == target_row.id,
                        VRFuzzCampaignProposalRecord.status == "pending",
                    ).with_for_update(),
                )).all()
                for old in old_rows:
                    try:
                        old_descriptor = json.loads(old.target_descriptor_json or "{}")
                    except (ValueError, TypeError):
                        continue
                    if _canonical_descriptor_key(old_descriptor) == descriptor_key:
                        old.status = "superseded"
                        old.updated_at = utc_now()
                        uow.session.add(old)

            row = VRFuzzCampaignProposalRecord(
                investigation_id=investigation_id,
                outcome_id=outcome_id,
                target_id=target_row.id,
                workspace_id=target_row.workspace_id,
                team_id=target_row.team_id,
                profile=profile,
                rationale=str(payload.get("rationale") or "")[:8192],
                confidence=str(outcome.confidence)[:24],
                target_descriptor_json=json.dumps(target_descriptor),
                suggested_engine_id=_str_or_none(
                    payload.get("suggested_engine_id")
                    or payload.get("engine_id"),
                ),
                suggested_engine_config_json=json.dumps(payload.get("suggested_engine_config")
                or payload.get("engine_config")
                or {}),
                suggested_strategy_id=_str_or_none(
                    payload.get("suggested_strategy_id")
                    or payload.get("strategy_id"),
                ),
                suggested_duration_hours=_int_or_none(
                    payload.get("suggested_duration_hours")
                    or payload.get("duration_hours"),
                ),
                harness_source=_str_or_none(payload.get("harness_source")),
                harness_language=_str_or_none(payload.get("harness_language")),
                harness_build_command=_str_or_none(
                    payload.get("harness_build_command"),
                ),
                harness_target_path=_str_or_none(
                    payload.get("harness_target_path"),
                ),
                seed_corpus_json=json.dumps(payload.get("seed_corpus") or []),
                dictionary_content=_str_or_none(
                    payload.get("dictionary_content"),
                ),
                status="pending",
            )
            uow.session.add(row)
            await uow.session.commit()
            await uow.session.refresh(row)
            proposal_id = row.id

        return OutcomeDispatchResult(
            outcome_id=outcome_id,
            outcome_kind=OutcomeKind.CAMPAIGN_LAUNCH,
            dispatch_status=OutcomeDispatchStatus.DISPATCHED,
            dispatch_target=f"fuzz_proposal:{proposal_id}",
            reason=(
                f"target_id={target_row.id} profile={profile} "
                f"status=pending awaiting operator approval"
            ),
        )

    async def _dispatch_profile_spec_draft(
        self,
        outcome_id: str,
        investigation_id: str,
        payload: dict[str, Any],
        outcome: VRInvestigationOutcomeRecord,
    ) -> OutcomeDispatchResult:
        """PROFILE_SPEC_DRAFT → KnowledgeService write under
        ``vr.profile_spec.workspace.<id>``.

        Stores the engine's proposed fuzzing-profile / strategy-profile
        draft. A future profile registry consumer reads the same namespace.

        Required payload fields:
          - profile_name
          - profile_kind (fuzzing | reasoning_strategy | other)
          - spec: structured dict
        """
        target_row, _ = await self._load_target_for_investigation(investigation_id)
        profile_name = str(payload.get("profile_name") or "").strip()
        profile_kind = str(payload.get("profile_kind") or "fuzzing").strip()
        spec = payload.get("spec") or {}
        if not profile_name or not isinstance(spec, dict) or not spec:
            return OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=OutcomeKind.PROFILE_SPEC_DRAFT,
                dispatch_status=OutcomeDispatchStatus.FAILED,
                dispatch_target=None,
                reason="missing_profile_name_or_spec",
            )

        workspace_id = target_row.workspace_id
        namespace = f"vr.profile_spec.workspace.{workspace_id}"
        content = (
            f"Profile draft — {profile_name} ({profile_kind})\n"
            f"spec={json.dumps(spec, sort_keys=True)}"
        )
        store_result = await self._knowledge.store(
            namespace=namespace,
            content=content,
            metadata={
                "investigation_id": investigation_id,
                "target_id": target_row.id,
                "workspace_id": workspace_id,
                "profile_name": profile_name,
                "profile_kind": profile_kind,
                "spec": spec,
                "rationale": payload.get("rationale") or "",
                "confidence": outcome.confidence,
                "outcome_id": outcome_id,
                "status": "draft",
            },
            # fix §264 — old dedup_key was (workspace, kind, name) only.
            # Two drafts that shared a profile_name but had different spec
            # dicts silently overwrote each other in KnowledgeService.
            # Mix in the canonical-JSON spec hash so genuine spec changes
            # produce a fresh entry instead of dedup-collapsing the latest
            # over the previous.
            dedup_key=(
                f"{workspace_id}|{profile_kind}|{profile_name}|"
                f"{hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()[:16]}"
            ),
        )
        entry_id = store_result.get("entry_id")
        return OutcomeDispatchResult(
            outcome_id=outcome_id,
            outcome_kind=OutcomeKind.PROFILE_SPEC_DRAFT,
            dispatch_status=OutcomeDispatchStatus.DISPATCHED,
            dispatch_target=f"knowledge_entry:{entry_id}",
            reason=f"namespace={namespace} name={profile_name}",
        )

    async def _dispatch_patch_assessment_report(
        self,
        outcome_id: str,
        investigation_id: str,
        payload: dict[str, Any],
    ) -> OutcomeDispatchResult:
        """PATCH_ASSESSMENT_REPORT → spawn variant_hunt children + (optionally) enqueue nday.

        Two parallel paths, both run when their inputs are present:

        1. ``variant_hunt_orders`` (list[dict]) — spawn one child
           investigation per residual-gap candidate the agent named.
           This is the path that matters when the agent's verdict is
           'PATCH PRESENT but with residual gap candidates (X, Y, Z)'
           — without spawning children for X/Y/Z, the candidates die in
           the report and no follow-up audit ever happens.

        2. ``patch_descriptor`` ({vulnerable_ref, patched_ref, repo_url})
           — kick off the N-day workflow that materialises the
           assessment into a finding + disclosure scaffold. Optional;
           skipped when the report is a pure patch-verification with no
           N-day disclosure path.
        """
        target_row, parent_inv = await self._load_target_for_investigation(
            investigation_id,
        )

        # Path 1: variant-hunt fan-out for residual gap candidates.
        # fix §266 — same idempotent spawn pattern as §236. Each
        # successful spawn writes back to the outcome payload so a
        # mid-loop crash + re-dispatch doesn't re-spawn the same N.
        spawned_indices: set[int] = set(
            payload.get("_spawned_variant_indices") or [],
        )
        spawned_children: list[str] = list(
            payload.get("_spawned_variant_child_ids") or [],
        )
        spawn_errors: list[str] = []
        variants = payload.get("variant_hunt_orders")
        # Reuse §238's coercion: tolerate a single dict, drop garbage.
        if isinstance(variants, dict):
            variants = [variants]
        elif variants is not None and not isinstance(variants, list):
            _log.warning(
                "patch_assessment variant_hunt_orders unexpected type=%s "
                "inv=%s outcome=%s",
                type(variants).__name__, investigation_id, outcome_id,
            )
            variants = None
        if isinstance(variants, list):
            for idx, raw in enumerate(variants):
                if not isinstance(raw, dict):
                    _log.warning(
                        "patch_assessment variant_hunt_orders[%d] non-dict "
                        "type=%s dropped inv=%s outcome=%s",
                        idx, type(raw).__name__, investigation_id, outcome_id,
                    )
                    continue
                if idx in spawned_indices:
                    continue
                try:
                    child_id = await self._spawn_variant_child(
                        parent=parent_inv,
                        parent_target_id=target_row.id,
                        payload=raw,
                    )
                    spawned_children.append(child_id)
                    spawned_indices.add(idx)
                    await self._persist_variant_spawn(
                        outcome_id=outcome_id,
                        variant_index=idx,
                        child_id=child_id,
                    )
                except (ValueError, RuntimeError) as exc:
                    spawn_errors.append(f"{type(exc).__name__}:{exc}")

        # Path 2: nday enqueue (optional — only when patch_descriptor present).
        patch_descriptor = payload.get("patch_descriptor") or {}
        assessment = payload.get("assessment") or {}
        nday_handle_id: str | None = None
        nday_error: str | None = None
        if isinstance(patch_descriptor, dict) and patch_descriptor:
            # fix §265 — explicit required-key check before enqueue. The
            # nday workflow upstream blew up midway when any of these
            # were absent; raise at the dispatcher so the outcome ends
            # up FAILED with a clear reason instead of silently leaving
            # the nday queue empty + a half-touched assessment row.
            missing = [
                k for k in ("vulnerable_ref", "patched_ref", "repo_url")
                if not patch_descriptor.get(k)
            ]
            if missing:
                raise ValueError(
                    f"patch_descriptor missing required keys: {missing}",
                )
            try:
                handle = await enqueue_vr_nday(
                    self._task_queue_factory(),
                    source_outcome_id=outcome_id,
                    patch_descriptor=patch_descriptor,
                    assessment=assessment,
                    parent_investigation_id=parent_inv.id,
                    target_id=target_row.id,
                    team_id=target_row.team_id,
                )
                nday_handle_id = handle.task_id
            except (OSError, TimeoutError, RuntimeError, ValueError) as exc:
                nday_error = f"{type(exc).__name__}:{exc}"

        # Both paths absent — at least the verdict prose lands in the
        # outcome row; report it as DISPATCHED so the UI shows green.
        if not spawned_children and nday_handle_id is None and not spawn_errors and not nday_error:
            return OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=OutcomeKind.PATCH_ASSESSMENT_REPORT,
                dispatch_status=OutcomeDispatchStatus.DISPATCHED,
                dispatch_target=None,
                reason="verdict_only:no_variants_no_nday_descriptor",
            )

        reason_parts: list[str] = []
        if spawned_children:
            reason_parts.append(f"spawned_children={len(spawned_children)}")
        if spawn_errors:
            reason_parts.append(f"spawn_errors={spawn_errors[:3]}")
        if nday_handle_id:
            reason_parts.append(f"nday_task={nday_handle_id}")
        if nday_error:
            reason_parts.append(f"nday_error={nday_error}")

        return OutcomeDispatchResult(
            outcome_id=outcome_id,
            outcome_kind=OutcomeKind.PATCH_ASSESSMENT_REPORT,
            dispatch_status=OutcomeDispatchStatus.DISPATCHED,
            dispatch_target=(
                f"children={spawned_children};nday={nday_handle_id}"
                if (spawned_children or nday_handle_id)
                else None
            ),
            reason="; ".join(reason_parts) or "patch_assessment_recorded",
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
        from aila.modules.vr.contracts import (  # noqa: PLC0415
            BranchStatus,
            InvestigationStatus,
        )
        from aila.modules.vr.db_models import (  # noqa: PLC0415
            VRInvestigationBranchRecord,
            VRInvestigationRecord,
        )
        from aila.modules.vr.services.outcome_review import (  # noqa: PLC0415
            OUTCOME_STATE_DISPATCHED,
        )
        from aila.platform.contracts._common import utc_now  # noqa: PLC0415

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
            just_dispatched = (
                result.dispatch_status == OutcomeDispatchStatus.DISPATCHED
            )
            if just_dispatched:
                outcome.state = OUTCOME_STATE_DISPATCHED
            uow.session.add(outcome)

            # When an outcome successfully dispatches, the investigation
            # has reached its goal — any remaining active sibling
            # branches should stop burning turns on a question already
            # answered. Halt them + flip the investigation to COMPLETED
            # if no branches remain active.
            #
            # Safety net behind evaluate_quorum's halt: evaluate_quorum
            # halts when state flips to APPROVED, but that requires
            # sibling votes. A legacy outcome that dispatches via
            # auto_promote (claim_verifier) or the operator promote-
            # to-finding endpoint bypasses quorum. Without this hook,
            # those paths leave siblings churning indefinitely.
            if just_dispatched:
                investigation_id = outcome.investigation_id
                proposing_branch_id = outcome.branch_id
                actives = (await uow.session.exec(
                    _select(VRInvestigationBranchRecord).where(
                        VRInvestigationBranchRecord.investigation_id
                        == investigation_id,
                        VRInvestigationBranchRecord.status
                        == BranchStatus.ACTIVE.value,
                    ),
                )).all()
                halted = 0
                for branch in actives:
                    if branch.id == proposing_branch_id:
                        continue
                    branch.status = BranchStatus.ABANDONED.value
                    branch.closed_reason = (
                        f"sibling_outcome_dispatched:{result.outcome_id}"
                    )
                    branch.closed_at = utc_now()
                    branch.updated_at = utc_now()
                    uow.session.add(branch)
                    halted += 1
                if halted > 0:
                    _log.info(
                        "outcome_dispatcher HALT_SIBLINGS outcome=%s "
                        "halted=%d (dispatched)",
                        result.outcome_id, halted,
                    )
                # Flip investigation to COMPLETED only when no active
                # branch remains (proposing branch could still be in
                # flight if dispatch was triggered async).
                inv = (await uow.session.exec(
                    _select(VRInvestigationRecord).where(
                        VRInvestigationRecord.id == investigation_id,
                    )
                )).first()
                if (
                    inv is not None
                    and inv.status == InvestigationStatus.RUNNING.value
                ):
                    remaining = (await uow.session.exec(
                        _select(VRInvestigationBranchRecord).where(
                            VRInvestigationBranchRecord.investigation_id
                            == investigation_id,
                            VRInvestigationBranchRecord.status
                            == BranchStatus.ACTIVE.value,
                        ),
                    )).all()
                    if not remaining:
                        inv.status = InvestigationStatus.COMPLETED.value
                        inv.stopped_at = utc_now()
                        inv.updated_at = utc_now()
                        uow.session.add(inv)
                        _log.info(
                            "outcome_dispatcher COMPLETE investigation=%s "
                            "(dispatched, no active branches remain)",
                            investigation_id,
                        )
            await uow.commit()

        # If the investigation just completed (no active branches remain
        # after sibling halt), drop the investigation's pending ARQ jobs
        # so siblings whose tasks were dispatched but not yet dequeued
        # don't run a wasted setup pass.
        if just_dispatched:
            try:
                from aila.modules.vr.services.arq_purge import (  # noqa: PLC0415
                    purge_arq_jobs_for_investigation,
                )
                purged = await purge_arq_jobs_for_investigation(
                    outcome.investigation_id, track="vr",
                )
                if purged.get("purged_jobs", 0) > 0:
                    _log.info(
                        "outcome_dispatcher ARQ_PURGE inv=%s purged=%d",
                        outcome.investigation_id, purged["purged_jobs"],
                    )
            except (OSError, RuntimeError, ImportError) as exc:
                _log.warning(
                    "outcome_dispatcher ARQ_PURGE failed inv=%s err=%s",
                    outcome.investigation_id, exc,
                )


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
