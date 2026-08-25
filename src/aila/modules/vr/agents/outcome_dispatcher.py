"""Outcome dispatcher (M3.R-8).

Routes accepted VRInvestigationOutcomeRecord rows to their downstream
artifacts. Ships handlers for every D-43 outcome kind except
ASSESSMENT_REPORT, which is terminal by design (narrative-only summary,
no downstream consumer):

  AUDIT_MEMO              \u2192 KnowledgeService.store namespace
                            ``vr.audit_memo.<scope>.<id>`` (D-38 pgvector
                            + HNSW + FTS).
  DIRECT_FINDING          \u2192 vr_findings row (linked to project +
                            target). Investigations without a project
                            still land the finding with project_id NULL
                            for later operator linking.
  VARIANT_HUNT_ORDER      \u2192 spawn child VRInvestigationRecord
                            (parent_investigation_id set, kind=variant_hunt)
                            + enqueue run_vr_investigate.
  CAMPAIGN_LAUNCH         \u2192 vr_fuzz_campaign_proposals row awaiting
                            operator approval before any fuzzer runs.
  PROFILE_SPEC_DRAFT      \u2192 KnowledgeService write under
                            ``vr.profile_spec.workspace.<id>``.
  PATCH_ASSESSMENT_REPORT \u2192 fan out variant_hunt children +
                            (optionally) enqueue N-day workflow.
  STRATEGY_DESCRIPTOR     \u2192 KnowledgeService write under
                            ``vr.strategy_descriptor.workspace.<id>``.
  CRASH_TRIAGE_REPORT     \u2192 KnowledgeService write under
                            ``vr.crash_triage.workspace.<id>``.
  CONFIG_DELTA            \u2192 KnowledgeService write under
                            ``vr.config_delta.workspace.<id>`` as a
                            recorded proposal (status=proposed). Never
                            auto-applied -- an operator or a future
                            review UI drives the apply/reject decision.
  SUB_INVESTIGATION       \u2192 spawn child VRInvestigationRecord +
                            enqueue run_vr_investigate. Guarded by
                            depth cap + per-parent fan-out cap.
  ASSESSMENT_REPORT       \u2192 SKIPPED with reason
                            ``assessment_reports_are_terminal_no_downstream``.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from typing import Any
from uuid import uuid4

from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select as _select

from aila.modules.vr._task_queue import (
    default_task_queue,
    enqueue_vr_nday,
)
from aila.modules.vr._task_queue import (
    default_task_queue as _build_default_task_queue,
)
from aila.modules.vr.contracts import BranchStatus, OutcomeDispatchStatus, OutcomeKind
from aila.modules.vr.contracts.evidence_ref import EvidenceRefList
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
from aila.modules.vr.services.outcome_review import (
    OUTCOME_STATE_APPROVED,
    OUTCOME_STATE_DISPATCHED,
    OUTCOME_STATE_DRAFT,
    OUTCOME_STATE_REJECTED,
    set_outcome_state,
)
from aila.platform.agents.outcome_dispatcher import (
    OutcomeDispatcherBase,
    OutcomeDispatcherError,
    OutcomeDispatchResult,
)
from aila.platform.contracts import utc_now
from aila.platform.services.branch_cleanup import close_orphan_branches_on_terminal
from aila.platform.services.knowledge import KnowledgeService
from aila.platform.tasks.arq_purge import purge_arq_jobs_for_investigation
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


# fix \u00a7237 -- variant-hunt fork-time guards. MAX_VARIANT_DEPTH bounds
# the recursion chain so a runaway agent can't fork variants of variants
# of variants forever. VARIANT_MIN_BUDGET_USD prevents spawning a child
# whose $-budget can't pay for even a single round of reasoning.
MAX_VARIANT_DEPTH = 5
VARIANT_MIN_BUDGET_USD = 5.0


# SUB_INVESTIGATION fork guards (mirror of the variant-hunt caps above).
# MAX_SUB_INVESTIGATION_DEPTH bounds parent-chain depth so a runaway
# agent can't recursively spawn sub-of-sub-of-sub investigations.
# child_depth = parent_depth + 1; we refuse when the child would exceed
# the cap. Default 2 means the tree may grow to depth 2 above root and
# no further (root -> sub -> sub-sub is the deepest allowed shape).
# MAX_SUB_INVESTIGATION_PER_PARENT bounds how many direct children a
# single parent may accumulate, so a single burst can't conjure a
# swarm of siblings.
MAX_SUB_INVESTIGATION_DEPTH = 2
MAX_SUB_INVESTIGATION_PER_PARENT = 5



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
    drift between the two formulas -- case, whitespace, key choice --
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
    except (TypeError, ValueError) as exc:
        # Coercion helper: bad inputs intentionally return None. Logged at
        # debug so the audit sees we're not silently swallowing the error,
        # so normal "could not parse" cases don't flood operator logs.
        _log.debug("_int_or_none: cannot coerce value=%r exc=%s", value, exc)
        return None



# ASSESSMENT_REPORT is the ONE remaining kind with no downstream
# dispatch: assessment reports are terminal narrative summaries and
# carry no actionable payload for a follow-up subsystem. Every other
# outcome kind (AUDIT_MEMO, DIRECT_FINDING, VARIANT_HUNT_ORDER,
# CAMPAIGN_LAUNCH, PROFILE_SPEC_DRAFT, PATCH_ASSESSMENT_REPORT,
# STRATEGY_DESCRIPTOR, CRASH_TRIAGE_REPORT, CONFIG_DELTA,
# SUB_INVESTIGATION) routes to a real handler in _handle_kind.
_NOT_YET_DISPATCHABLE: dict[OutcomeKind, str] = {
    OutcomeKind.ASSESSMENT_REPORT: "assessment_reports_are_terminal_no_downstream",
}


class OutcomeDispatcher(OutcomeDispatcherBase):
    """Routes accepted VR outcomes to their downstream artifacts.

    Thin subclass of :class:`OutcomeDispatcherBase`: the base owns the
    claim + not-found/not-won paths + terminal status write cascade
    wiring; this class supplies the VR outcome model, the state guard
    that gates dispatch on ``state == 'approved'``, the if/elif
    per-kind routing, and the VR-specific persist step (halt sibling
    branches, flip investigation to COMPLETED, purge ARQ jobs).

    Construction takes only the KnowledgeService -- the other handlers
    use direct DB writes through UnitOfWork plus the platform task
    queue for child-investigation spawning. Tests can inject a fake
    KnowledgeService with the same ``store(namespace, content, ...)``
    coroutine signature.
    """

    _outcome_model = VRInvestigationOutcomeRecord
    _outcome_kind_cls = OutcomeKind
    # A missing outcome is stamped with a terminal-flavoured kind so the
    # SKIPPED result carries a valid enum member. ASSESSMENT_REPORT is
    # the terminal-no-downstream VR kind and reads correctly on the
    # operator dashboard.
    _default_error_kind = OutcomeKind.ASSESSMENT_REPORT
    # VR treats a handler exception as fatal: re-raise so the ARQ task
    # is marked FAILED and the caller can decide to retry. Malware
    # folds the same shape into a FAILED result via the base default.
    _catch_handler_errors = False

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

    def _dispatch_state_guard(self, outcome: VRInvestigationOutcomeRecord) -> str | None:
        """Refuse dispatch of any outcome whose state is not approved.

        Runs inside the platform claim's FOR UPDATE transaction. Returns a
        skip reason for draft/rejected/already-dispatched rows so they are
        not claimed, None to allow the claim (approved), and raises on a
        corrupt state so the worker logs it and the caller marks FAILED.
        """
        state = outcome.state
        if state is None:
            raise OutcomeDispatcherError(
                f"outcome.state is NULL outcome_id={outcome.id}",
            )
        if state == OUTCOME_STATE_DRAFT:
            return "draft_awaiting_sibling_quorum"
        if state == OUTCOME_STATE_REJECTED:
            return "rejected_by_sibling_review"
        if state == OUTCOME_STATE_DISPATCHED:
            return "already_dispatched"
        if state != OUTCOME_STATE_APPROVED:
            raise OutcomeDispatcherError(
                f"unknown outcome state outcome_id={outcome.id} state={state!r}",
            )
        return None

    async def _load_outcome_row(
        self, outcome_id: str,
    ) -> VRInvestigationOutcomeRecord | None:
        """Reload the outcome row after the claim so per-kind handlers
        can read ``outcome.confidence`` off a live row.

        The base skeleton reads the routing values (payload,
        investigation_id) off the claim snapshot; this reload only
        supplies the row object AUDIT_MEMO / CAMPAIGN_LAUNCH /
        PROFILE_SPEC_DRAFT need to stamp confidence onto their
        knowledge-entry / proposal-row metadata.
        """
        async with UnitOfWork() as uow:
            return (await uow.session.exec(
                _select(VRInvestigationOutcomeRecord).where(
                    VRInvestigationOutcomeRecord.id == outcome_id,
                ),
            )).first()

    async def _handle_kind(
        self,
        *,
        outcome_kind: OutcomeKind,
        outcome_id: str,
        investigation_id: str,
        payload: dict[str, Any],
        outcome_row: VRInvestigationOutcomeRecord | None,
    ) -> OutcomeDispatchResult:
        """Route the winning claim to the matching per-kind handler.

        AUDIT_MEMO / CAMPAIGN_LAUNCH / PROFILE_SPEC_DRAFT need the
        live outcome row for ``outcome.confidence``; the others take
        only the payload snapshot.
        """
        if outcome_kind == OutcomeKind.AUDIT_MEMO:
            return await self._dispatch_audit_memo(
                outcome_id, investigation_id, payload, outcome_row,
            )
        if outcome_kind == OutcomeKind.DIRECT_FINDING:
            return await self._dispatch_direct_finding(
                outcome_id, investigation_id, payload,
            )
        if outcome_kind == OutcomeKind.VARIANT_HUNT_ORDER:
            return await self._dispatch_variant_hunt_order(
                outcome_id, investigation_id, payload,
            )
        if outcome_kind == OutcomeKind.CAMPAIGN_LAUNCH:
            return await self._dispatch_campaign_launch(
                outcome_id, investigation_id, payload, outcome_row,
            )
        if outcome_kind == OutcomeKind.PROFILE_SPEC_DRAFT:
            return await self._dispatch_profile_spec_draft(
                outcome_id, investigation_id, payload, outcome_row,
            )
        if outcome_kind == OutcomeKind.PATCH_ASSESSMENT_REPORT:
            return await self._dispatch_patch_assessment_report(
                outcome_id, investigation_id, payload,
            )
        if outcome_kind == OutcomeKind.STRATEGY_DESCRIPTOR:
            return await self._dispatch_strategy_descriptor(
                outcome_id, investigation_id, payload, outcome_row,
            )
        if outcome_kind == OutcomeKind.CRASH_TRIAGE_REPORT:
            return await self._dispatch_crash_triage_report(
                outcome_id, investigation_id, payload, outcome_row,
            )
        if outcome_kind == OutcomeKind.CONFIG_DELTA:
            return await self._dispatch_config_delta(
                outcome_id, investigation_id, payload, outcome_row,
            )
        if outcome_kind == OutcomeKind.SUB_INVESTIGATION:
            return await self._dispatch_sub_investigation(
                outcome_id, investigation_id, payload,
            )
        if outcome_kind in _NOT_YET_DISPATCHABLE:
            return OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=outcome_kind,
                dispatch_status=OutcomeDispatchStatus.SKIPPED,
                dispatch_target=None,
                reason=_NOT_YET_DISPATCHABLE[outcome_kind],
            )
        return OutcomeDispatchResult(
            outcome_id=outcome_id,
            outcome_kind=outcome_kind,
            dispatch_status=OutcomeDispatchStatus.SKIPPED,
            dispatch_target=None,
            reason=f"unknown_outcome_kind:{outcome_kind.value}",
        )

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
            extract_entities=True,
            link_neighbors=True,
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
        the finding to a project later -- listings filter by
        ``project_id IS NULL`` to surface orphans.
        """
        target_row, inv = await self._load_target_for_investigation(investigation_id)

        # fix §239 -- variant-hunt advisory now stamps every DIRECT_FINDING
        # outcome, not only kind=variant_hunt investigations. AUDIT and
        # NDAY children were silently skipping the stamp; operators saw
        # blank advisories on findings spawned through those paths. The
        # advisory remains informational -- `exhaustion_declared` when the
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
        raw_cvss = payload.get("cvss_score")
        cvss_score = float(raw_cvss) if isinstance(raw_cvss, (int, float)) else None
        cvss_vector = payload.get("cvss_vector")
        cwe_id = payload.get("cwe_id")
        assigned_cve_id = payload.get("assigned_cve_id") or payload.get("cve_id")

        # fix §186 + §235 -- single UoW atomically inserts the finding
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
                cvss_score=cvss_score,
                cvss_vector=(cvss_vector[:128] if isinstance(cvss_vector, str) else None),
                cwe_id=(cwe_id[:16] if isinstance(cwe_id, str) else None),
                assigned_cve_id=(assigned_cve_id[:32] if isinstance(assigned_cve_id, str) else None),
                evidence_refs_json=EvidenceRefList.model_validate(
                    payload.get("evidence_refs") or [],
                ).model_dump_json(),
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

        # RFC-12: burn the finding into the vector DB so a future
        # investigation on this target retrieves it. The agent's primary
        # output (a confirmed vulnerability) must reach the RAG store, not
        # only vr_findings -- otherwise cross-investigation knowledge never
        # sees it. Best-effort: the finding row is already committed, so a
        # KB-mirror failure logs and returns the finding result unchanged
        # rather than failing the dispatch.
        finding_text = str(root_cause).strip()
        if finding_text:
            target_signature = str(
                payload.get("target_signature")
                or _compute_target_signature(target_row.id, payload),
            )
            ws_id = target_row.workspace_id
            try:
                await self._knowledge.store(
                    namespace=f"vr.finding.workspace.{ws_id}",
                    content=finding_text,
                    metadata={
                        "investigation_id": investigation_id,
                        "finding_id": finding_id,
                        "target_id": target_row.id,
                        "workspace_id": ws_id,
                        "target_signature": target_signature,
                        "vulnerable_function": vulnerable_function,
                        "crash_type": crash_type,
                        "evidence_refs": payload.get("evidence_refs") or [],
                        "outcome_id": outcome_id,
                    },
                    dedup_key=f"finding:{finding_id}",
                    extract_entities=True,
                    link_neighbors=True,
                )
            except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError) as exc:
                _log.warning(
                    "direct_finding KB mirror failed inv=%s finding=%s: %s",
                    investigation_id, finding_id, exc, exc_info=True,
                )

        # fix §236 -- variant spawn loop is non-atomic across child
        # investigations (each _spawn_variant_child has its own UoW +
        # ARQ enqueue). A crash mid-loop used to leave N children alive
        # leaving no record of what was already spawned, so re-dispatching
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
        # fix §238 -- agents occasionally emit `variant_hunt_orders` as a
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
        # fix §234 -- parent.cost_budget_usd is sometimes None (legacy
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
            child_team_id = child.team_id

        # fix §233 -- enqueue the run_vr_investigate task. Without this
        # the child sits in status=CREATED forever; the canonical
        # VARIANT_HUNT_ORDER outcome path produced zombie investigations
        # whereas the bundled _spawn_variant_child path correctly enqueued.
        # Same enqueue shape as _spawn_variant_child (commit 6d7cab1).
        enqueue_error: str | None = None
        try:
            from aila.modules.vr.workflow.task import run_vr_investigate
            task_queue = default_task_queue()
            await task_queue.submit(
                track="vr",
                fn=run_vr_investigate,
                kwargs={"investigation_id": child_id},
                user_id="system",
                group_id="vr_variant_hunt_order",
                team_id=child_team_id,
            )
        except (OSError, RuntimeError, TimeoutError, ImportError) as exc:
            enqueue_error = f"{type(exc).__name__}:{exc}"
            _log.warning(
                "_dispatch_variant_hunt_order: enqueue failed child=%s err=%s",
                child_id, exc,
            )

        reason_parts = [
            f"target_id={child_target_id}",
            f"budget=${child_budget:.2f}",
        ]
        if enqueue_error:
            reason_parts.append(f"enqueue_error={enqueue_error[:120]}")
        return OutcomeDispatchResult(
            outcome_id=outcome_id,
            outcome_kind=OutcomeKind.VARIANT_HUNT_ORDER,
            dispatch_status=OutcomeDispatchStatus.DISPATCHED,
            dispatch_target=f"vr_investigation:{child_id}",
            reason=" ".join(reason_parts),
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
            children atomically -- needed because the reasoning loop
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
        # fix §237 -- fork-time guards. depth from payload (default 1 =
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
        # executes -- without this the child investigation sits in
        # status=CREATED forever waiting for someone to drive it.
        # Same pattern as the API's create_investigation endpoint.
        try:
            from aila.modules.vr.workflow.task import run_vr_investigate
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
        LLM time) -- finding lands immediately, PoC trickles in.
        """
        from aila.modules.vr.workflow.task import run_vr_draft_poc

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

        # fix §262 + §263 -- canonical descriptor key + row-level lock.
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
            f"Profile draft -- {profile_name} ({profile_kind})\n"
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
            # fix §264 -- old dedup_key was (workspace, kind, name) only.
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

        1. ``variant_hunt_orders`` (list[dict]) -- spawn one child
           investigation per residual-gap candidate the agent named.
           This is the path that matters when the agent's verdict is
           'PATCH PRESENT but with residual gap candidates (X, Y, Z)'
           -- without spawning children for X/Y/Z, the candidates die in
           the report and no follow-up audit ever happens.

        2. ``patch_descriptor`` ({vulnerable_ref, patched_ref, repo_url})
           -- kick off the N-day workflow that materialises the
           assessment into a finding + disclosure scaffold. Optional;
           skipped when the report is a pure patch-verification with no
           N-day disclosure path.
        """
        target_row, parent_inv = await self._load_target_for_investigation(
            investigation_id,
        )

        # Path 1: variant-hunt fan-out for residual gap candidates.
        # fix §266 -- same idempotent spawn pattern as §236. Each
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

        # Path 2: nday enqueue (optional -- only when patch_descriptor present).
        patch_descriptor = payload.get("patch_descriptor") or {}
        assessment = payload.get("assessment") or {}
        nday_handle_id: str | None = None
        nday_error: str | None = None
        if isinstance(patch_descriptor, dict) and patch_descriptor:
            # fix §265 -- explicit required-key check before enqueue. The
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

        # Both paths absent -- at least the verdict prose lands in the
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

    async def _dispatch_strategy_descriptor(
        self,
        outcome_id: str,
        investigation_id: str,
        payload: dict[str, Any],
        outcome: VRInvestigationOutcomeRecord | None,
    ) -> OutcomeDispatchResult:
        """STRATEGY_DESCRIPTOR -> KnowledgeService write under
        ``vr.strategy_descriptor.workspace.<id>``.

        Mirrors ``_dispatch_profile_spec_draft`` shape: the engine
        emits a reusable strategy artifact (e.g. FUZZILLI/AFL++ recipe,
        directed-fuzzing playbook) and we persist it in the workspace
        namespace so a future strategy-registry consumer can read it.

        Required payload fields:
          - descriptor_name
          - descriptor (dict)
        Recommended:
          - descriptor_kind (default 'generic')
          - rationale
        """
        target_row, _ = await self._load_target_for_investigation(investigation_id)
        descriptor_name = str(
            payload.get("descriptor_name") or payload.get("name") or "",
        ).strip()
        descriptor_kind = str(payload.get("descriptor_kind") or "generic").strip()
        descriptor = payload.get("descriptor") or payload.get("spec") or {}
        if (
            not descriptor_name
            or not isinstance(descriptor, dict)
            or not descriptor
        ):
            return OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=OutcomeKind.STRATEGY_DESCRIPTOR,
                dispatch_status=OutcomeDispatchStatus.FAILED,
                dispatch_target=None,
                reason="missing_descriptor_name_or_descriptor",
            )

        workspace_id = target_row.workspace_id
        namespace = f"vr.strategy_descriptor.workspace.{workspace_id}"
        content = (
            f"Strategy descriptor -- {descriptor_name} ({descriptor_kind})\n"
            f"descriptor={json.dumps(descriptor, sort_keys=True)}"
        )
        # dedup_key mixes canonical-JSON descriptor hash so genuine spec
        # changes produce a fresh entry instead of overwriting the prior
        # descriptor (same rationale as \u00a7264 for profile_spec_draft).
        dedup_key = (
            f"{workspace_id}|{descriptor_kind}|{descriptor_name}|"
            f"{hashlib.sha256(json.dumps(descriptor, sort_keys=True).encode()).hexdigest()[:16]}"
        )
        try:
            store_result = await self._knowledge.store(
                namespace=namespace,
                content=content,
                metadata={
                    "investigation_id": investigation_id,
                    "target_id": target_row.id,
                    "workspace_id": workspace_id,
                    "descriptor_name": descriptor_name,
                    "descriptor_kind": descriptor_kind,
                    "descriptor": descriptor,
                    "rationale": payload.get("rationale") or "",
                    "confidence": (
                        outcome.confidence if outcome is not None else None
                    ),
                    "outcome_id": outcome_id,
                    "status": "recorded",
                },
                dedup_key=dedup_key,
            )
        except (
            OSError, RuntimeError, TimeoutError, ValueError,
            SQLAlchemyError,
        ) as exc:
            _log.warning(
                "_dispatch_strategy_descriptor: store failed inv=%s "
                "outcome=%s err=%s",
                investigation_id, outcome_id, exc,
            )
            return OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=OutcomeKind.STRATEGY_DESCRIPTOR,
                dispatch_status=OutcomeDispatchStatus.FAILED,
                dispatch_target=None,
                reason=f"knowledge_store_failed:{type(exc).__name__}",
            )
        entry_id = store_result.get("entry_id")
        return OutcomeDispatchResult(
            outcome_id=outcome_id,
            outcome_kind=OutcomeKind.STRATEGY_DESCRIPTOR,
            dispatch_status=OutcomeDispatchStatus.DISPATCHED,
            dispatch_target=f"knowledge_entry:{entry_id}",
            reason=f"namespace={namespace} name={descriptor_name}",
        )

    async def _dispatch_crash_triage_report(
        self,
        outcome_id: str,
        investigation_id: str,
        payload: dict[str, Any],
        outcome: VRInvestigationOutcomeRecord | None,
    ) -> OutcomeDispatchResult:
        """CRASH_TRIAGE_REPORT -> KnowledgeService write under
        ``vr.crash_triage.workspace.<id>``.

        Mirrors ``_dispatch_audit_memo``: the engine's analysis of an
        existing crash artifact (root cause hypothesis, exploitability
        judgement, adjacent-function review) lands in the workspace
        namespace so a future crash-triage consumer can read it.

        Required payload fields (one of):
          - triage_summary
          - claim
          - answer
        Recommended:
          - crash_signature
          - crash_type
          - vulnerable_function
          - evidence_refs
        """
        target_row, _ = await self._load_target_for_investigation(investigation_id)
        summary = str(
            payload.get("triage_summary")
            or payload.get("claim")
            or payload.get("answer")
            or "",
        ).strip()
        if not summary:
            return OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=OutcomeKind.CRASH_TRIAGE_REPORT,
                dispatch_status=OutcomeDispatchStatus.FAILED,
                dispatch_target=None,
                reason="empty_triage_summary",
            )

        workspace_id = target_row.workspace_id
        namespace = f"vr.crash_triage.workspace.{workspace_id}"
        crash_signature = str(payload.get("crash_signature") or "").strip()
        crash_type = str(payload.get("crash_type") or "").strip()
        header_parts: list[str] = []
        if crash_type:
            header_parts.append(f"crash_type={crash_type}")
        if crash_signature:
            header_parts.append(f"signature={crash_signature}")
        header = " ".join(header_parts)
        content = f"{header}\n\n{summary}" if header else summary

        # Dedup on (workspace, target, signature-or-summary-hash). Repeat
        # triage of the same crash overwrites the previous row; distinct
        # crashes (fresh signature or fresh summary) produce new rows.
        dedup_body = (
            crash_signature
            or hashlib.sha256(summary.encode()).hexdigest()[:32]
        )
        dedup_key = f"{workspace_id}|{target_row.id}|{dedup_body}"
        try:
            store_result = await self._knowledge.store(
                namespace=namespace,
                content=content,
                metadata={
                    "investigation_id": investigation_id,
                    "target_id": target_row.id,
                    "workspace_id": workspace_id,
                    "crash_signature": crash_signature or None,
                    "crash_type": crash_type or None,
                    "vulnerable_function": (
                        payload.get("vulnerable_function") or None
                    ),
                    "evidence_refs": payload.get("evidence_refs") or [],
                    "confidence": (
                        outcome.confidence if outcome is not None else None
                    ),
                    "outcome_id": outcome_id,
                },
                dedup_key=dedup_key,
                extract_entities=True,
            )
        except (
            OSError, RuntimeError, TimeoutError, ValueError,
            SQLAlchemyError,
        ) as exc:
            _log.warning(
                "_dispatch_crash_triage_report: store failed inv=%s "
                "outcome=%s err=%s",
                investigation_id, outcome_id, exc,
            )
            return OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=OutcomeKind.CRASH_TRIAGE_REPORT,
                dispatch_status=OutcomeDispatchStatus.FAILED,
                dispatch_target=None,
                reason=f"knowledge_store_failed:{type(exc).__name__}",
            )
        entry_id = store_result.get("entry_id")
        return OutcomeDispatchResult(
            outcome_id=outcome_id,
            outcome_kind=OutcomeKind.CRASH_TRIAGE_REPORT,
            dispatch_status=OutcomeDispatchStatus.DISPATCHED,
            dispatch_target=f"knowledge_entry:{entry_id}",
            reason=(
                f"namespace={namespace} "
                f"operation={store_result.get('operation')}"
            ),
        )

    async def _dispatch_config_delta(
        self,
        outcome_id: str,
        investigation_id: str,
        payload: dict[str, Any],
        outcome: VRInvestigationOutcomeRecord | None,
    ) -> OutcomeDispatchResult:
        """CONFIG_DELTA -> KnowledgeService write under
        ``vr.config_delta.workspace.<id>`` as a *proposal*.

        The payload the engine emits here is UNTYPED and there is no
        safe typed ConfigRegistry.set consumer that could ingest it
        without a schema. Auto-applying arbitrary key/value pairs to
        the config registry would be a live-configuration footgun.

        Instead we record the proposal in the workspace knowledge
        namespace with ``status=proposed``. An operator (or a future
        ConfigDelta review UI) reads the same namespace and applies
        or rejects each proposal explicitly; the dispatcher never
        writes to ConfigRegistry directly from this path.

        Required payload fields:
          - target_key (str)  -- dotted config path the delta names
          - proposed_value    -- new value (any JSON-serializable type)
        Recommended:
          - current_value     -- what the engine observed before
          - rationale         -- why the change is proposed
        """
        target_row, _ = await self._load_target_for_investigation(investigation_id)
        target_key = str(
            payload.get("target_key") or payload.get("key") or "",
        ).strip()
        # NOTE: proposed_value may legitimately be None / False / 0, so
        # we test key presence, not truthiness.
        if not target_key or "proposed_value" not in payload:
            return OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=OutcomeKind.CONFIG_DELTA,
                dispatch_status=OutcomeDispatchStatus.FAILED,
                dispatch_target=None,
                reason="missing_target_key_or_proposed_value",
            )

        workspace_id = target_row.workspace_id
        namespace = f"vr.config_delta.workspace.{workspace_id}"
        proposed_json = json.dumps(
            payload.get("proposed_value"), sort_keys=True, default=str,
        )
        current_json = json.dumps(
            payload.get("current_value"), sort_keys=True, default=str,
        )
        rationale = str(payload.get("rationale") or "")
        content = (
            f"Config delta proposal -- key={target_key}\n"
            f"current={current_json}\n"
            f"proposed={proposed_json}\n"
            f"rationale={rationale}"
        )
        dedup_key = (
            f"{workspace_id}|{target_key}|"
            f"{hashlib.sha256(proposed_json.encode()).hexdigest()[:16]}"
        )
        try:
            store_result = await self._knowledge.store(
                namespace=namespace,
                content=content,
                metadata={
                    "investigation_id": investigation_id,
                    "target_id": target_row.id,
                    "workspace_id": workspace_id,
                    "target_key": target_key,
                    "current_value": payload.get("current_value"),
                    "proposed_value": payload.get("proposed_value"),
                    "rationale": rationale,
                    "confidence": (
                        outcome.confidence if outcome is not None else None
                    ),
                    "outcome_id": outcome_id,
                    # Never auto-applied; an operator flips this to
                    # 'applied' or 'rejected' via the review UI.
                    "status": "proposed",
                },
                dedup_key=dedup_key,
            )
        except (
            OSError, RuntimeError, TimeoutError, ValueError,
            SQLAlchemyError,
        ) as exc:
            _log.warning(
                "_dispatch_config_delta: store failed inv=%s outcome=%s err=%s",
                investigation_id, outcome_id, exc,
            )
            return OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=OutcomeKind.CONFIG_DELTA,
                dispatch_status=OutcomeDispatchStatus.FAILED,
                dispatch_target=None,
                reason=f"knowledge_store_failed:{type(exc).__name__}",
            )
        entry_id = store_result.get("entry_id")
        return OutcomeDispatchResult(
            outcome_id=outcome_id,
            outcome_kind=OutcomeKind.CONFIG_DELTA,
            dispatch_status=OutcomeDispatchStatus.DISPATCHED,
            dispatch_target=f"knowledge_entry:{entry_id}",
            reason=(
                f"namespace={namespace} key={target_key} status=proposed"
            ),
        )

    async def _dispatch_sub_investigation(
        self,
        outcome_id: str,
        investigation_id: str,
        payload: dict[str, Any],
    ) -> OutcomeDispatchResult:
        """SUB_INVESTIGATION -> spawn nested child VRInvestigationRecord.

        Mirrors the malware module's `_dispatch_sub_investigation` plus
        VR's variant-hunt fork-time guards. Two hard limits protect the
        fleet from runaway fan-out:

          - depth cap (``MAX_SUB_INVESTIGATION_DEPTH``, default 2) --
            refuse to spawn once the child would sit deeper in the
            parent chain than the cap allows. A recursive agent that
            keeps emitting SUB_INVESTIGATION outcomes hits this ceiling
            before consuming unbounded worker slots.
          - per-parent fan-out cap
            (``MAX_SUB_INVESTIGATION_PER_PARENT``, default 5) -- refuse
            once a parent already has that many direct children.

        Both guards return SKIPPED (not FAILED) so a legitimate agent
        retry doesn't re-mark the outcome dispatchable.

        Required payload shape::

            {
              "investigation": {
                "target_id": "<vr_target uuid>",
                "kind": "<vr investigation kind>",
                "title": "<child title>",
                # optional
                "initial_question": "...",
                "strategy_family": "vulnerability_research.discovery_research",
                "cost_budget_usd": 25.0,
                "auto_pilot": true,
              }
            }
        """
        _, parent = await self._load_target_for_investigation(investigation_id)

        # Depth guard. parent_depth = ancestor hops above spawning
        # parent; the child sits at parent_depth + 1. Refuse when the
        # child would exceed the cap.
        parent_depth = await self._compute_investigation_depth(investigation_id)
        if parent_depth + 1 > MAX_SUB_INVESTIGATION_DEPTH:
            return OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=OutcomeKind.SUB_INVESTIGATION,
                dispatch_status=OutcomeDispatchStatus.SKIPPED,
                dispatch_target=None,
                reason=(
                    f"sub_investigation_depth_exceeded:"
                    f"parent_depth={parent_depth} "
                    f"max={MAX_SUB_INVESTIGATION_DEPTH}"
                ),
            )

        # Per-parent fan-out cap.
        child_count = await self._count_sub_investigation_children(
            investigation_id,
        )
        if child_count >= MAX_SUB_INVESTIGATION_PER_PARENT:
            return OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=OutcomeKind.SUB_INVESTIGATION,
                dispatch_status=OutcomeDispatchStatus.SKIPPED,
                dispatch_target=None,
                reason=(
                    f"sub_investigation_fanout_exceeded:"
                    f"children={child_count} "
                    f"max={MAX_SUB_INVESTIGATION_PER_PARENT}"
                ),
            )

        spec = payload.get("investigation") or {}
        if not isinstance(spec, dict):
            return OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=OutcomeKind.SUB_INVESTIGATION,
                dispatch_status=OutcomeDispatchStatus.FAILED,
                dispatch_target=None,
                reason="malformed_investigation_spec",
            )
        child_target_id = str(spec.get("target_id") or "").strip()
        child_kind = str(spec.get("kind") or "").strip()
        child_title = str(spec.get("title") or "").strip()
        if not child_target_id or not child_kind or not child_title:
            return OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=OutcomeKind.SUB_INVESTIGATION,
                dispatch_status=OutcomeDispatchStatus.FAILED,
                dispatch_target=None,
                reason="missing_target_id_or_kind_or_title",
            )

        try:
            child_id = await self._spawn_sub_investigation_child(
                parent=parent,
                child_target_id=child_target_id,
                child_kind=child_kind,
                child_title=child_title,
                spec=spec,
            )
        except (
            ValueError, RuntimeError, OSError, TimeoutError,
            SQLAlchemyError,
        ) as exc:
            _log.warning(
                "_dispatch_sub_investigation: spawn failed inv=%s "
                "outcome=%s err=%s",
                investigation_id, outcome_id, exc,
            )
            return OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=OutcomeKind.SUB_INVESTIGATION,
                dispatch_status=OutcomeDispatchStatus.FAILED,
                dispatch_target=None,
                reason=f"spawn_failed:{type(exc).__name__}:{exc}",
            )

        return OutcomeDispatchResult(
            outcome_id=outcome_id,
            outcome_kind=OutcomeKind.SUB_INVESTIGATION,
            dispatch_status=OutcomeDispatchStatus.DISPATCHED,
            dispatch_target=f"vr_investigation:{child_id}",
            reason=(
                f"child_spawned parent={investigation_id} "
                f"depth={parent_depth + 1}"
            ),
        )

    async def _compute_investigation_depth(self, investigation_id: str) -> int:
        """Count ancestor hops above ``investigation_id`` in the parent chain.

        Returns 0 for a root investigation. Follows
        ``parent_investigation_id`` upward one hop at a time; cycle-safe
        (a self-referential or looped chain terminates once a repeat is
        observed).
        """
        depth = 0
        cur: str | None = investigation_id
        seen: set[str] = set()
        async with UnitOfWork() as uow:
            while cur is not None:
                if cur in seen:
                    break
                seen.add(cur)
                row = (await uow.session.exec(
                    _select(VRInvestigationRecord).where(
                        VRInvestigationRecord.id == cur,
                    ),
                )).first()
                if row is None or not row.parent_investigation_id:
                    break
                depth += 1
                cur = row.parent_investigation_id
        return depth

    async def _count_sub_investigation_children(
        self, investigation_id: str,
    ) -> int:
        """Count direct children whose ``parent_investigation_id`` equals
        the given id. Used to enforce the per-parent fan-out cap."""
        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                _select(VRInvestigationRecord.id).where(
                    VRInvestigationRecord.parent_investigation_id
                    == investigation_id,
                ),
            )).all()
            return len(rows)

    async def _spawn_sub_investigation_child(
        self,
        *,
        parent: VRInvestigationRecord,
        child_target_id: str,
        child_kind: str,
        child_title: str,
        spec: dict[str, Any],
    ) -> str:
        """Create the child VRInvestigationRecord + its primary branch
        and enqueue ``run_vr_investigate`` against it.

        Returns the new investigation id. Enqueue failure is logged
        (not raised) so the child row still lands and ``stall_recovery``
        (or an operator retrigger) can pick it up later, mirroring
        ``_spawn_variant_child``'s best-effort enqueue.
        """
        parent_budget = float(parent.cost_budget_usd or 5.0)
        child_budget = float(
            spec.get("cost_budget_usd") or (parent_budget * 0.5),
        )
        if child_budget < 5.0:
            child_budget = 5.0
        strategy_family = str(
            spec.get("strategy_family")
            or "vulnerability_research.discovery_research",
        )[:64]
        initial_question = str(spec.get("initial_question") or "")
        auto_pilot = bool(spec.get("auto_pilot", parent.auto_pilot))

        async with UnitOfWork() as uow:
            child = VRInvestigationRecord(
                target_id=child_target_id,
                team_id=parent.team_id,
                parent_investigation_id=parent.id,
                kind=child_kind[:32],
                title=child_title[:255],
                initial_question=initial_question,
                status=InvestigationStatus.CREATED.value,
                auto_pilot=auto_pilot,
                strategy_family=strategy_family,
                cost_budget_usd=child_budget,
            )
            uow.session.add(child)
            await uow.session.flush()
            primary_branch = VRInvestigationBranchRecord(
                investigation_id=child.id,
                status="active",
                fork_reason="sub_investigation_primary",
            )
            uow.session.add(primary_branch)
            await uow.session.commit()
            await uow.session.refresh(child)
            child_id = child.id
            child_team_id = child.team_id

        # Best-effort enqueue. If it fails, the row is queryable and
        # stall_recovery / operator resume covers the gap. Same shape
        # as _spawn_variant_child's enqueue call.
        try:
            from aila.modules.vr.workflow.task import run_vr_investigate
            task_queue = self._task_queue_factory()
            await task_queue.submit(
                track="vr",
                fn=run_vr_investigate,
                kwargs={"investigation_id": child_id},
                user_id="system",
                group_id="vr_sub_investigation",
                team_id=child_team_id,
            )
        except (OSError, RuntimeError, TimeoutError, ImportError) as exc:
            _log.warning(
                "_spawn_sub_investigation_child: enqueue failed child=%s err=%s",
                child_id, exc,
            )
        return child_id

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

    async def _persist_dispatch_status(
        self,
        *,
        outcome_id: str,
        result: OutcomeDispatchResult,
    ) -> None:
        """Write the terminal dispatch status + cross-row cascade.

        Overrides the base's minimal writer to add the VR-specific
        cascade: on DISPATCHED, halt every sibling active branch that
        was still churning on the same question, flip the parent
        investigation to COMPLETED when no active branch remains, and
        purge every ARQ job the investigation had queued (with a
        short retry loop for transient Redis blips).
        """
        del outcome_id
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
                # fix §20 -- single point for outcome.state writes.
                # set_outcome_state adds the audit-trail row (and
                # this outcome row) to the session; we still need
                # the explicit session.add for the dispatch_status /
                # dispatch_target columns we set above when this
                # call is a no-op state-wise.
                set_outcome_state(
                    uow,
                    outcome,
                    OUTCOME_STATE_DISPATCHED,
                    reason=f"dispatched_by_outcome_dispatcher:{result.dispatch_target or '?'}",
                )
            else:
                # state unchanged -- still persist the dispatch_status
                # / dispatch_target updates from the lines above.
                uow.session.add(outcome)

            # When an outcome successfully dispatches, the investigation
            # has reached its goal -- any remaining active sibling
            # branches should stop burning turns on a question already
            # answered. Halt them + flip the investigation to COMPLETED
            # when no branches remain active.
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
                        # fix §22 -- single chokepoint for the status
                        # transition. Phase B will replace the direct
                        # write with a workflow-engine transition call;
                        # in the meantime route every COMPLETED write
                        # through this helper so Phase B is a one-line
                        # swap. The dispatcher MUST NOT remain the
                        # writer of investigation.status per the SSOT
                        # contract -- engine state handlers own it.
                        await self._mark_investigation_completed(uow, inv)
                        _log.info(
                            "outcome_dispatcher COMPLETE investigation=%s "
                            "(dispatched, no active branches remain)",
                            investigation_id,
                        )
            await uow.commit()

        # fix §104 -- ARQ purge happens after the UoW commit. The purge
        # touches Redis, not Postgres, so we can't include it in the
        # SQLAlchemy transaction. Partial-failure semantics:
        #   1. DB commit succeeded → investigation row reads COMPLETED.
        #   2. Purge can fail (Redis unreachable, transient ARQ format
        #      change). We retry up to 3× with exponential backoff so
        #      a transient Redis blip doesn't leak siblings into the
        #      queue for a completed investigation.
        #   3. If all retries fail, log a WARNING and move on. The
        #      reactive guard in investigation_setup.py is the safety
        #      net: when a worker dequeues a job for a completed
        #      investigation, it exits with STATUS_LOCKED instead of
        #      doing real work. Cost: one wasted dequeue per leaked
        #      job, not unbounded re-runs.
        if just_dispatched:
            await self._purge_arq_with_retry(outcome.investigation_id)

    async def _mark_investigation_completed(
        self,
        uow: UnitOfWork,
        inv: VRInvestigationRecord,
    ) -> None:
        """Single chokepoint for COMPLETED status writes (fix §22).

        Today this is a direct ORM mutation, identical to the inline
        write it replaced. Phase B will replace the body with a call
        into the workflow engine's transition API so the dispatcher
        no longer writes investigation status -- engine state handlers
        own that field per the SSOT contract. Keeping the call site
        in one place means Phase B is a one-line swap, not a hunt for
        every COMPLETED writer in the dispatcher.
        """

        now = utc_now()
        inv.status = InvestigationStatus.COMPLETED.value
        inv.stopped_at = now
        inv.updated_at = now
        uow.session.add(inv)
        # Phase C surgical (BLOCK fix): keep branches projection in
        # lockstep with the inv terminal flip. See
        # aila.platform.services.branch_cleanup.
        await close_orphan_branches_on_terminal(
            uow, inv.id, branch_table="vr_investigation_branches",
            reason="investigation_completed", now=now,
        )

    async def _purge_arq_with_retry(
        self,
        investigation_id: str,
        *,
        attempts: int = 3,
    ) -> None:
        """Purge ARQ jobs for ``investigation_id`` with retry on transient errors."""

        for attempt in range(1, attempts + 1):
            try:
                purged = await purge_arq_jobs_for_investigation(
                    investigation_id, track="vr",
                )
                if purged.get("purged_jobs", 0) > 0:
                    _log.info(
                        "outcome_dispatcher ARQ_PURGE inv=%s purged=%d attempt=%d",
                        investigation_id, purged["purged_jobs"], attempt,
                    )
                return
            except (OSError, RuntimeError, ImportError) as exc:
                if attempt == attempts:
                    _log.warning(
                        "outcome_dispatcher ARQ_PURGE giving up inv=%s "
                        "attempt=%d/%d err=%s -- investigation_setup safety net "
                        "catches any leaked dequeues",
                        investigation_id, attempt, attempts, exc,
                    )
                    return
                _log.info(
                    "outcome_dispatcher ARQ_PURGE retry inv=%s attempt=%d/%d err=%s",
                    investigation_id, attempt, attempts, exc,
                )
                # Exponential backoff: 0.1s, 0.2s, 0.4s ...
                await asyncio.sleep(0.1 * (2 ** (attempt - 1)))


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
        # No region descriptor -- fall back to a random sig so multiple
        # audit memos against the same target don't dedup over each other.
        return f"{target_id}|{uuid4()}"
    return hashlib.sha256(raw).hexdigest()
