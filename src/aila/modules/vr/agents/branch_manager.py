"""Branch manager (M3.R-5).

Implements the 6 D-41 branch operations on an investigation's branch
tree:

  fork      — spawn a new ACTIVE branch from a parent. New branch
              inherits parent's case_state snapshot + optional persona
              voice + fork_reason. Parent stays ACTIVE.
  merge     — consolidate two ACTIVE branches into a new ACTIVE branch.
              Both originals → MERGED with merged_into_branch_id set.
              New branch's case_state = absorb(absorb(empty, a), b).
  promote   — mark a branch as the authoritative one. Sibling ACTIVE
              branches transition to ABANDONED with reason.
  abandon   — close a branch without promotion. Status → ABANDONED,
              closed_at + closed_reason set.
  pause     — temporarily stop driving the branch. Status → PAUSED.
  resume    — re-activate a PAUSED branch. Status → ACTIVE.

This module owns ONLY the state transitions. The investigation_loop
state in workflow/states/ still drives turns; in v1 it drives only the
primary branch. Multi-branch driving (loop iterates all ACTIVE branches
per cycle) is a follow-up — schema + operations support it now.

Per the no-overengineering rule: case-state merging on merge() is
intentionally simple — the CyberReasoningEngine.absorb() method is
sequential per-decision; merging two static states is approximated by
hypothesis union + rejected union + observable update. If a real
investigation produces a merge that's lossy, refine then.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlmodel import select as _select

from aila.modules.vr.contracts.branch import BranchOperation, BranchStatus
from aila.modules.vr.contracts.investigation import InvestigationStatus
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
)
from aila.platform.contracts._common import utc_now
from aila.platform.contracts.reasoning import (
    Hypothesis,
    ReasoningCaseState,
    ReasoningContract,
    RejectedHypothesis,
)
from aila.platform.uow import UnitOfWork

__all__ = [
    "BranchManager",
    "BranchManagerError",
    "BranchOpResult",
]

_log = logging.getLogger(__name__)

# fix §149 — per-investigation branch cap. 24 = 6 personas * 4 fork
# generations, comfortable headroom for legitimate operator branching
# without permitting runaway fork-bombs (each fork enqueues one ARQ
# task; uncapped fork cycles can exhaust the worker pool). Operator-
# tunable via VR_MAX_BRANCHES_PER_INVESTIGATION at process start.
_DEFAULT_MAX_BRANCHES_PER_INVESTIGATION = 24


def _max_branches_per_investigation() -> int:
    raw = os.environ.get("VR_MAX_BRANCHES_PER_INVESTIGATION")
    if not raw:
        return _DEFAULT_MAX_BRANCHES_PER_INVESTIGATION
    try:
        parsed = int(raw)
    except ValueError:
        return _DEFAULT_MAX_BRANCHES_PER_INVESTIGATION
    # Floor at 1 so a typo doesn't disable forking entirely; the cap
    # itself is operator policy, but a 0/negative cap is almost
    # certainly a config mistake (and would brick auto_deliberation).
    return max(1, parsed)


@dataclass(slots=True)
class BranchOpResult:
    """Result of one branch operation."""

    op: BranchOperation
    investigation_id: str
    primary_branch_id: str
    new_branch_id: str | None = None
    affected_branch_ids: list[str] | None = None
    reason: str = ""


class BranchManagerError(Exception):
    """Raised on illegal branch transitions (wrong status, missing branch)."""


class BranchManager:
    """Per-investigation branch tree operations.

    Each operation is one async method that opens a UnitOfWork,
    performs the transition atomically, and returns a
    ``BranchOpResult``. All transitions enforce status guards — calling
    promote on an ABANDONED branch raises BranchManagerError rather
    than silently no-op.
    """

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id

    async def fork(
        self,
        parent_branch_id: str,
        *,
        persona_voice: str | None = None,
        fork_reason: str = "",
        at_turn: int | None = None,
    ) -> BranchOpResult:
        """Spawn a new ACTIVE branch from ``parent_branch_id``."""
        # fix §178 — default to a known marker so the frontend (and §180
        # NOT NULL alembic migration) never sees a null persona_voice.
        # Callers that supply a persona (auto_deliberation, operator
        # picker) keep their value; callers that don't (older API
        # paths) get a grep-able structural marker instead of NULL.
        if not persona_voice or not persona_voice.strip():
            persona_voice = "fork_unnamed"
        async with UnitOfWork() as uow:
            # fix §149 — branch count cap. Counts ACTIVE branches
            # (terminal-status rows do not contribute to fork pressure)
            # and refuses the fork above the cap. The cap is enforced
            # inside the UoW so concurrent forks racing on the same
            # investigation see each other's PENDING inserts after the
            # first commit. Without it, an operator (or runaway agent)
            # could fork-bomb one investigation into hundreds of
            # branches, each consuming an ARQ task slot.
            cap = _max_branches_per_investigation()
            active_rows = (await uow.session.exec(
                _select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.investigation_id
                    == self.investigation_id,
                    VRInvestigationBranchRecord.status
                    == BranchStatus.ACTIVE.value,
                ),
            )).all()
            if len(active_rows) >= cap:
                raise BranchManagerError(
                    f"branch count cap exceeded: {cap} active branches "
                    f"on investigation {self.investigation_id} "
                    f"(tune via VR_MAX_BRANCHES_PER_INVESTIGATION)",
                )

            parent = await self._load_branch(uow, parent_branch_id, for_update=True)
            if parent.status != BranchStatus.ACTIVE.value:
                raise BranchManagerError(
                    f"cannot fork from branch {parent_branch_id} in status "
                    f"{parent.status!r} — only ACTIVE branches are forkable",
                )

            child = VRInvestigationBranchRecord(
                investigation_id=self.investigation_id,
                parent_branch_id=parent_branch_id,
                status=BranchStatus.ACTIVE.value,
                persona_voice=persona_voice,
                fork_reason=fork_reason,
                fork_at_turn=at_turn,
                # fix §112 — strip parent's rejected/resolved hypothesis
                # bookkeeping from the forked copy. Carrying these
                # forward verbatim caused sibling-consensus rejection
                # (vuln_researcher) to count each branch's rejections
                # independently — the child never learned the parent
                # had killed h7, so both branches re-walked the dead
                # end. The child re-derives rejection from its own
                # evidence stream if its turns lead there.
                case_state_json=_strip_rejected_from_state(
                    _strip_directives_from_state(parent.case_state_json or "{}"),
                ),
                turn_count=0,
                branch_cost_usd=0.0,
            )
            uow.session.add(child)
            await uow.session.flush()
            await uow.commit()

            return BranchOpResult(
                op=BranchOperation.FORK,
                investigation_id=self.investigation_id,
                primary_branch_id=parent_branch_id,
                new_branch_id=child.id,
                affected_branch_ids=[parent_branch_id],
                reason=fork_reason,
            )

    async def merge(
        self,
        branch_a_id: str,
        branch_b_id: str,
        *,
        merge_reason: str = "",
    ) -> BranchOpResult:
        """Consolidate two ACTIVE branches into a new ACTIVE branch."""
        if branch_a_id == branch_b_id:
            raise BranchManagerError(
                "cannot merge a branch with itself",
            )

        async with UnitOfWork() as uow:
            a = await self._load_branch(uow, branch_a_id, for_update=True)
            b = await self._load_branch(uow, branch_b_id, for_update=True)
            for branch in (a, b):
                if branch.status != BranchStatus.ACTIVE.value:
                    raise BranchManagerError(
                        f"cannot merge branch {branch.id} in status {branch.status!r}"
                        f" — only ACTIVE branches are mergeable",
                    )
                if branch.investigation_id != self.investigation_id:
                    raise BranchManagerError(
                        f"branch {branch.id} does not belong to investigation "
                        f"{self.investigation_id}",
                    )

            merged_state = _merge_case_states(
                _decode(a.case_state_json), _decode(b.case_state_json),
            )

            # fix §115 — preserve lineage. Pick branch A's parent first
            # (deterministic on argument order); fall back to B's parent
            # if A was a root. Result: the branch tree UI walks from
            # the merged child back to a real ancestor instead of
            # rendering it as an orphan new root next to a/b.
            # Closes §40 (speculative survivor-pointer note) as a
            # side-effect — same code path.
            inherited_parent = a.parent_branch_id or b.parent_branch_id

            merged = VRInvestigationBranchRecord(
                investigation_id=self.investigation_id,
                parent_branch_id=inherited_parent,
                status=BranchStatus.ACTIVE.value,
                persona_voice="merge_result",  # fix §177 — structural marker, never null
                fork_reason=f"merge: {merge_reason}" if merge_reason else "merge",
                case_state_json=_encode(merged_state),
                # fix §113 — turn_count carries the higher of the two
                # source histories. The merged branch "inherits" A+B's
                # reasoning depth so subsequent turn-cap checks see
                # the inflated value. This is INTENTIONAL: a merged
                # branch starting at turn 0 would let the operator
                # bypass per-branch turn caps by merging then forking.
                # max() preserves the cap's intent (work-done depth)
                # without double-counting like a + b would.
                turn_count=max(a.turn_count, b.turn_count),
                # fix §114 — cost moves to the survivor. Source-branch
                # costs are zeroed below so the investigation-level
                # sum (Σ branches.branch_cost_usd) reads
                # (a + b) + 0 + 0 = (a + b) instead of double-counted
                # (a + b) + a + b = 2*(a + b).
                branch_cost_usd=a.branch_cost_usd + b.branch_cost_usd,
            )
            uow.session.add(merged)
            await uow.session.flush()

            now = utc_now()
            for branch in (a, b):
                branch.merged_into_branch_id = merged.id
                branch.closed_reason = merge_reason or "merged"
                branch.closed_at = now
                # fix §114 — zero source-branch costs after transfer.
                # The cost is now carried solely by ``merged``; the
                # investigation-total aggregator sums all branches
                # naively and would otherwise double-count.
                branch.branch_cost_usd = 0.0
                # fix §21 — status write routed through chokepoint.
                self._emit_branch_status_event(
                    uow, branch, BranchStatus.MERGED,
                    reason=merge_reason or "merged", at=now,
                )
            await uow.commit()

            return BranchOpResult(
                op=BranchOperation.MERGE,
                investigation_id=self.investigation_id,
                primary_branch_id=merged.id,
                new_branch_id=merged.id,
                affected_branch_ids=[branch_a_id, branch_b_id],
                reason=merge_reason,
            )

    async def promote(
        self,
        branch_id: str,
        *,
        reason: str = "",
    ) -> BranchOpResult:
        """Mark branch as authoritative; sibling ACTIVE branches → ABANDONED."""
        async with UnitOfWork() as uow:
            branch = await self._load_branch(uow, branch_id, for_update=True)
            if branch.status not in {
                BranchStatus.ACTIVE.value, BranchStatus.PAUSED.value,
            }:
                raise BranchManagerError(
                    f"cannot promote branch {branch_id} in status {branch.status!r}",
                )

            siblings = (await uow.session.exec(
                _select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.investigation_id == self.investigation_id,
                    VRInvestigationBranchRecord.id != branch_id,
                    VRInvestigationBranchRecord.status.in_([
                        BranchStatus.ACTIVE.value, BranchStatus.PAUSED.value,
                    ]),
                ).with_for_update()
            )).all()

            now = utc_now()
            branch.promoted = True
            branch.closed_reason = reason or "promoted"
            branch.closed_at = now
            # fix §21 — status write routed through chokepoint.
            self._emit_branch_status_event(
                uow, branch, BranchStatus.PROMOTED,
                reason=reason or "promoted", at=now,
            )

            affected: list[str] = [branch_id]
            for sib in siblings:
                sib.closed_reason = f"superseded by promoted branch {branch_id}"
                sib.closed_at = now
                # fix §21 — status write routed through chokepoint.
                self._emit_branch_status_event(
                    uow, sib, BranchStatus.ABANDONED,
                    reason=sib.closed_reason, at=now,
                )
                affected.append(sib.id)
            await uow.commit()

            return BranchOpResult(
                op=BranchOperation.PROMOTE,
                investigation_id=self.investigation_id,
                primary_branch_id=branch_id,
                affected_branch_ids=affected,
                reason=reason,
            )

    async def abandon(
        self,
        branch_id: str,
        *,
        reason: str = "",
    ) -> BranchOpResult:
        """Close a branch without promotion."""
        async with UnitOfWork() as uow:
            branch = await self._load_branch(uow, branch_id, for_update=True)
            if branch.status in {
                BranchStatus.MERGED.value,
                BranchStatus.PROMOTED.value,
                BranchStatus.ABANDONED.value,
            }:
                raise BranchManagerError(
                    f"cannot abandon branch {branch_id} in terminal status {branch.status!r}",
                )

            now = utc_now()
            branch.closed_reason = reason or "abandoned by operator"
            branch.closed_at = now
            # fix §21 — status write routed through chokepoint.
            self._emit_branch_status_event(
                uow, branch, BranchStatus.ABANDONED,
                reason=branch.closed_reason, at=now,
            )
            await uow.commit()

            return BranchOpResult(
                op=BranchOperation.ABANDON,
                investigation_id=self.investigation_id,
                primary_branch_id=branch_id,
                reason=reason,
            )

    async def pause(
        self,
        branch_id: str,
        *,
        reason: str = "",
    ) -> BranchOpResult:
        """Temporarily stop driving the branch."""
        async with UnitOfWork() as uow:
            # fix §64 — refuse to pause under a terminal investigation.
            # Without this guard an operator can pause a branch under
            # a COMPLETED/FAILED/ABANDONED investigation, leaving an
            # orphan PAUSED branch the reaper skips and resume()
            # cannot wake (because the engine never re-enqueues for a
            # terminal investigation per fix §39). The branch then
            # sits PAUSED forever.
            inv = await self._load_parent_investigation(uow)
            if inv.status in {
                InvestigationStatus.COMPLETED.value,
                InvestigationStatus.FAILED.value,
                InvestigationStatus.ABANDONED.value,
            }:
                raise BranchManagerError(
                    f"cannot pause branch on {inv.status!r} investigation "
                    f"{self.investigation_id} — branch would orphan",
                )

            branch = await self._load_branch(uow, branch_id)
            if branch.status != BranchStatus.ACTIVE.value:
                raise BranchManagerError(
                    f"cannot pause branch {branch_id} in status {branch.status!r} — must be ACTIVE",
                )
            # fix §21 — status write routed through chokepoint.
            self._emit_branch_status_event(
                uow, branch, BranchStatus.PAUSED, reason=reason,
            )
            await uow.commit()

            return BranchOpResult(
                op=BranchOperation.PAUSE,
                investigation_id=self.investigation_id,
                primary_branch_id=branch_id,
                reason=reason,
            )

    async def resume(
        self,
        branch_id: str,
        *,
        reason: str = "",
    ) -> BranchOpResult:
        """Re-activate a PAUSED branch."""
        async with UnitOfWork() as uow:
            branch = await self._load_branch(uow, branch_id)
            if branch.status != BranchStatus.PAUSED.value:
                raise BranchManagerError(
                    f"cannot resume branch {branch_id} in status {branch.status!r} — must be PAUSED",
                )
            # fix §21 — status write routed through chokepoint.
            self._emit_branch_status_event(
                uow, branch, BranchStatus.ACTIVE, reason=reason,
            )
            await uow.commit()

            return BranchOpResult(
                op=BranchOperation.RESUME,
                investigation_id=self.investigation_id,
                primary_branch_id=branch_id,
                reason=reason,
            )

    async def spawn_strategy(
        self,
        *,
        strategy_family: str,
        persona_voice: str | None = None,
        rationale: str = "",
        parent_branch_id: str | None = None,
    ) -> BranchOpResult:
        """Spawn a new branch tagged with a strategy_family (v0.4 GA-50).

        Used by the multi-strategy orchestration flow: one investigation
        can carry N strategy branches running in parallel
        (discovery_research + variant_hunt + patch_diff_analysis).

        Differs from fork():
          - parent_branch_id is OPTIONAL — the new branch can start from
            the investigation root (no parent) for genuinely parallel
            strategies that don't share state.
          - strategy_family is REQUIRED and gets tagged on the new row
            for per-turn strategy dispatch.
          - When parent_branch_id is set, copies the parent's case_state
            (same as fork) so the new branch inherits observables /
            hypotheses.
        """
        if not strategy_family or not strategy_family.strip():
            raise BranchManagerError(
                "strategy_family is required for spawn_strategy",
            )

        async with UnitOfWork() as uow:
            inherited_case_state = "{}"
            parent_at_turn: int | None = None
            if parent_branch_id:
                parent = await self._load_branch(uow, parent_branch_id)
                if parent.status != BranchStatus.ACTIVE.value:
                    raise BranchManagerError(
                        f"cannot spawn from parent {parent_branch_id} in "
                        f"status {parent.status!r} — must be ACTIVE",
                    )
                inherited_case_state = _strip_directives_from_state(parent.case_state_json or "{}")
                parent_at_turn = parent.turn_count

            child = VRInvestigationBranchRecord(
                investigation_id=self.investigation_id,
                parent_branch_id=parent_branch_id,
                status=BranchStatus.ACTIVE.value,
                persona_voice=persona_voice,
                strategy_family=strategy_family,
                fork_reason=rationale or f"spawn_strategy:{strategy_family}",
                fork_at_turn=parent_at_turn,
                case_state_json=inherited_case_state,
                turn_count=0,
                branch_cost_usd=0.0,
            )
            uow.session.add(child)
            await uow.session.flush()
            await uow.commit()

            return BranchOpResult(
                op=BranchOperation.SPAWN_STRATEGY,
                investigation_id=self.investigation_id,
                primary_branch_id=parent_branch_id or child.id,
                new_branch_id=child.id,
                affected_branch_ids=(
                    [parent_branch_id] if parent_branch_id else []
                ),
                reason=rationale,
            )

    async def list_active_by_strategy(
        self,
    ) -> dict[str, list[str]]:
        """Return active branches grouped by strategy_family.

        Branches without a strategy_family (v0.3 legacy single-strategy
        investigations) are grouped under the empty-string key for
        backward compatibility.
        """
        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                _select(VRInvestigationBranchRecord)
                .where(
                    VRInvestigationBranchRecord.investigation_id == self.investigation_id,
                    VRInvestigationBranchRecord.status == BranchStatus.ACTIVE.value,
                )
                .order_by(VRInvestigationBranchRecord.created_at.asc()),
            )).all()

        groups: dict[str, list[str]] = {}
        for row in rows:
            key = row.strategy_family or ""
            groups.setdefault(key, []).append(row.id)
        return groups

    async def _load_branch(
        self, uow: Any, branch_id: str, *, for_update: bool = False,
    ) -> VRInvestigationBranchRecord:
        stmt = _select(VRInvestigationBranchRecord).where(
            VRInvestigationBranchRecord.id == branch_id,
        )
        if for_update:
            stmt = stmt.with_for_update()
        branch = (await uow.session.exec(stmt)).first()
        if branch is None:
            raise BranchManagerError(f"branch {branch_id} not found")
        if branch.investigation_id != self.investigation_id:
            raise BranchManagerError(
                f"branch {branch_id} does not belong to investigation "
                f"{self.investigation_id}",
            )
        return branch

    async def _load_parent_investigation(
        self, uow: Any,
    ) -> VRInvestigationRecord:
        """Load the parent VRInvestigationRecord for this manager (fix §64).

        Used by pause() to refuse pausing under a terminal investigation.
        No FOR UPDATE — the check is advisory (a race where the
        investigation flips terminal between this read and the branch
        write is harmless: the branch becomes a PAUSED orphan that
        Phase B's reaper will sweep, same outcome as the current
        codebase has without this guard).
        """
        inv = (await uow.session.exec(
            _select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == self.investigation_id,
            ),
        )).first()
        if inv is None:
            raise BranchManagerError(
                f"investigation {self.investigation_id} not found",
            )
        return inv

    def _emit_branch_status_event(
        self,
        uow: Any,
        branch: VRInvestigationBranchRecord,
        new_status: BranchStatus,
        *,
        reason: str = "",
        at: datetime | None = None,
    ) -> None:
        """Single chokepoint for branch.status transitions (fix §21).

        Today this is a direct ORM mutation — identical to the inline
        ``branch.status = …`` writes it replaced. Phase B will swap
        the body for a workflow-engine transition call so branch.status
        gains the same SSOT discipline investigation.status has: no
        parallel writers, every flip landing an audit-trail row +
        cursor advance atomically.

        Routing every write through one helper means Phase B is a
        one-line swap, not a hunt across 5 methods. Same chokepoint
        pattern as outcome_dispatcher._mark_investigation_completed
        (fix §22, sibling helper at the investigation layer).

        ``reason`` is captured for the future audit row; today it
        flows into a debug log only. ``at`` lets the caller fix a
        single ``now`` across multiple status writes in one txn
        (e.g. promote() updates one chosen branch + N siblings; all
        of them should land the same closed_at / updated_at value).
        """
        now = at if at is not None else utc_now()
        branch.status = new_status.value
        branch.updated_at = now
        uow.session.add(branch)
        _log.debug(
            "branch_status_event branch=%s investigation=%s "
            "new_status=%s reason=%s",
            branch.id, self.investigation_id, new_status.value, reason,
        )

def _strip_directives_from_state(raw_json: str) -> str:
    """Strip ``_directive.*`` observables from a case_state JSON blob.

    Used at fork time: children should start with a clean directive
    slate, not inherit the parent's pivot/steering. Otherwise spawning
    3 sibling personas at the moment the parent's pivot directive is
    active causes all 3 children to render '*** PIVOT REQUIRED ***' on
    their turn 0, before they've made any tool calls of their own.
    """
    if not raw_json:
        return raw_json
    try:
        data = json.loads(raw_json)
    except (ValueError, TypeError):
        return raw_json
    obs = data.get("observables")
    if not isinstance(obs, dict):
        return raw_json
    data["observables"] = {
        k: v for k, v in obs.items() if not str(k).startswith("_directive.")
    }
    return json.dumps(data)

def _strip_rejected_from_state(raw_json: str) -> str:
    """Strip ``rejected`` + ``resolved`` hypothesis lists from a case_state JSON blob.

    Used at fork time (fix §112): rejected/resolved hypothesis lists
    are parent-branch bookkeeping. Copying them verbatim to the child
    makes sibling-consensus rejection (vuln_researcher) count each
    branch's rejections independently, so a hypothesis the parent
    killed stays live in the child until the child happens to reject
    it on its own. Worse: both branches then burn turns re-deriving
    the same dead end. The fix is to start the child with empty
    rejected/resolved lists; it re-derives rejection from its own
    evidence if/when its turns reach that conclusion.

    Live ``hypotheses`` are kept — those are the parent's open
    investigative threads the child legitimately inherits and may
    continue working on (or independently reject).
    """
    if not raw_json:
        return raw_json
    try:
        data = json.loads(raw_json)
    except (ValueError, TypeError):
        return raw_json
    if isinstance(data.get("rejected"), list):
        data["rejected"] = []
    if isinstance(data.get("resolved"), list):
        data["resolved"] = []
    return json.dumps(data)


def _decode(raw_json: str | None) -> ReasoningCaseState:
    """Decode a branch.case_state_json column into ReasoningCaseState."""
    if not raw_json:
        return ReasoningCaseState()
    try:
        return ReasoningCaseState.model_validate_json(raw_json)
    except (ValueError, TypeError):
        return ReasoningCaseState()


def _encode(state: ReasoningCaseState) -> str:
    """Encode ReasoningCaseState back to JSON for the column."""
    return json.dumps(state.model_dump(mode="json"))


def merge_hypotheses(
    a: list[Hypothesis], b: list[Hypothesis],
) -> list[Hypothesis]:
    """Union of two hypothesis lists by id (later entries win on dup)."""
    by_id: dict[str, Hypothesis] = {h.id: h for h in a}
    for h in b:
        by_id[h.id] = h
    return list(by_id.values())


def merge_rejected(
    a: list[RejectedHypothesis], b: list[RejectedHypothesis],
) -> list[RejectedHypothesis]:
    """Union of two rejected-hypothesis lists by id."""
    by_id: dict[str, RejectedHypothesis] = {h.id: h for h in a}
    for h in b:
        by_id[h.id] = h
    return list(by_id.values())


def _merge_case_states(
    a: ReasoningCaseState, b: ReasoningCaseState,
) -> ReasoningCaseState:
    """Merge two case states for branch merge.

    Contract: prefer the more-specific (non-default) contract.
    Hypotheses + rejected: id-union (later wins on duplicate id).
    Observables: dict union (b wins on key conflict).
    """
    contract = a.contract
    if not _has_contract(contract) and _has_contract(b.contract):
        contract = b.contract

    return ReasoningCaseState(
        contract=contract,
        hypotheses=merge_hypotheses(a.hypotheses, b.hypotheses),
        rejected=merge_rejected(a.rejected, b.rejected),
        observables={**a.observables, **b.observables},
    )


def _has_contract(c: ReasoningContract) -> bool:
    return bool(c.answer_type) or bool(c.answer_format) or bool(c.evidence_domain)
