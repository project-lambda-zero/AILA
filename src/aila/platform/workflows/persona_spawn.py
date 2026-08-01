"""Platform persona sibling spawn (RFC-02 Phase 3).

Two-phase atomic spawn of one branch per persona for an investigation,
extracted from the vr and malware setup states (which were a
byte-identical ``s/vr/malware/`` copy). The module binds its concrete
branch model, table names, persona tuple, task function, ARQ track and
group, and the case_state strip composition; the platform never names a
module.

Phase 1 (atomic UnitOfWork, one commit): lock the inv row so parallel
spawn ticks serialize; group every existing branch by persona and pick
the winner (an ``operator_reopen:`` branch always wins, then highest
turn_count, then newest); reactivate the winner to a fresh slot
(turn_count 0, stripped case_state, prior messages deleted so the
tool-failure breaker starts clean); abandon duplicates; and INSERT a
branch for every persona without one. Any raise rolls the whole panel
back -- either all siblings resolve to a stable id or none do.

Phase 2 (best-effort): submit one worker task per resolved branch. A
single enqueue failure logs and continues because the branch row
already persists from phase 1, so a reaper-on-cursor sweep can resubmit
it. An empty ``siblings`` tuple is a valid no-op for single-agent
modules.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from sqlalchemy import text as _sql_text
from sqlmodel import select as _select

from aila.platform.contracts import utc_now
from aila.platform.exceptions import WorkerUnreachableError
from aila.platform.uow import UnitOfWork

if TYPE_CHECKING:
    from aila.platform.eval.routing_learner import RoutingRecommendation

_log = logging.getLogger(__name__)

# Minimum evidence multiplier the sizing-hint consumer requires before
# it takes the recommendation seriously enough to cap siblings. The
# learner's own ``min_evidence_per_task_type`` guards each task_type
# individually; this second gate scales with panel width so a
# 3-persona panel with 12 samples on the top task_type gets the
# capped spawn while a 3-persona panel with only 6 samples spawns
# everyone. Kept module-level so a test can monkey-patch it.
_SIZING_HINT_EVIDENCE_MULTIPLIER: int = 4
# Minimum absolute score the top-ranked task_type must clear before the
# sizing hint reduces sibling count. Below this the router treats the
# recommendation as "no clear winner" and spawns the full panel; the
# learner's cost-weight-penalised score is bounded on [-1, 1] so a
# 0.5 floor is comfortably above chance.
_SIZING_HINT_MIN_TOP_SCORE: float = 0.5

__all__ = [
    "SiblingSpawnResult",
    "spawn_persona_siblings",
    "spawn_specialist_branch",
]


@dataclass(frozen=True)
class SiblingSpawnResult:
    """Outcome of one spawn call, for logging and tests."""

    reactivated: list[str] = field(default_factory=list)
    inserted: list[str] = field(default_factory=list)
    abandoned: list[str] = field(default_factory=list)
    enqueued: list[str] = field(default_factory=list)


def _cap_siblings_by_sizing_hint(
    siblings: tuple[Any, ...],
    sizing_hint: RoutingRecommendation | None,
) -> tuple[Any, ...]:
    """Reduce ``siblings`` when the routing recommendation is confident.

    Returns ``siblings`` unchanged when:
      * ``sizing_hint`` is None (caller has no evidence),
      * the hint carries fewer than ``_SIZING_HINT_EVIDENCE_MULTIPLIER *
        len(siblings)`` total samples (evidence too thin to prune),
      * the top task_type score is below
        :data:`_SIZING_HINT_MIN_TOP_SCORE` (no clear winner),
      * the persona tuple is already 1 or empty (nothing to cap).

    Otherwise caps the returned tuple to the top ``ceil(len(siblings)/2)``
    personas by position, on the assumption that the persona tuple is
    ordered by module convention with the most-signal-carrying voices
    first. This is a conservative sizing consumer -- it never spawns
    ZERO siblings (leaves at least one non-primary voice) and never
    increases the caller's original list.
    """
    if sizing_hint is None or len(siblings) <= 1:
        return siblings
    if sizing_hint.total_samples < _SIZING_HINT_EVIDENCE_MULTIPLIER * len(siblings):
        return siblings
    if not sizing_hint.ranked_task_types:
        return siblings
    top_score = sizing_hint.ranked_task_types[0].score
    if top_score < _SIZING_HINT_MIN_TOP_SCORE:
        return siblings
    # Halve the panel (rounded up) so at least one non-primary voice
    # survives to keep the dialectic real. The persona tuple order is
    # a module convention -- the module chooses which personas rank
    # highest by placing them first in the sibling tuple.
    keep = max(1, (len(siblings) + 1) // 2)
    capped = siblings[:keep]
    _log.info(
        "persona_spawn.sizing_hint capped siblings %d -> %d "
        "target_kind=%s top_task_type=%s top_score=%.3f samples=%d",
        len(siblings), len(capped),
        sizing_hint.target_kind,
        sizing_hint.ranked_task_types[0].task_type,
        top_score, sizing_hint.total_samples,
    )
    return capped


async def spawn_persona_siblings(
    investigation_id: str,
    primary_branch_id: str,
    team_id: str | None,
    *,
    siblings: tuple[Any, ...],
    branch_model: type[Any],
    inv_table: str,
    message_table: str,
    task_fn: Callable[..., Awaitable[Any]],
    track: str,
    group_id: str,
    task_queue: Any,
    strip_case_state: Callable[[str], str],
    should_reactivate: Callable[[Any], Awaitable[bool]] | None = None,
    sizing_hint: RoutingRecommendation | None = None,
) -> SiblingSpawnResult:
    """Spawn / reuse one branch per persona for ``investigation_id``.

    ``siblings`` is a tuple of persona members carrying a ``.value``
    string. ``strip_case_state`` composes the module's reject/directive
    strip helpers so a reactivated or freshly forked persona starts from
    the same clean baseline.

    ``sizing_hint`` is the pre-execution :class:`RoutingRecommendation`
    from :meth:`aila.platform.eval.routing_learner.RoutingLearner.recommend`
    computed by the investigation-setup path before this call. When the
    recommendation carries enough evidence and a clear top task_type,
    the sibling tuple is capped to the top half of the persona list --
    saving budget on investigations whose target_kind + task_type has a
    well-known good route. A hint of None (or insufficient evidence /
    no clear winner) leaves the sibling tuple untouched, preserving
    the pre-RFC-08 behaviour.
    """
    siblings = _cap_siblings_by_sizing_hint(siblings, sizing_hint)
    result = SiblingSpawnResult()
    if not siblings:
        return result

    # Phase 1 -- atomic dedup + reactivate + insert new branches. On any
    # exception inside the `async with` block the UoW rolls back: no
    # branch INSERT survives, no status flip persists.
    sibling_branch_ids: dict[str, str] = {}  # persona_value -> branch_id
    async with UnitOfWork() as uow:
        # Serialize concurrent spawn calls per-investigation. Without
        # this lock, the primary task and N sibling tasks landing in
        # parallel workers each read all_branches at once, all see a
        # persona missing, and all INSERT a duplicate. SELECT FOR UPDATE
        # on the inv row gives spawn a per-investigation mutex.
        await uow.session.execute(
            _sql_text(
                f"SELECT id FROM {inv_table} WHERE id = :id FOR UPDATE"
            ).bindparams(id=investigation_id),
        )

        all_branches = (await uow.session.exec(
            _select(branch_model).where(
                branch_model.investigation_id == investigation_id,
            )
        )).all()

        # Group by persona. An ``operator_reopen:<userid>`` branch always
        # wins regardless of turn_count (the operator explicitly created
        # it to drive a fresh pass); otherwise the most-turns branch
        # wins, with created_at as the tertiary tiebreaker so the newest
        # reopen is not silently abandoned as a duplicate.
        def _branch_priority(b: Any) -> tuple[int, int, float]:
            is_reopen = (b.fork_reason or "").startswith("operator_reopen:")
            created_ts = b.created_at.timestamp() if b.created_at else 0.0
            return (1 if is_reopen else 0, b.turn_count, created_ts)

        best_by_persona: dict[str, Any] = {}
        for b in all_branches:
            if not b.persona_voice:
                continue
            existing = best_by_persona.get(b.persona_voice)
            if existing is None or _branch_priority(b) > _branch_priority(existing):
                best_by_persona[b.persona_voice] = b

        # Reactivate the winner per persona; abandon duplicates.
        for b in all_branches:
            if not b.persona_voice:
                continue
            best = best_by_persona.get(b.persona_voice)
            if best is None:
                continue
            if b.id == best.id:
                # Winner -- reactivate as a fresh slot (turn_count 0,
                # stripped case_state, prior messages deleted) so the
                # cap math, steering directives, rejected-hypothesis
                # lists, and tool-failure breaker all start clean.
                #
                # RFC-13 SETUP IDEMPOTENCY (2026-07-26): this reset MUST
                # only fire for terminal branches (``abandoned`` /
                # ``completed``). An ``active`` / ``paused`` winner is a
                # live branch -- resetting turn_count and DELETEing its
                # messages here would wipe an investigation mid-run every
                # time setup re-ran (e.g. on the auto_continue re-enqueue
                # path). The status guard below is the single load-bearing
                # check; do NOT relax it. investigation_setup relies on
                # this contract when it calls spawn_fn on every setup
                # invocation for a RUNNING investigation.
                _reactivate = b.status in ("abandoned", "completed")
                if (
                    _reactivate
                    and b.status == "completed"
                    and should_reactivate is not None
                    and not await should_reactivate(b)
                ):
                    # Completed branch with no pending review work left --
                    # leave it completed. Resurrecting it here (turn_count
                    # reset, prior messages deleted) with nothing to review
                    # is the deliberation churn: every setup re-entry reset
                    # already-voted siblings, so a fully-deliberated split
                    # finding never let the investigation settle (it cycled
                    # until the auto_continue cap). The predicate returns
                    # True only while an unvoted pending draft exists.
                    _reactivate = False
                    _log.info(
                        "auto_deliberation: NOT reactivating completed %s "
                        "branch %s -- no unvoted pending draft (deliberation "
                        "complete)",
                        b.persona_voice, b.id,
                    )
                if _reactivate:
                    b.status = "active"
                    b.closed_reason = ""
                    b.closed_at = None
                    b.turn_count = 0
                    b.case_state_json = strip_case_state(
                        b.case_state_json or "{}",
                    )
                    uow.session.add(b)
                    await uow.session.execute(
                        _sql_text(
                            f"DELETE FROM {message_table} "
                            "WHERE branch_id = :bid"
                        ).bindparams(bid=b.id),
                    )
                    result.reactivated.append(b.id)
                    _log.info(
                        "auto_deliberation: reactivated %s branch %s "
                        "(turn_count + case_state + breaker reset to fresh)",
                        b.persona_voice, b.id,
                    )
            elif b.status not in ("abandoned",):
                b.status = "abandoned"
                b.closed_reason = "duplicate_persona_cleanup"
                b.closed_at = utc_now()
                uow.session.add(b)
                result.abandoned.append(b.id)
                _log.info(
                    "auto_deliberation: abandoned duplicate %s branch %s "
                    "(turns=%d, keeping %s)",
                    b.persona_voice, b.id, b.turn_count, best.id,
                )

        # INSERT new branches for personas without one, in this same UoW
        # so the whole panel is all-or-nothing. Inherit the primary's
        # case_state through the same strip the reactivation path uses.
        parent = (await uow.session.exec(
            _select(branch_model).where(branch_model.id == primary_branch_id)
        )).first()
        parent_case_state = (
            (parent.case_state_json or "{}") if parent is not None else "{}"
        )
        inherited_case_state = strip_case_state(parent_case_state)

        for persona in siblings:
            existing_branch = best_by_persona.get(persona.value)
            if existing_branch is not None:
                sibling_branch_ids[persona.value] = existing_branch.id
                continue
            child = branch_model(
                investigation_id=investigation_id,
                parent_branch_id=primary_branch_id,
                status="active",
                persona_voice=persona.value,
                fork_reason=f"auto_deliberation:{persona.value}",
                fork_at_turn=0,
                case_state_json=inherited_case_state,
                turn_count=0,
                branch_cost_usd=0.0,
            )
            uow.session.add(child)
            await uow.session.flush()  # populate child.id within the UoW
            sibling_branch_ids[persona.value] = child.id
            result.inserted.append(child.id)

        await uow.commit()

    # Phase 2 -- best-effort enqueue per resolved branch.
    #
    # RFC-13 DEDUP CONTRACT (2026-07-26): these submits go through the
    # normal (bypass_dedup=False) TaskQueue path. The dedup search there
    # is branch-scoped (see aila.platform.tasks.queue.TaskQueue.submit
    # "Branch-scoped soft dedup"), so if an auto_continue task is
    # already in-flight for the same (investigation_id, branch_id) --
    # even though its input_hash was UUID-mixed by ``bypass_dedup=True``
    # on the caller side -- this submit returns that existing task's
    # handle rather than enqueueing a duplicate.
    for persona in siblings:
        sibling_branch_id = sibling_branch_ids.get(persona.value)
        if not sibling_branch_id:
            continue
        try:
            await task_queue.submit(
                track=track,
                fn=task_fn,
                kwargs={
                    "investigation_id": investigation_id,
                    "branch_id": sibling_branch_id,
                },
                user_id="system",
                group_id=group_id,
                team_id=team_id,
            )
            result.enqueued.append(f"{persona.value}={sibling_branch_id[:8]}")
        except (
            WorkerUnreachableError, OSError, RuntimeError, ValueError, TypeError,
        ) as exc:
            _log.warning(
                "auto_deliberation: enqueue failed persona=%s branch=%s "
                "err=%s (branch row persists; reaper-on-cursor can resubmit)",
                persona.value, sibling_branch_id, exc,
                exc_info=True,
            )

    if result.enqueued:
        _log.info(
            "auto_deliberation: spawned siblings for %s: %s",
            investigation_id, result.enqueued,
        )
    return result


async def spawn_specialist_branch(
    investigation_id: str,
    primary_branch_id: str,
    team_id: str | None,
    *,
    specialist_name: str,
    branch_model: type[Any],
    inv_table: str,
    task_fn: Callable[..., Awaitable[Any]],
    track: str,
    group_id: str,
    task_queue: Any,
    strip_case_state: Callable[[str], str],
) -> str | None:
    """Spawn one on-demand specialist branch (``persona_voice`` = name).

    Called by a module's setup for each ratified ``request_specialist``
    capability (resolved to a registry specialist). Idempotent: if a branch
    with this ``persona_voice`` already exists for the investigation (in any
    non-abandoned state), returns its id without spawning, so re-running
    setup does not fork duplicates. The branch's capability is resolved from
    the specialist registry in setup (persona_voice -> capability), which
    threads ``_branch_capability`` so the dispatch hub routes it to the
    capability-scoped phases. Returns the branch id (existing or new).
    """
    async with UnitOfWork() as uow:
        await uow.session.execute(
            _sql_text(
                f"SELECT id FROM {inv_table} WHERE id = :id FOR UPDATE"
            ).bindparams(id=investigation_id),
        )
        existing = (await uow.session.exec(
            _select(branch_model).where(
                branch_model.investigation_id == investigation_id,
                branch_model.persona_voice == specialist_name,
                branch_model.status != "abandoned",
            )
        )).first()
        if existing is not None:
            return existing.id
        parent = (await uow.session.exec(
            _select(branch_model).where(branch_model.id == primary_branch_id)
        )).first()
        parent_case_state = (
            (parent.case_state_json or "{}") if parent is not None else "{}"
        )
        child = branch_model(
            investigation_id=investigation_id,
            parent_branch_id=primary_branch_id,
            status="active",
            persona_voice=specialist_name,
            fork_reason=f"specialist_request:{specialist_name}",
            fork_at_turn=0,
            case_state_json=strip_case_state(parent_case_state),
            turn_count=0,
            branch_cost_usd=0.0,
        )
        uow.session.add(child)
        await uow.session.flush()
        branch_id = child.id
        await uow.commit()

    try:
        await task_queue.submit(
            track=track,
            fn=task_fn,
            kwargs={
                "investigation_id": investigation_id,
                "branch_id": branch_id,
            },
            user_id="system",
            group_id=group_id,
            team_id=team_id,
        )
        _log.info(
            "specialist spawn: %s branch %s for %s",
            specialist_name, branch_id, investigation_id,
        )
    except (
        WorkerUnreachableError, OSError, RuntimeError, ValueError, TypeError,
    ) as exc:
        _log.warning(
            "specialist spawn: enqueue failed name=%s branch=%s err=%s "
            "(branch row persists; a later setup pass can resubmit)",
            specialist_name, branch_id, exc,
        )
    return branch_id
