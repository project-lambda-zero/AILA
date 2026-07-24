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
from typing import Any

from sqlalchemy import text as _sql_text
from sqlmodel import select as _select

from aila.platform.contracts import utc_now
from aila.platform.exceptions import WorkerUnreachableError
from aila.platform.uow import UnitOfWork

_log = logging.getLogger(__name__)

__all__ = ["SiblingSpawnResult", "spawn_persona_siblings"]


@dataclass(frozen=True)
class SiblingSpawnResult:
    """Outcome of one spawn call, for logging and tests."""

    reactivated: list[str] = field(default_factory=list)
    inserted: list[str] = field(default_factory=list)
    abandoned: list[str] = field(default_factory=list)
    enqueued: list[str] = field(default_factory=list)


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
) -> SiblingSpawnResult:
    """Spawn / reuse one branch per persona for ``investigation_id``.

    ``siblings`` is a tuple of persona members carrying a ``.value``
    string. ``strip_case_state`` composes the module's reject/directive
    strip helpers so a reactivated or freshly forked persona starts from
    the same clean baseline.
    """
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
                if b.status in ("abandoned", "completed"):
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
