"""Atomic investigation pause / resume across the four sources of truth.

The durable lifecycle of an investigation touches four stores that must
move together:

1. the ``<module>_investigation`` row (projection column ``status`` plus
   ``pause_reason`` / ``updated_at``);
2. ``workflow_state_cursor`` (per-branch ``current_state`` /
   ``archived_state`` and the ``__paused__`` sentinel);
3. ``taskrecord`` (ARQ task rows in ``queued`` / ``running`` /
   ``waiting``);
4. ARQ Redis (``arq:in-progress:<id>`` keys and queued jobs).

Correctness comes from doing the mutable three (inv row, cursor rows,
taskrecord rows) in one transaction with the right ordering (lock the
inv row, then the cursors, flip everything, commit) and then doing the
best-effort ARQ Redis purge after commit. That ordering is a platform
property, not a module one: it sits above the persona roster and MCP
catalog. Leaving it per module gives every new module the choice of
copying the correct version, copying a stale one, or writing a third --
which is exactly how the malware copy fell behind. One implementation
forces one behavior.

Generic over the module: callers bind their concrete investigation and
branch record models, the raw branch table name (for the operator-facing
branch-status projection), the ARQ track, and the module task function
via a thin module wrapper. The platform file never names a module. The
pause-reason enum coercion stays module-side (each module validates its
own reason vocabulary) and the already-coerced string is passed in.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any

from sqlalchemy import text as _sql_text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlmodel import select

from aila.platform.contracts import utc_now
from aila.platform.contracts.enums import InvestigationStatus
from aila.platform.llm.cancellation import (
    cancel_for_investigation,
    clear_for_investigation,
)
from aila.platform.tasks.arq_purge import purge_arq_jobs_for_investigation
from aila.platform.tasks.models import TaskStatus
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.types import RESERVED_PAUSED

_log = logging.getLogger(__name__)

__all__ = [
    "PauseInvestigationError",
    "ReenqueueInvestigationError",
    "ResumeInvestigationError",
    "mark_investigation_completed",
    "pause_investigation",
    "reenqueue_investigation",
    "resume_investigation",
]


def mark_investigation_completed(
    inv_row: Any, *, now: datetime | None = None,
) -> None:
    """Flip an investigation row to COMPLETED in one place.

    Sets ``status`` / ``stopped_at`` / ``updated_at`` the same way for
    every terminal writer so synthesis, the emit finalizer, and any
    future terminal path agree on the three fields. Generic over the
    module: any investigation record carrying those three columns. The
    caller stages the row (``session.add``) and commits -- this helper
    only mutates the in-memory row. Pass ``now`` to share one timestamp
    across a batch of terminal writes; it defaults to ``utc_now()``.
    """
    stamp = now or utc_now()
    inv_row.status = InvestigationStatus.COMPLETED.value
    inv_row.stopped_at = stamp
    inv_row.updated_at = stamp


class PauseInvestigationError(RuntimeError):
    """Pause refused because the investigation isn't in a pausable state."""


class ResumeInvestigationError(RuntimeError):
    """Resume refused because there are no paused cursors to restore."""


class ReenqueueInvestigationError(RuntimeError):
    """Re-enqueue refused because the investigation could not be loaded."""


async def pause_investigation(
    investigation_id: str,
    *,
    inv_model: type[Any],
    branch_model: type[Any],
    branch_table: str,
    track: str,
    pause_reason: str,
    user_id: str | None = None,
) -> dict[str, Any]:
    """Atomically pause every active task for ``investigation_id``.

    Returns a summary dict::

        {"paused_cursors": N, "cancelled_tasks": N, "inv_status": "paused"}

    Raises :class:`PauseInvestigationError` if the investigation is
    already terminal (COMPLETED / FAILED / ABANDONED). The CREATED /
    RUNNING / PAUSED states are all pause-able; PAUSED is a no-op
    flagged by ``noop=True`` in the returned summary. ``pause_reason``
    is the already-coerced enum value; the module wrapper owns the
    coercion so the reason vocabulary stays module-side.
    """
    summary: dict[str, Any] = {
        "paused_cursors": 0,
        "cancelled_tasks": 0,
        "inv_status": None,
        "noop": False,
    }
    now = utc_now()

    async with UnitOfWork() as uow:
        # Lock the investigation row first so no concurrent dispatcher
        # can flip status under us.
        inv_stmt = (
            select(inv_model)
            .where(inv_model.id == investigation_id)
            .with_for_update()
        )
        inv = (await uow.session.exec(inv_stmt)).first()
        if inv is None:
            raise PauseInvestigationError(
                f"Investigation {investigation_id!r} not found.",
            )
        terminal = {
            InvestigationStatus.COMPLETED.value,
            InvestigationStatus.FAILED.value,
            InvestigationStatus.ABANDONED.value,
        }
        if inv.status in terminal:
            raise PauseInvestigationError(
                f"Cannot pause investigation in status {inv.status!r}.",
            )
        if inv.status == InvestigationStatus.PAUSED.value:
            summary["noop"] = True
            summary["inv_status"] = inv.status
            return summary

        # 1. Find every active branch (its `id` equals the workflow run_id
        #    of the per-branch task). SELECT FOR UPDATE on the cursors so
        #    a concurrent task can't flip current_state under us.
        branch_rows = (await uow.session.exec(
            select(branch_model.id)
            .where(
                branch_model.investigation_id == investigation_id,
            )
        )).all()
        branch_ids = [str(b) for b in branch_rows]

        # 2. Lock + flip cursors. Raw SQL for the bulk lock + UPDATE
        #    because the pattern is clearer as a single statement.
        if branch_ids:
            # Lock the cursors matching the investigation's branches +
            # the investigation_id itself (some workflows use the
            # investigation_id as run_id for the parent).
            lock_stmt = _sql_text(
                "SELECT run_id, current_state FROM workflow_state_cursor "
                "WHERE run_id = ANY(:ids) FOR UPDATE"
            ).bindparams(ids=[investigation_id, *branch_ids])
            locked = (await uow.session.exec(lock_stmt)).all()
            pausable = [
                row.run_id
                for row in locked
                if row.current_state != RESERVED_PAUSED
            ]
            if pausable:
                upd_stmt = _sql_text(
                    "UPDATE workflow_state_cursor "
                    "SET archived_state = current_state, "
                    "    current_state = :paused, "
                    "    updated_at = :ts, "
                    "    version = version + 1 "
                    "WHERE run_id = ANY(:ids) "
                    "  AND current_state <> :paused"
                ).bindparams(
                    paused=RESERVED_PAUSED,
                    ts=now,
                    ids=pausable,
                )
                result = await uow.session.exec(upd_stmt)
                summary["paused_cursors"] = result.rowcount or 0

        # 3. Cancel TaskRecord rows in active dispatch states. The worker
        #    that picks up the task next sees status != queued/running and
        #    exits clean.
        if branch_ids:
            cancel_stmt = _sql_text(
                "UPDATE taskrecord "
                "SET status = :cancelled, "
                "    completed_at = :ts, "
                "    error = COALESCE(error, '') || :marker "
                "WHERE id = ANY(:ids) "
                "  AND status = ANY(:active_statuses)"
            ).bindparams(
                cancelled=TaskStatus.CANCELLED.value,
                active_statuses=[
                    TaskStatus.QUEUED.value,
                    TaskStatus.RUNNING.value,
                ],
                ts=now,
                marker=f"operator_pause:{user_id or 'unknown'}\n",
                ids=[investigation_id, *branch_ids],
            )
            cancel_result = await uow.session.exec(cancel_stmt)
            summary["cancelled_tasks"] = cancel_result.rowcount or 0

        # 3.5. Flip every active branch's projection status to paused so
        # the UI does not show a paused investigation with branches still
        # marked active. The cursor sentinel stays authoritative for
        # whether the worker runs. The branch status column serves only
        # as the operator-facing projection, kept in step so the chip
        # colour matches the investigation chip. Resume restores active.
        if branch_ids:
            branch_pause_stmt = _sql_text(
                f"UPDATE {branch_table} "
                "SET status = :paused, updated_at = :ts "
                "WHERE investigation_id = :inv "
                "  AND status = :active"
            ).bindparams(
                paused="paused",
                active="active",
                inv=investigation_id,
                ts=now,
            )
            branch_pause_result = await uow.session.exec(branch_pause_stmt)
            summary["paused_branches"] = branch_pause_result.rowcount or 0
        else:
            summary["paused_branches"] = 0

        # 4. Flip the investigation status derived projection.
        inv.status = InvestigationStatus.PAUSED.value
        inv.pause_reason = pause_reason
        inv.updated_at = now
        uow.session.add(inv)

        await uow.session.commit()
        await uow.session.refresh(inv)
        summary["inv_status"] = inv.status

    # 5. Best-effort ARQ purge AFTER commit. Surviving jobs read the
    #    cursor on next pickup, see __paused__, exit clean. Log failures
    #    but never propagate -- the cursor SSOT is enough.
    try:
        await purge_arq_jobs_for_investigation(
            investigation_id, track=track,
        )
    except (OSError, RuntimeError, ImportError, ValueError, TypeError) as exc:
        _log.warning(
            "pause_investigation ARQ_PURGE failed inv=%s err=%s",
            investigation_id, exc,
            exc_info=True,
        )
    # 6. Hard cancellation: flip the per-investigation cancellation token
    # so any in-flight LLM retry loop or tool bridge dispatch sees the
    # cancellation at its next retry-boundary check (no-op if no token
    # exists in this process -- the cursor SSOT is the cross-process
    # synchronizer).
    try:
        cancel_for_investigation(investigation_id)
    except (OSError, RuntimeError, ImportError, ValueError, TypeError) as exc:
        _log.warning(
            "pause_investigation CANCEL_TOKEN failed inv=%s err=%s",
            investigation_id, exc,
            exc_info=True,
        )

    return summary


async def resume_investigation(
    investigation_id: str,
    *,
    inv_model: type[Any],
    branch_model: type[Any],
    branch_table: str,
    track: str,
    task_fn: Callable[..., Awaitable[Any]],
    task_queue: Any = None,
    user_id: str | None = None,
    auth_user_id: str | None = None,
    auth_role: str | None = None,
    auth_team_id: str | None = None,
) -> dict[str, Any]:
    """Atomically resume every paused cursor for ``investigation_id``.

    Returns::

        {"resumed_cursors": N, "submitted_tasks": N, "inv_status": "running"}

    Raises :class:`ResumeInvestigationError` if the investigation is not
    PAUSED. The fan-out submits one ``task_fn`` task per resumed cursor
    so every branch (not just the primary) ticks again.
    """
    if task_queue is None:
        raise ResumeInvestigationError(
            "task_queue argument required (auth-bound for safety)",
        )

    summary: dict[str, Any] = {
        "resumed_cursors": 0,
        "submitted_tasks": 0,
        "inv_status": None,
    }
    now = utc_now()
    resumed_run_ids: list[str] = []

    async with UnitOfWork() as uow:
        inv_stmt = (
            select(inv_model)
            .where(inv_model.id == investigation_id)
            .with_for_update()
        )
        inv = (await uow.session.exec(inv_stmt)).first()
        if inv is None:
            raise ResumeInvestigationError(
                f"Investigation {investigation_id!r} not found.",
            )
        if inv.status != InvestigationStatus.PAUSED.value:
            raise ResumeInvestigationError(
                f"Cannot resume investigation in status {inv.status!r}.",
            )

        # 1. Lock + restore paused cursors associated with this
        #    investigation's branches (and the investigation_id itself).
        branch_ids = (await uow.session.exec(
            select(branch_model.id)
            .where(
                branch_model.investigation_id == investigation_id,
            )
        )).all()
        candidate_ids = [investigation_id, *[str(b) for b in branch_ids]]

        lock_stmt = _sql_text(
            "SELECT run_id, archived_state FROM workflow_state_cursor "
            "WHERE run_id = ANY(:ids) "
            "  AND current_state = :paused "
            "FOR UPDATE"
        ).bindparams(paused=RESERVED_PAUSED, ids=candidate_ids)
        locked = (await uow.session.exec(lock_stmt)).all()

        for row in locked:
            if row.archived_state:
                resumed_run_ids.append(str(row.run_id))

        if resumed_run_ids:
            # 2. Restore archived_state and clear the archive. One UPDATE
            #    per run_id because each row's prior state differs.
            for run_id in resumed_run_ids:
                upd_stmt = _sql_text(
                    "UPDATE workflow_state_cursor "
                    "SET current_state = COALESCE(archived_state, 'investigation_setup'), "
                    "    archived_state = NULL, "
                    "    updated_at = :ts, "
                    "    version = version + 1 "
                    "WHERE run_id = :rid "
                    "  AND current_state = :paused"
                ).bindparams(
                    rid=run_id,
                    ts=now,
                    paused=RESERVED_PAUSED,
                )
                await uow.session.exec(upd_stmt)
            summary["resumed_cursors"] = len(resumed_run_ids)

        # 2.5. Flip projection status of every branch previously paused
        # back to ``active``. Symmetric with pause's step 3.5. We DO NOT
        # touch branches whose status is something other than ``paused``
        # (a branch that finished mid-pause with completed / abandoned /
        # merged MUST stay where it is).
        resumed_branch_count_stmt = _sql_text(
            f"UPDATE {branch_table} "
            "SET status = :active, updated_at = :ts "
            "WHERE investigation_id = :inv "
            "  AND status = :paused"
        ).bindparams(
            active="active",
            paused="paused",
            inv=investigation_id,
            ts=now,
        )
        resumed_branch_result = await uow.session.exec(resumed_branch_count_stmt)
        summary["resumed_branches"] = resumed_branch_result.rowcount or 0

        # 3. Flip inv.status back to RUNNING.
        inv.status = InvestigationStatus.RUNNING.value
        inv.pause_reason = None
        inv.updated_at = now
        uow.session.add(inv)

        await uow.session.commit()
        await uow.session.refresh(inv)
        summary["inv_status"] = inv.status

    # Clear the cancellation token so the resumed branches' next LLM call
    # / tool dispatch sees a fresh (non-cancelled) token. The fan-out
    # below dispatches new ARQ tasks that mint a fresh token.
    try:
        clear_for_investigation(investigation_id)
    except (OSError, RuntimeError, ImportError, ValueError, TypeError) as exc:
        _log.warning(
            "resume_investigation CLEAR_TOKEN failed inv=%s err=%s",
            investigation_id, exc,
            exc_info=True,
        )
    # 4. AFTER commit: fan-out one ARQ task per resumed cursor so every
    #    branch (not just the primary) gets a worker pickup.
    submitted = 0
    for run_id in resumed_run_ids:
        kwargs: dict[str, Any] = {"investigation_id": investigation_id}
        # If the cursor's run_id is a branch id (not the inv id), carry
        # it as branch_id so investigation_loop targets that branch.
        if run_id != investigation_id:
            kwargs["branch_id"] = run_id
        try:
            await task_queue.submit(
                track=track,
                fn=task_fn,
                kwargs=kwargs,
                user_id=auth_user_id or user_id,
                group_id=auth_role,
                team_id=auth_team_id,
                # dedup via the TaskRecord.input_hash UNIQUE index:
                # re-submitting the same (track, fn, canonical kwargs)
                # within the active window raises IntegrityError which the
                # caller catches as 'already queued'.
            )
            submitted += 1
        except IntegrityError:
            # Idempotency-key collision: another resume already submitted
            # this run_id within the same second. Acceptable.
            _log.info(
                "resume_investigation dedup inv=%s run=%s",
                investigation_id, run_id,
            )
        except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError) as exc:
            _log.warning(
                "resume_investigation submit failed inv=%s run=%s err=%s",
                investigation_id, run_id, exc,
                exc_info=True,
            )
    # Legacy-branch fallback: investigations spawned before the cursor
    # SSOT shipped have no cursor rows. The cursor-driven fan-out finds
    # zero rows and dispatches zero tasks; resume would become a no-op
    # leaving those branches at status='active' with no in-flight task.
    #
    # When the cursor path resumed nothing, scan for any ACTIVE branches
    # on this investigation and dispatch one task each. The new tasks
    # pick up wherever the branch left off (turn_count + case_state_json
    # persist across pause/resume; only the in-flight worker disappears).
    if not resumed_run_ids:
        async with UnitOfWork() as uow:
            active_branches = (await uow.session.exec(
                select(branch_model.id)
                .where(
                    branch_model.investigation_id == investigation_id,
                    branch_model.status == "active",
                ),
            )).all()
        legacy_ids = [str(b) for b in active_branches]
        if legacy_ids:
            _log.info(
                "resume_investigation LEGACY_FALLBACK inv=%s "
                "active_branches=%d (no cursors found -- pre-cursor-SSOT "
                "investigation; dispatching one task per branch)",
                investigation_id, len(legacy_ids),
            )
        for br_id in legacy_ids:
            try:
                await task_queue.submit(
                    track=track,
                    fn=task_fn,
                    kwargs={
                        "investigation_id": investigation_id,
                        "branch_id": br_id,
                    },
                    user_id=auth_user_id or user_id,
                    group_id=auth_role,
                    team_id=auth_team_id,
                )
                submitted += 1
            except IntegrityError:
                _log.info(
                    "resume_investigation LEGACY dedup inv=%s br=%s",
                    investigation_id, br_id,
                )
            except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError) as exc:
                _log.warning(
                    "resume_investigation LEGACY submit failed "
                    "inv=%s br=%s err=%s",
                    investigation_id, br_id, exc, exc_info=True,
                )

    summary["submitted_tasks"] = submitted
    return summary


async def _fan_out_reenqueue_submit(
    investigation_id: str,
    *,
    submit_one: Callable[[str, str | None], Awaitable[None]],
    branch_model: type[Any] | None,
    branch_status_active: str | None,
) -> int:
    """Fan the fresh submit out across active branches (platform-owned).

    ``branch_model is None`` selects submit-once mode (VR): one task with
    no branch id, and the setup state respawns/reuses the persona
    branches on dispatch. Otherwise (malware) one task is submitted per
    active branch, or one setup task when no branch is active. Returns
    the number of submit calls made. This orchestration lives in the
    platform so a module cannot get the branch fan-out wrong.
    """
    if branch_model is None:
        await submit_one(investigation_id, None)
        return 1
    async with UnitOfWork() as uow:
        branch_stmt = (
            select(branch_model.id)
            .where(branch_model.investigation_id == investigation_id)
            .where(branch_model.status == branch_status_active)
        )
        branch_ids = [
            str(bid) for bid in (await uow.session.exec(branch_stmt)).all()
        ]
    if branch_ids:
        for branch_id in branch_ids:
            await submit_one(investigation_id, branch_id)
        return len(branch_ids)
    await submit_one(investigation_id, None)
    return 1


async def reenqueue_investigation(
    investigation_id: str,
    *,
    inv_model: type[Any],
    fn_path_pattern: str,
    submit_one: Callable[[str, str | None], Awaitable[None]],
    branch_model: type[Any] | None = None,
    branch_status_active: str | None = None,
    new_kind: str | None = None,
    new_strategy: str | None = None,
) -> dict[str, Any]:
    """Reset an investigation to CREATED and submit fresh worker tasks.

    Returns::

        {"submitted": N, "cancelled_stale_tasks": N,
         "wiped_crashed_cursors": N, "investigation_id": "<id>"}

    Owns the full re-enqueue state machine so a module cannot diverge:
    reset the row to CREATED, cancel every stale taskrecord matching
    ``fn_path_pattern`` and this investigation (this is what stops
    ``TaskQueue.submit``'s input-hash dedup from returning the
    pre-existing handle), wipe every ``__crashed__``
    workflow_state_cursor tied to the investigation (without which the
    engine refuses to resume cleanly), commit, then submit. The commit
    precedes the submit; the same UoW would race with the dedup session
    opened inside ``TaskQueue.submit``. ``new_kind`` / ``new_strategy``
    update ``inv.kind`` / ``inv.strategy_family`` when supplied; the
    caller resolves the module's kind-to-strategy default map.

    The only module-specific input is the atomic submit primitive:
    ``submit_one(investigation_id, branch_id | None) -> None`` submits
    exactly one worker task. ``branch_model`` (with ``branch_status_active``)
    selects the fan-out: ``None`` submits once (VR, setup respawns the
    branches); a branch model submits one task per active branch, or one
    setup task when no branch is active (malware). The branch fan-out
    itself is platform-owned; the module supplies only the one-submit
    primitive and the branch-query parameters as data.
    """
    summary: dict[str, Any] = {
        "submitted": 0,
        "cancelled_stale_tasks": 0,
        "wiped_crashed_cursors": 0,
        "investigation_id": investigation_id,
    }
    now = utc_now()

    async with UnitOfWork() as uow:
        inv_stmt = (
            select(inv_model)
            .where(inv_model.id == investigation_id)
            .with_for_update()
        )
        inv = (await uow.session.exec(inv_stmt)).first()
        if inv is None:
            raise ReenqueueInvestigationError(
                f"Investigation {investigation_id!r} not found.",
            )
        # Sync strategy_family to the kind default when the caller passes
        # an explicit kind. This covers both changing the kind and
        # repairing a mismatch left by an earlier create-time default bug.
        if new_kind is not None:
            inv.kind = new_kind
            if new_strategy is not None:
                inv.strategy_family = new_strategy
        inv.status = InvestigationStatus.CREATED.value
        inv.pause_reason = None
        inv.updated_at = now
        uow.session.add(inv)

        # Cancel any stale task still in queued/running/waiting for this
        # investigation. Without this, TaskQueue.submit()'s input-hash
        # dedup returns the pre-existing handle and the re-enqueue
        # silently no-ops.
        cancel_stmt = _sql_text(
            "UPDATE taskrecord "
            "SET status = :cancelled "
            "WHERE fn_path LIKE :fn_pat "
            "  AND status = ANY(:active_statuses) "
            "  AND kwargs_json LIKE :inv_pat"
        ).bindparams(
            cancelled=TaskStatus.CANCELLED.value,
            fn_pat=fn_path_pattern,
            active_statuses=[
                TaskStatus.QUEUED.value,
                TaskStatus.RUNNING.value,
                TaskStatus.WAITING.value,
            ],
            inv_pat=f'%"{investigation_id}"%',
        )
        cancel_result = await uow.session.exec(cancel_stmt)
        summary["cancelled_stale_tasks"] = cancel_result.rowcount or 0

        # Wipe __crashed__ cursors for this investigation so the workflow
        # engine starts fresh on the next dispatch.
        wipe_stmt = _sql_text(
            "DELETE FROM workflow_state_cursor "
            "WHERE current_state = '__crashed__' "
            "  AND run_id IN (SELECT id FROM taskrecord "
            "WHERE kwargs_json LIKE :inv_pat)"
        ).bindparams(inv_pat=f'%"{investigation_id}"%')
        wipe_result = await uow.session.exec(wipe_stmt)
        summary["wiped_crashed_cursors"] = wipe_result.rowcount or 0

        await uow.session.commit()

    # Commit precedes submit: the same UoW would race with the dedup
    # session opened inside the submit primitive's TaskQueue.submit.
    summary["submitted"] = await _fan_out_reenqueue_submit(
        investigation_id,
        submit_one=submit_one,
        branch_model=branch_model,
        branch_status_active=branch_status_active,
    )
    return summary
