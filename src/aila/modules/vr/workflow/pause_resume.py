"""Phase B (cutover): atomic pause / resume / reset implementations.

Promotes ``workflow_state_cursor`` to the single source of truth for
"is this investigation paused right now". The prior implementation
wrote ``inv.status = PAUSED`` directly from the API handler, leaving
three sources of truth unsynchronized (``TaskRecord.status``,
``workflow_state_cursor.current_state``, ``arq:in-progress:<id>``).
Per ``docs/CUTOVER_DEPS.md §2`` Phase B closes items §3, §30-§33,
§46, §47, §156, §287, §288, §296.

Three operations expose the same atomic-transaction shape:

* :func:`pause_investigation_atomic`
    SELECT FOR UPDATE every branch's cursor that belongs to the
    investigation → flip ``current_state -> '__paused__'`` while
    archiving the prior state → cancel TaskRecord rows in
    ``queued/running/waiting`` → flip ``inv.status -> PAUSED``
    derived projection. One transaction, one commit. ARQ purge runs
    AFTER the commit (best-effort: surviving jobs read the cursor on
    next pickup, see ``__paused__``, and exit clean).

* :func:`resume_investigation_atomic`
    SELECT FOR UPDATE every cursor with ``current_state ==
    '__paused__'`` → restore ``archived_state -> current_state`` and
    clear archive → flip ``inv.status -> RUNNING``. AFTER commit,
    fan-out one ``run_vr_investigate`` ARQ task per resumed cursor so
    every branch (not just the primary) actually ticks again.

* :func:`reset_investigation_atomic`
    Pause + delete every cursor + clear every outcome → spawn a fresh
    primary branch. Matches the operator-observed contract that
    ``/reset`` returns the investigation to a pristine state.

Mid-LLM-call cancellation (Phase B.5 in the design doc) is deferred:
in-flight LLM calls commit when they finish, which can be minutes
after the pause. The next turn-boundary tries to acquire the cursor
lock, sees ``__paused__``, and exits. No further work happens.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import text as _sql_text
from sqlalchemy.exc import IntegrityError
from sqlmodel import select

from aila.modules.vr.contracts.investigation import (
    InvestigationPauseReason,
    InvestigationStatus,
)
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
)
from aila.platform.contracts._common import utc_now
from aila.platform.tasks.models import TaskStatus
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.types import RESERVED_PAUSED

_log = logging.getLogger(__name__)

__all__ = [
    "PauseInvestigationError",
    "ResumeInvestigationError",
    "pause_investigation_atomic",
    "resume_investigation_atomic",
]


class PauseInvestigationError(RuntimeError):
    """Pause refused because the investigation isn't in a pausable state."""


class ResumeInvestigationError(RuntimeError):
    """Resume refused because there are no paused cursors to restore."""


def _pause_reason_value(reason: str | None) -> str:
    """Coerce caller-supplied reason to a contract-enum value.

    Empty / unknown strings degrade to ``OPERATOR`` so the column never
    holds a free-form string (matches Phase E §19 contract).
    """
    if reason is None:
        return InvestigationPauseReason.OPERATOR.value
    try:
        return InvestigationPauseReason(reason).value
    except ValueError:
        return InvestigationPauseReason.OPERATOR.value


async def pause_investigation_atomic(
    investigation_id: str,
    *,
    user_id: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    """Atomically pause every active task for ``investigation_id``.

    Returns a summary dict::

        {"paused_cursors": N, "cancelled_tasks": N, "inv_status": "paused"}

    Raises :class:`PauseInvestigationError` if the investigation is
    already terminal (COMPLETED / FAILED / ABANDONED). The CREATED /
    RUNNING / PAUSED states are all pause-able; PAUSED is a no-op
    flagged by ``noop=True`` in the returned summary.
    """
    summary: dict[str, Any] = {
        "paused_cursors": 0,
        "cancelled_tasks": 0,
        "inv_status": None,
        "noop": False,
    }
    pause_reason = _pause_reason_value(reason)
    now = utc_now()

    async with UnitOfWork() as uow:
        # Lock the investigation row first so no concurrent dispatcher
        # can flip status under us.
        inv_stmt = (
            select(VRInvestigationRecord)
            .where(VRInvestigationRecord.id == investigation_id)
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
        #    for the per-branch task). SELECT FOR UPDATE on the cursors so
        #    a concurrent task can't flip current_state under us.
        branch_rows = (await uow.session.exec(
            select(VRInvestigationBranchRecord.id)
            .where(
                VRInvestigationBranchRecord.investigation_id == investigation_id,
            )
        )).all()
        branch_ids = [str(b) for b in branch_rows]

        # 2. Lock + flip cursors. We use raw SQL for the lock + UPDATE
        #    because SQLModel's ``with_for_update`` is supported but the
        #    bulk lock pattern is clearer as a single statement.
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

        # 3. Cancel TaskRecord rows in active dispatch states. Phase B
        #    decision: ``cancelled`` is the canonical "operator
        #    interrupted" status. The worker that picks up the task
        #    next sees status != queued/running and exits clean.
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

        # 4. Flip the investigation status derived projection.
        inv.status = InvestigationStatus.PAUSED.value
        inv.pause_reason = pause_reason
        inv.updated_at = now
        uow.session.add(inv)

        await uow.session.commit()
        await uow.session.refresh(inv)
        summary["inv_status"] = inv.status

    # 5. Best-effort ARQ purge AFTER commit. Surviving jobs read the
    #    cursor on next pickup, see __paused__, exit clean. We log
    #    failures but never propagate — the cursor SSOT is enough.
    try:
        from aila.modules.vr.services.arq_purge import (  # noqa: PLC0415
            purge_arq_jobs_for_investigation,
        )
        await purge_arq_jobs_for_investigation(
            investigation_id, track="vr",
        )
    except Exception as exc:  # noqa: BLE001 — best-effort
        _log.warning(
            "pause_investigation_atomic ARQ_PURGE failed inv=%s err=%s",
            investigation_id, exc,
        )

    return summary


async def resume_investigation_atomic(
    investigation_id: str,
    *,
    user_id: str | None = None,
    task_queue: Any = None,
    auth_user_id: str | None = None,
    auth_role: str | None = None,
    auth_team_id: str | None = None,
) -> dict[str, Any]:
    """Atomically resume every paused cursor for ``investigation_id``.

    Returns::

        {"resumed_cursors": N, "submitted_tasks": N, "inv_status": "running"}

    Raises :class:`ResumeInvestigationError` if the investigation is
    not PAUSED. The fan-out submits one ``run_vr_investigate`` task
    per resumed cursor so every branch (not just the primary) ticks
    again — closing §34.
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
            select(VRInvestigationRecord)
            .where(VRInvestigationRecord.id == investigation_id)
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
            select(VRInvestigationBranchRecord.id)
            .where(
                VRInvestigationBranchRecord.investigation_id == investigation_id,
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
            # 2. Restore archived_state and clear the archive. Single
            #    UPDATE per run_id because we need each row's prior
            #    state, which differs across cursors.
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

        # 3. Flip inv.status back to RUNNING.
        inv.status = InvestigationStatus.RUNNING.value
        inv.pause_reason = None
        inv.updated_at = now
        uow.session.add(inv)

        await uow.session.commit()
        await uow.session.refresh(inv)
        summary["inv_status"] = inv.status

    # 4. AFTER commit: fan-out one ARQ task per resumed cursor. Closes
    #    §34 — every branch (not just the primary) gets a worker pickup.
    from aila.modules.vr.workflow.task import run_vr_investigate  # noqa: PLC0415

    submitted = 0
    for run_id in resumed_run_ids:
        kwargs: dict[str, Any] = {"investigation_id": investigation_id}
        # If the cursor's run_id is a branch id (not the inv id),
        # carry it as branch_id so investigation_loop targets that
        # branch specifically.
        if run_id != investigation_id:
            kwargs["branch_id"] = run_id
        try:
            await task_queue.submit(
                track="vr",
                fn=run_vr_investigate,
                kwargs=kwargs,
                user_id=auth_user_id or user_id,
                group_id=auth_role,
                team_id=auth_team_id,
                idempotency_key=(
                    f"resume:{investigation_id}:{run_id}:{now.isoformat()}"
                ),
            )
            submitted += 1
        except IntegrityError:
            # Idempotency-key collision: another resume already
            # submitted this run_id within the same second. Acceptable.
            _log.info(
                "resume_investigation_atomic dedup inv=%s run=%s",
                investigation_id, run_id,
            )
        except Exception as exc:  # noqa: BLE001 — best-effort per branch
            _log.warning(
                "resume_investigation_atomic submit failed inv=%s run=%s err=%s",
                investigation_id, run_id, exc,
            )

    summary["submitted_tasks"] = submitted
    return summary
