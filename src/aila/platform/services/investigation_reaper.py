"""Periodic cap-exceeded sweep for module investigations.

The cap-check logic in ``investigation_emit`` only fires at turn
boundaries. When workers are stuck in LLM-provider retry storms (300
seconds + 100 retries per call observed live), the emit path never
runs, the cap never evaluates, and an investigation past its
wall-clock limit stays RUNNING for hours after it should have
completed. Observed live 2026-06-03: 4 systemd investigations past
6h wall-clock kept queueing auto-continue tasks because no worker
could reach the cap-check at the turn boundary.

This reaper runs every minute via the ARQ cron, INDEPENDENT of
worker turn progress. It applies the same caps via the same
mechanism (halt branches + complete investigation + arq-purge).

Generic over the module: callers bind their concrete investigation /
branch / message record models, the ARQ track name, and an async
``cap_resolver`` returning a :class:`CapConfig` via a module-level
``functools.partial``. The platform file never names a module. The
emit-side check stays in place as belt+suspenders -- it catches the
cap faster (immediately on the turn that breached it) and lets the
emit path log the breach next to the turn that caused it. The
reaper is the catch-net for the stuck-worker case.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import and_, func, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.sql.functions import coalesce

from aila.platform.contracts import utc_now
from aila.platform.contracts.enums import BranchStatus, InvestigationStatus
from aila.platform.tasks.arq_purge import (
    purge_arq_jobs_for_investigation,
)
from aila.platform.uow import UnitOfWork

__all__ = [
    "CapConfig",
    "evaluate_cap_for_investigation",
    "sweep_cap_exceeded_investigations",
]

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class CapConfig:
    """Resolved investigation cap values used by one reaper pass.

    Populated per-call via the module-supplied async ``cap_resolver`` so
    operator overrides written through ``PUT /config`` land on the next
    tick without a worker restart.
    """

    turn_cap: int
    message_cap: int
    wallclock_hours: float
    idle_grace_s: float


async def _purge_arq_for_completed(
    completed_ids: list[str],
    *,
    track: str,
) -> None:
    """Best-effort ARQ purge for capped investigations.

    Shared between the sweep wrapper and the per-id helper so both
    paths produce identical post-cap cleanup.
    """
    if not completed_ids:
        return
    for inv_id in completed_ids:
        try:
            purged = await purge_arq_jobs_for_investigation(
                inv_id, track=track,
            )
            if purged.get("purged_jobs", 0):
                _log.info(
                    "investigation_reaper: arq-purged %d jobs for %s",
                    purged["purged_jobs"], inv_id,
                )
        except (OSError, RuntimeError, ImportError) as exc:
            _log.warning(
                "investigation_reaper: arq purge failed inv=%s err=%s",
                inv_id, exc,
            )


def _breach_reason_for_row(
    row: Any,
    now: Any,
    turn_cap: int,
    message_cap: int,
    wallclock_cutoff: Any,
    wallclock_hours: float,
    idle_grace_s: float,
) -> str | None:
    """Return a breach reason string or ``None`` if the row is healthy.

    Encapsulates the priority order (turn -> message -> wall-clock with
    idle grace) so per-id helper and the bulk sweep share the same
    decision tree. `row` is a tuple-ish (inv_id, clock_start,
    total_turns, total_messages, latest_act).
    """
    _, clock_start, total_turns, total_messages, latest_act = row
    if clock_start and getattr(clock_start, "tzinfo", None) is None:
        clock_start = clock_start.replace(tzinfo=now.tzinfo)
    if latest_act and getattr(latest_act, "tzinfo", None) is None:
        latest_act = latest_act.replace(tzinfo=now.tzinfo)
    if total_turns and total_turns >= turn_cap:
        return f"investigation_turn_cap:{total_turns}/{turn_cap}"
    if total_messages and total_messages >= message_cap:
        return f"investigation_message_cap:{total_messages}/{message_cap}"
    if clock_start and clock_start < wallclock_cutoff:
        if latest_act is not None:
            idle_s = (now - latest_act).total_seconds()
            if idle_s < idle_grace_s:
                return None  # alive -- calendar age doesn't kill
        age_hours = (now - clock_start).total_seconds() / 3600.0
        return (
            f"investigation_wall_clock:{age_hours:.1f}h/"
            f"{wallclock_hours:.1f}h"
        )
    return None


async def _flip_branches_and_inv_to_completed(
    uow: UnitOfWork,
    inv_id: str,
    reason: str,
    now: Any,
    *,
    branch_model: Any,
    investigation_model: Any,
) -> None:
    """Atomic two-update cascade shared by sweep + per-id paths."""
    BR = branch_model
    INV = investigation_model
    await uow.session.exec(
        update(BR)
        .where(
            BR.investigation_id == inv_id,
            BR.status == BranchStatus.ACTIVE.value,
        )
        .values(
            status=BranchStatus.ABANDONED.value,
            closed_reason=f"cap_exceeded:{reason}",
            closed_at=now,
            updated_at=now,
        )
        .execution_options(synchronize_session=False),
    )
    await uow.session.exec(
        update(INV)
        .where(and_(INV.id == inv_id, INV.status == InvestigationStatus.RUNNING.value))
        .values(
            status=InvestigationStatus.COMPLETED.value,
            stopped_at=now,
            updated_at=now,
        )
        .execution_options(synchronize_session=False),
    )


async def evaluate_cap_for_investigation(
    investigation_id: str,
    *,
    investigation_model: Any,
    branch_model: Any,
    message_model: Any,
    track: str,
    cap_resolver: Callable[[], Awaitable[CapConfig]],
) -> str | None:
    """Per-id cap check used by :func:`finalize_investigation`.

    Returns the breach reason string (matching the sweep's
    ``cap_exceeded:<reason>`` format) when the cap fires, ``None``
    otherwise. On a fired breach, completes the cascade (halt
    branches + flip investigation + ARQ purge) atomically.

    Phase C extraction: the bulk sweep below now delegates to this
    function per row, so the sweep + chokepoint produce identical
    outcomes from one decision tree.
    """
    caps = await cap_resolver()
    turn_cap = caps.turn_cap
    message_cap = caps.message_cap
    wallclock_hours = caps.wallclock_hours
    wallclock_cutoff = utc_now() - timedelta(hours=wallclock_hours)
    idle_grace_s = caps.idle_grace_s

    INV = investigation_model
    BR = branch_model
    MSG = message_model
    now = utc_now()

    async with UnitOfWork() as uow:
        # One row with the same shape the sweep produces.
        row = (await uow.session.exec(
            select(
                INV.id,
                coalesce(INV.started_at, INV.created_at).label("clock_start"),
                (
                    select(coalesce(func.sum(BR.turn_count), 0))
                    .where(BR.investigation_id == INV.id)
                    .scalar_subquery()
                ),
                (
                    select(func.count(MSG.id))
                    .where(MSG.investigation_id == INV.id)
                    .scalar_subquery()
                ),
                (
                    select(func.max(BR.updated_at))
                    .where(
                        BR.investigation_id == INV.id,
                        BR.status == BranchStatus.ACTIVE.value,
                    )
                    .scalar_subquery()
                ),
            ).where(
                INV.id == investigation_id,
                INV.status == InvestigationStatus.RUNNING.value,
            ),
        )).first()
        if row is None:
            return None
        reason = _breach_reason_for_row(
            row, now, turn_cap, message_cap, wallclock_cutoff,
            wallclock_hours, idle_grace_s,
        )
        if reason is None:
            return None
        await _flip_branches_and_inv_to_completed(
            uow, investigation_id, reason, now,
            branch_model=branch_model,
            investigation_model=investigation_model,
        )
        await uow.commit()
        _log.warning(
            "investigation_reaper: cap exceeded -- %s reason=%s",
            investigation_id, reason,
        )
    await _purge_arq_for_completed([investigation_id], track=track)
    return reason


async def sweep_cap_exceeded_investigations(
    *,
    investigation_model: Any,
    branch_model: Any,
    message_model: Any,
    track: str,
    cap_resolver: Callable[[], Awaitable[CapConfig]],
) -> int:
    """Find RUNNING investigations past any cap, halt branches, complete,
    purge their pending ARQ jobs.

    Returns the number of investigations transitioned to COMPLETED.

    Phase C: now delegates per-row to
    :func:`evaluate_cap_for_investigation`. The sweep enumerates
    candidates; per-id evaluation owns the decision + action so the
    chokepoint and the cron produce identical outcomes.
    """
    INV = investigation_model
    async with UnitOfWork() as uow:
        running_ids = (await uow.session.exec(
            select(INV.id).where(INV.status == InvestigationStatus.RUNNING.value),
        )).all()

    completed = 0
    for inv_id in running_ids:
        try:
            reason = await evaluate_cap_for_investigation(
                str(inv_id),
                investigation_model=investigation_model,
                branch_model=branch_model,
                message_model=message_model,
                track=track,
                cap_resolver=cap_resolver,
            )
        except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError) as exc:
            # fix §350 -- surface traceback so a per-id eval failure
            # (cap evaluation crash, FK regression) is debuggable from
            # the cron log instead of only the class name.
            _log.warning(
                "investigation_reaper: per-id eval failed inv=%s err=%s",
                inv_id, exc,
                exc_info=True,
            )
            continue
        if reason is not None:
            completed += 1
    return completed
