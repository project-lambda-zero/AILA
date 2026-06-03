"""Periodic cap-exceeded sweep for VR investigations.

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
mechanism (halt branches + complete investigation + arq-purge):

  VR_INVESTIGATION_TURN_CAP            (default 300, sum of branch turns)
  VR_INVESTIGATION_MESSAGE_CAP         (default 1000, total messages)
  VR_INVESTIGATION_WALL_CLOCK_HOURS    (default 6, investigation lifetime)

The emit-side check stays in place as belt+suspenders — it catches
the cap faster (immediately on the turn that breached it) and lets
the emit path log the breach next to the turn that caused it. The
reaper is the catch-net for the stuck-worker case.
"""
from __future__ import annotations

import logging
import os
from datetime import timedelta

from sqlalchemy import and_, func, select, update
from sqlalchemy.sql.functions import coalesce

from aila.modules.vr.contracts import BranchStatus, InvestigationStatus
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationRecord,
)
from aila.platform.contracts._common import utc_now
from aila.platform.uow import UnitOfWork

__all__ = ["sweep_cap_exceeded_investigations"]

_log = logging.getLogger(__name__)


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def _float_env(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    try:
        return float(raw) if raw else default
    except ValueError:
        return default


async def sweep_cap_exceeded_investigations() -> int:
    """Find RUNNING investigations past any cap, halt branches, complete,
    purge their pending ARQ jobs.

    Returns the number of investigations transitioned to COMPLETED.
    """
    turn_cap = _int_env("VR_INVESTIGATION_TURN_CAP", 300)
    message_cap = _int_env("VR_INVESTIGATION_MESSAGE_CAP", 1000)
    wallclock_hours = _float_env("VR_INVESTIGATION_WALL_CLOCK_HOURS", 6.0)
    wallclock_cutoff = utc_now() - timedelta(hours=wallclock_hours)

    INV = VRInvestigationRecord  # noqa: N806
    BR = VRInvestigationBranchRecord  # noqa: N806
    MSG = VRInvestigationMessageRecord  # noqa: N806

    completed_ids: list[str] = []

    async with UnitOfWork() as uow:
        # Per-investigation aggregates. One query returns
        # (inv_id, clock_start, total_turns, total_messages).
        # total_turns = sum of all branch.turn_count for that inv.
        # total_messages = count of vr_investigation_messages.
        branch_turns = (
            select(
                BR.investigation_id.label("inv_id"),
                coalesce(func.sum(BR.turn_count), 0).label("total_turns"),
            )
            .group_by(BR.investigation_id)
            .subquery()
        )
        msg_counts = (
            select(
                MSG.investigation_id.label("inv_id"),
                func.count(MSG.id).label("total_messages"),
            )
            .group_by(MSG.investigation_id)
            .subquery()
        )
        running = (await uow.session.exec(
            select(
                INV.id,
                # Clock from started_at (first turn) falling back to
                # created_at if the worker hasn't stamped it yet. Using
                # created_at directly punishes investigations that sat
                # queued during long target ingestion — they'd insta-cap
                # the moment a worker finally picked them up. See the
                # 9e99eda0 incident (32h queue wait, all branches cap
                # killed on turn 1 with zero execution time).
                coalesce(INV.started_at, INV.created_at).label("clock_start"),
                coalesce(branch_turns.c.total_turns, 0),
                coalesce(msg_counts.c.total_messages, 0),
            )
            .outerjoin(branch_turns, branch_turns.c.inv_id == INV.id)
            .outerjoin(msg_counts, msg_counts.c.inv_id == INV.id)
            .where(INV.status == InvestigationStatus.RUNNING.value),
        )).all()

        now = utc_now()
        breaches: list[tuple[str, str]] = []
        for row in running:
            inv_id, clock_start, total_turns, total_messages = row
            if clock_start and clock_start.tzinfo is None:
                clock_start = clock_start.replace(tzinfo=now.tzinfo)
            reason = None
            if total_turns and total_turns >= turn_cap:
                reason = f"investigation_turn_cap:{total_turns}/{turn_cap}"
            elif total_messages and total_messages >= message_cap:
                reason = f"investigation_message_cap:{total_messages}/{message_cap}"
            elif clock_start and clock_start < wallclock_cutoff:
                age_hours = (now - clock_start).total_seconds() / 3600.0
                reason = (
                    f"investigation_wall_clock:{age_hours:.1f}h/"
                    f"{wallclock_hours:.1f}h"
                )
            if reason is not None:
                breaches.append((str(inv_id), reason))

        if not breaches:
            return 0

        for inv_id, reason in breaches:
            # Atomic cascade in two ORM updates:
            #   1. Flip all active branches to abandoned with the cap reason
            #   2. Flip the investigation to completed
            # No raw SQL — both are sqlalchemy update() with .where()
            # clauses referencing the related table so PostgreSQL
            # compiles to a single UPDATE ... WHERE per call.
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
            completed_ids.append(inv_id)
            _log.warning(
                "investigation_reaper: cap exceeded — %s reason=%s",
                inv_id, reason,
            )
        await uow.commit()

    # Best-effort ARQ purge so the queued auto-continue tasks for
    # capped investigations get dropped immediately rather than
    # waking workers up to short-circuit via STATUS_LOCKED.
    if completed_ids:
        try:
            from .arq_purge import purge_arq_jobs_for_investigation  # noqa: PLC0415
            for inv_id in completed_ids:
                try:
                    purged = await purge_arq_jobs_for_investigation(
                        inv_id, track="vr",
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
        except ImportError:
            pass

    return len(completed_ids)
