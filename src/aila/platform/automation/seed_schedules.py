"""Idempotent seeding of platform-owned automation schedules.

RFC-08 Tier D activation: the calibration proposer sweep and calibrator
trainer sweep are registered as automation actions in
:mod:`aila.platform.automation.maintenance`, but the fit + propose paths
stay dormant until an :class:`AutomationScheduleRecord` exists that
targets their action_id. Historically operators had to create these rows
by hand via ``POST /automation/schedules`` before either sweep ever
fired, which is why zero fitted calibrator versions ever shipped.

:func:`seed_default_automation_schedules` runs during API startup and
inserts a single platform-scoped (team_id=None) schedule per calibration
sweep IF no row already targets that action_id. Operator overrides
(cron, enabled, kwargs) survive restart untouched -- the seed only
writes when the action_id has no existing row at all.

Fault-tolerant by design: any DB / infra fault is logged and swallowed,
returning 0 seeded. A seed fault must never block API startup because
the entire calibration subsystem is advisory (candidates only until an
admin promotes) and the operator can always insert the schedule by
hand.
"""
from __future__ import annotations

__all__ = ["seed_default_automation_schedules"]

import logging

import sqlalchemy.exc
from sqlmodel import select

from aila.platform.automation.models import AutomationScheduleRecord
from aila.storage.database import async_session_scope

_log = logging.getLogger(__name__)


# One row per calibration sweep. Cron picked so the proposer aggregates
# the prior day's review history at 03:00 UTC and the trainer refits at
# 04:00 UTC on the same window (proposer writes first so the trainer
# sees the freshest CalibrationProposalRecord thresholds).
_DEFAULT_SCHEDULES: tuple[tuple[str, str], ...] = (
    ("platform.calibration_proposer_sweep", "0 3 * * *"),
    ("platform.calibrator_trainer_sweep", "0 4 * * *"),
    # Issue #150 semantic-tier consolidation. Runs after the calibration
    # sweeps so any refit that affects distillation routing has already
    # landed. Idempotent per investigation via the dedup-key existence
    # check in :mod:`aila.platform.services.memory.consolidator`, so a
    # tick with nothing new is a bounded, LLM-free no-op.
    ("platform.semantic_consolidation_sweep", "0 5 * * *"),
)

_SEED_ACTOR: str = "platform.seed_default_automation_schedules"


# Isolation tuple for the seed's failure modes. Mirrors the posture of
# platform_health_check's probes: any realistic DB / infra fault is
# captured, logged, and swallowed so a bad row cannot abort startup.
# Bare ``except Exception`` is banned by honesty audit rule 33.
_SEED_ERRORS: tuple[type[BaseException], ...] = (
    sqlalchemy.exc.SQLAlchemyError,
    OSError,
    RuntimeError,
    ValueError,
    TypeError,
    LookupError,
    ConnectionError,
    TimeoutError,
)


async def seed_default_automation_schedules() -> int:
    """Insert default calibration-sweep schedules that are missing.

    Idempotent: each action_id in ``_DEFAULT_SCHEDULES`` is checked for
    an existing :class:`AutomationScheduleRecord` (any team, any enabled
    state); when none exists a platform-scoped (team_id=None) row is
    created with the default cron. Existing rows are never touched so
    operator overrides survive restart.

    Returns the count of rows actually seeded. A DB / infra fault is
    logged and swallowed, returning 0 -- the calibration subsystem is
    advisory (candidates only until an admin promotes) so a seed fault
    must not block API startup.
    """
    seeded = 0
    try:
        async with async_session_scope() as session:
            for action_id, cron_expression in _DEFAULT_SCHEDULES:
                existing = (
                    await session.exec(
                        select(AutomationScheduleRecord).where(
                            AutomationScheduleRecord.action_id == action_id,
                        ),
                    )
                ).first()
                if existing is not None:
                    continue
                session.add(
                    AutomationScheduleRecord(
                        action_id=action_id,
                        target_name="platform",
                        cron_expression=cron_expression,
                        cron_timezone="UTC",
                        action_kwargs_json="{}",
                        enabled=True,
                        team_id=None,
                        created_by=_SEED_ACTOR,
                    ),
                )
                seeded += 1
            if seeded:
                await session.commit()
    except _SEED_ERRORS as exc:
        _log.warning(
            "seed_default_automation_schedules skipped (%s)",
            type(exc).__name__,
            exc_info=exc,
        )
        return 0
    if seeded:
        _log.info(
            "Seeded %d default automation schedules (calibration sweeps)",
            seeded,
        )
    return seeded
