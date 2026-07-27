"""Platform-owned automation schedule + run-history models."""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from aila.platform.contracts import utc_now
from aila.storage.mixins import TeamScopedMixin

__all__ = ["AutomationRunRecord", "AutomationScheduleRecord"]


class AutomationScheduleRecord(TeamScopedMixin, SQLModel, table=True):
    """Generic platform-owned automation schedule.

    Replaces module-owned ScheduledScanRecord. Any module can register
    automatable actions; schedules reference actions by action_id.

    Written by: CRUD API (POST /automation/schedules).
    Consumed by: AutomationRunner.tick() to evaluate due schedules.

    Timezone (#46-2): ``cron_expression`` is interpreted against
    ``cron_timezone`` (IANA name, default 'UTC') so a schedule like
    ``0 9 * * *`` fires at 9 AM in that zone rather than 9 AM UTC.
    A null or unrecognized zone name falls back to UTC in the runner.

    Disable-on-parse-error (#46-4b): when the runner cannot parse the
    cron expression or the timezone, it flips ``enabled`` to False and
    records the cause in ``disable_reason`` instead of raising every
    tick. Operators clear both fields to re-enable the schedule.
    """

    __tablename__ = "automation_schedule_records"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    action_id: str = Field(index=True)
    target_name: str = Field(index=True)
    cron_expression: str
    cron_timezone: str | None = Field(default="UTC", nullable=True)
    action_kwargs_json: str = Field(default="{}", sa_column=Column(Text))
    enabled: bool = Field(default=True, index=True)
    disable_reason: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    created_by: str = Field(index=True)
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    last_run_at: datetime | None = Field(default=None, nullable=True, sa_type=DateTime(timezone=True))
    last_run_result: str | None = Field(default=None, nullable=True)


class AutomationRunRecord(SQLModel, table=True):
    """History of one intended automation occurrence (#46).

    Every distinct ``(schedule_id, occurrence_at)`` tuple maps to a
    single row. ``occurrence_at`` is the cron-computed instant the
    schedule was meant to fire (last ``get_prev`` result at or before
    the runner's ``now``); two runner processes ticking the same
    schedule at the same tick derive the same bucket and race on this
    row.

    The ``UNIQUE(schedule_id, occurrence_at)`` constraint is both the
    run-history contract AND the second-order distributed-lock backstop
    for the Redis-based lock in ``platform/automation/lock.py``: when
    Redis is unavailable and the runner degrades to the DB fallback,
    the INSERT itself is the atomic claim -- the losing process sees
    ``IntegrityError`` and skips.

    outcome values written by the runner:
      - ``"running"``   -- inserted at run start, before submit.
      - ``"submitted:<task_id>"`` -- overwrites ``running`` after the
        queue submit returns; ``task_id`` also populated.
      - ``"error:<ExcType>"`` -- overwrites ``running`` after the
        isolation guard caught the submit path failing.

    Not team-scoped: the operator dashboard reading this table joins
    to ``automation_schedule_records`` for the team filter; keeping
    the run-history flat avoids an RLS policy that would need to
    duplicate the schedule table's policy.
    """

    __tablename__ = "automation_run_records"
    __table_args__ = (
        UniqueConstraint(
            "schedule_id",
            "occurrence_at",
            name="uq_automation_run_schedule_occurrence",
        ),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    schedule_id: str = Field(index=True)
    occurrence_at: datetime = Field(sa_type=DateTime(timezone=True))
    started_at: datetime = Field(sa_type=DateTime(timezone=True))
    finished_at: datetime | None = Field(default=None, nullable=True, sa_type=DateTime(timezone=True))
    outcome: str
    task_id: str | None = Field(default=None, nullable=True)
    runner_id: str | None = Field(default=None, nullable=True)
