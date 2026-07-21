"""Platform-owned automation schedule model."""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now
from aila.storage.mixins import TeamScopedMixin

__all__ = ["AutomationScheduleRecord"]


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
