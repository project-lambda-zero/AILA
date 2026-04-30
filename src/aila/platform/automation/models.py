"""Platform-owned automation schedule model."""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now
from aila.storage.mixins import TeamScopedMixin


class AutomationScheduleRecord(TeamScopedMixin, SQLModel, table=True):
    """Generic platform-owned automation schedule.

    Replaces module-owned ScheduledScanRecord. Any module can register
    automatable actions; schedules reference actions by action_id.

    Written by: CRUD API (POST /automation/schedules).
    Consumed by: AutomationRunner.tick() to evaluate due schedules.
    """

    __tablename__ = "automation_schedule_records"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    action_id: str = Field(index=True)
    target_name: str = Field(index=True)
    cron_expression: str
    action_kwargs_json: str = Field(default="{}", sa_column=Column(Text))
    enabled: bool = Field(default=True, index=True)
    created_by: str = Field(index=True)
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    last_run_at: datetime | None = Field(default=None, nullable=True, sa_type=DateTime(timezone=True))
    last_run_result: str | None = Field(default=None, nullable=True)
