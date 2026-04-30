"""Automation schedule request/response schemas.

Pydantic models for the /automation/schedules CRUD API (AUTO-04/AUTO-05).
Separate from internal AutomationScheduleRecord to avoid leaking DB shape.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

__all__ = [
    "AutomationActionResponse",
    "AutomationScheduleCreate",
    "AutomationScheduleResponse",
    "AutomationScheduleUpdate",
]


class AutomationScheduleCreate(BaseModel):
    """Request body for POST /automation/schedules."""

    action_id: str
    target_name: str
    cron_expression: str
    action_kwargs: dict | None = Field(default=None)
    enabled: bool = True


class AutomationScheduleUpdate(BaseModel):
    """Request body for PATCH /automation/schedules/{schedule_id}."""

    cron_expression: str | None = None
    action_kwargs: dict | None = None
    enabled: bool | None = None


class AutomationScheduleResponse(BaseModel):
    """Response model for a single automation schedule."""

    id: str
    action_id: str
    target_name: str
    cron_expression: str
    action_kwargs: dict
    enabled: bool
    team_id: str | None
    created_by: str
    created_at: str
    updated_at: str
    last_run_at: str | None
    last_run_result: str | None


class AutomationActionResponse(BaseModel):
    """Response model for a registered automation action."""

    action_id: str
    description: str
    module_id: str
