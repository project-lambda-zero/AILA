"""Contract models for activity log and dashboard statistics.

Design references: D-48, D-65, D-66.

These are pure Pydantic contract models — no SQLModel, no DB access.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from aila.api.schemas.common import APIModel

from .session import SessionSummaryResponse

__all__ = [
    "ActivityResponse",
    "DashboardStatsResponse",
]


class ActivityResponse(APIModel):
    """One activity log entry for a session.

    event_type: short slug describing the event (e.g. "session.created").
    actor_name: display name of the person who triggered the event (nullable).
    actor_email: email of the actor (nullable).
    detail: arbitrary event-specific metadata deserialized from detail_json.
    created_at: UTC timestamp when the event was recorded.
    """

    event_type: str
    actor_name: str | None = None
    actor_email: str | None = None
    detail: dict = Field(default_factory=dict)
    created_at: datetime


class DashboardStatsResponse(APIModel):
    """Architect-facing dashboard statistics per D-48.

    session_counts_by_status: mapping of status string to count
        (e.g. {"draft": 5, "completed": 12}).
    recent_sessions: up to 10 most recently updated sessions.
    completion_rate: (completed + resolved) / total non-draft sessions,
        0.0 when no non-draft sessions exist.
    avg_time_to_complete_hours: mean hours from created_at to status='completed'
        across all completed sessions; None when no completed sessions exist.
    total_sessions: total non-deleted session count (all statuses).
    """

    session_counts_by_status: dict[str, int]
    recent_sessions: list[SessionSummaryResponse] = Field(default_factory=list)
    completion_rate: float = 0.0
    avg_time_to_complete_hours: float | None = None
    total_sessions: int = 0
