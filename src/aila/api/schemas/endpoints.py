"""Request and response schemas for Plan C endpoints.

Covers: dashboard, search, tags, finding workflow, saved filters, widget
layout, scheduled reports, and notifications.

All schemas are the inner payload type for DataEnvelope[T].
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

__all__ = [
    "DashboardResponse",
    "ExecutiveHealthResponse",
    "FindingTransitionRequest",
    "FindingWorkflowHistoryResponse",
    "FindingWorkflowStateResponse",
    "FleetStats",
    "NotificationResponse",
    "OIDCAuthorizeResponse",
    "SavedFilterCreate",
    "SavedFilterResponse",
    "SavedFilterUpdate",
    "ScheduledReportCreate",
    "ScheduledReportResponse",
    "ScheduledReportTriggerResponse",
    "ScheduledReportUpdate",
    "SearchResult",
    "TagAssignRequest",
    "TagResponse",
    "TagVocabCreate",
    "TagVocabResponse",
    "UnreadNotificationsResponse",
    "WidgetLayoutRequest",
    "WidgetLayoutResponse",
    "WorkflowStateDefinition",
]


class FleetStats(BaseModel):
    total_systems: int
    online_systems: int
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int


class DashboardResponse(BaseModel):
    risk_score: float = Field(ge=0.0, le=10.0, description="Composite platform risk score 0-10")
    fleet_stats: FleetStats
    module_data: dict[str, Any] = Field(default_factory=dict)
    generated_at: datetime


class SearchResult(BaseModel):
    entity_type: str
    entity_id: str
    title: str
    snippet: str = ""
    module_id: str | None = None
    score: float = 1.0


class TagVocabCreate(BaseModel):
    tag_key: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_\-]+$")
    description: str = Field(default="", max_length=255)


class TagVocabResponse(BaseModel):
    id: str
    tag_key: str
    description: str
    is_system_default: bool
    created_at: datetime


class TagAssignRequest(BaseModel):
    tag_key: str = Field(min_length=1, max_length=64)
    tag_value: str = Field(default="", max_length=255)


class TagResponse(BaseModel):
    id: int
    system_id: int
    tag_key: str
    tag_value: str
    created_at: datetime


class FindingTransitionRequest(BaseModel):
    target_state: str
    notes: str = Field(default="", max_length=2048)
    module_id: str = Field(default="platform")


class FindingWorkflowHistoryResponse(BaseModel):
    id: str
    finding_id: str
    module_id: str
    current_state: str
    previous_state: str | None
    transitioned_by: str
    notes: str
    created_at: datetime


class FindingWorkflowStateResponse(BaseModel):
    finding_id: str
    current_state: str
    history: list[FindingWorkflowHistoryResponse]


class SavedFilterCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    entity_type: str
    filter_json: str = Field(default="{}")
    is_pinned: bool = False
    shared_with_team: bool = False


class SavedFilterUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    filter_json: str | None = None
    is_pinned: bool | None = None
    shared_with_team: bool | None = None


class SavedFilterResponse(BaseModel):
    id: str
    user_id: str
    name: str
    entity_type: str
    filter_json: str
    is_pinned: bool
    shared_with_team: bool
    created_at: datetime
    updated_at: datetime


class WidgetLayoutRequest(BaseModel):
    layout_json: str = Field(description="Frontend-owned JSON layout descriptor (max 64KB)")

    @field_validator("layout_json")
    @classmethod
    def _validate_size(cls, v: str) -> str:
        if len(v.encode("utf-8")) > 64 * 1024:
            raise ValueError("layout_json exceeds 64KB limit")
        return v


class WidgetLayoutResponse(BaseModel):
    user_id: str
    layout_json: str
    updated_at: datetime


class ScheduledReportCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    report_type: str
    cron_expression: str
    recipient_emails_json: str = Field(default="[]")
    config_json: str = Field(default="{}")
    is_active: bool = True


class ScheduledReportUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    cron_expression: str | None = None
    recipient_emails_json: str | None = None
    config_json: str | None = None
    is_active: bool | None = None


class ScheduledReportResponse(BaseModel):
    id: str
    name: str
    report_type: str
    cron_expression: str
    recipient_emails_json: str
    config_json: str
    is_active: bool
    last_run_at: datetime | None
    created_by: str
    created_at: datetime
    updated_at: datetime


class NotificationResponse(BaseModel):
    id: str
    user_id: str
    title: str
    body: str
    category: str
    source_module: str | None
    source_entity_id: str | None
    is_read: bool
    created_at: datetime
    read_at: datetime | None


class UnreadNotificationsResponse(BaseModel):
    unread_count: int
    items: list[NotificationResponse]


class WorkflowStateDefinition(BaseModel):
    states: list[str]
    transitions: dict[str, list[str]]


class ExecutiveHealthResponse(BaseModel):
    """Fleet-wide risk posture summary for the executive dashboard."""

    total_findings: int = Field(description="Total number of active findings across all systems")
    severity_breakdown: dict[str, int] = Field(
        description="Finding counts by severity level (Immediate, High, Moderate, Planned)",
    )
    last_scanned_at: str | None = Field(
        default=None,
        description="ISO-8601 timestamp of the most recent scan across all findings",
    )
    systems_with_findings: int = Field(description="Number of distinct systems with at least one finding")


class OIDCAuthorizeResponse(BaseModel):
    """Response for GET /auth/oidc/authorize with the redirect URL."""

    authorization_url: str = Field(description="Microsoft OIDC authorization URL to redirect the user")


class ScheduledReportTriggerResponse(BaseModel):
    """Response for POST /scheduled-reports/{report_id}/trigger."""

    report_id: str = Field(description="Scheduled report that was triggered")
    task_id: str = Field(description="Background task ID for polling (or 'manual' if arq unavailable)")
    status: str = Field(description="Trigger status (queued)")
