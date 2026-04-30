"""Audit event and seal API response schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from .common import APIModel, PaginatedResponse

__all__ = [
    "AuditEventResponse",
    "AuditListResponse",
    "AuditSealListResponse",
    "AuditSealResponse",
]


class AuditEventResponse(APIModel):
    """A single immutable audit trail entry.

    Mirrors AuditEventRecord. details is deserialized from details_json.
    """

    id: int | None = Field(default=None, description="Database primary key")
    run_id: str = Field(description="Workflow run this event belongs to")
    stage: str = Field(description="Pipeline stage that emitted this event")
    action: str = Field(description="Action performed (e.g. scan.start, ssh.execute)")
    status: str = Field(default="completed", description="Event outcome status")
    target: str = Field(default="", description="Target system or resource affected")
    user_id: str = Field(default="system", description="User or service that triggered the action")
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured event details (deserialized from details_json)",
    )
    created_at: datetime | None = Field(default=None, description="When this event was recorded")


AuditListResponse = PaginatedResponse[AuditEventResponse]
AuditListResponse.__doc__ = "Paginated list of audit events."


class AuditSealResponse(APIModel):
    """A single cryptographic audit seal record.

    Mirrors AuditSealRecord fields. prompt_content and response_content
    are excluded by default -- only included when ?include_content=true
    is passed to the endpoint.
    """

    id: int | None = Field(default=None, description="Database primary key")
    run_id: str = Field(description="Scan run this seal belongs to")
    seal_hash: str = Field(description="HMAC-SHA256 hex digest")
    input_hash: str = Field(description="SHA-256 of serialized messages")
    output_hash: str = Field(description="SHA-256 of response content")
    model_id: str = Field(description="Model used for this LLM call")
    task_type: str = Field(description="Task type (e.g. scoring, synthesis)")
    timestamp: datetime = Field(description="When the seal was computed (UTC)")
    classification: str | None = Field(default=None, description="Data classification level")
    confidence: str | None = Field(default=None, description="Confidence gating result")
    evidence_validation_pass: bool | None = Field(default=None, description="Evidence validation overall result")
    content_stored: bool = Field(default=False, description="Whether prompt/response content was stored")
    prompt_content: str | None = Field(default=None, description="Serialized prompt messages (only with include_content=true)")
    response_content: str | None = Field(default=None, description="LLM response content (only with include_content=true)")
    created_at: datetime | None = Field(default=None, description="Record creation timestamp")


AuditSealListResponse = PaginatedResponse[AuditSealResponse]
AuditSealListResponse.__doc__ = "Paginated list of audit seal records."
