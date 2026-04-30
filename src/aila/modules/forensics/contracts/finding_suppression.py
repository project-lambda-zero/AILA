"""Contract models for analyst-marked false-positive auto-findings."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "FindingSuppression",
    "FindingSuppressionRequest",
]


class FindingSuppressionRequest(BaseModel):
    """Inbound payload for suppressing an auto-finding as false positive."""

    model_config = ConfigDict(extra="forbid")

    fingerprint: str = Field(min_length=1, max_length=64)
    artifact_type: str | None = None
    executable: str | None = None
    path: str | None = None
    name: str | None = None
    finding_user: str | None = None
    reasons: list[str] = Field(default_factory=list)
    notes: str = Field(default="", max_length=4000)


class FindingSuppression(BaseModel):
    """A persisted finding suppression returned by the API."""

    model_config = ConfigDict(extra="forbid")

    id: str
    project_id: str
    fingerprint: str
    artifact_type: str | None = None
    executable: str | None = None
    path: str | None = None
    name: str | None = None
    finding_user: str | None = None
    reasons: list[str] = Field(default_factory=list)
    notes: str = ""
    source_directive_id: str | None = None
    suppressed_by: str | None = None
    suppressed_at: datetime
