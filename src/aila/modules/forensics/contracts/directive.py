"""Analyst directive contract models for the forensics module."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "AnalystDirective",
    "AnalystDirectiveCreate",
]


class AnalystDirectiveCreate(BaseModel):
    """Inbound payload for creating a directive."""

    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=4000)
    investigation_id: str | None = Field(
        default=None,
        description=(
            "When set, the directive applies only to that investigation. "
            "When omitted, the directive is project-wide and applies to "
            "every investigation under the project."
        ),
    )
    strategy_family: str | None = Field(
        default=None,
        description="Optional explicit strategy-family pin for the reasoning engine.",
    )
    required_artifact: str | None = Field(
        default=None,
        description="Optional artifact identifier/path the answer must cite before submission.",
    )


class AnalystDirective(BaseModel):
    """A persisted analyst directive returned by the API."""

    model_config = ConfigDict(extra="forbid")

    id: str
    project_id: str
    investigation_id: str | None = None
    text: str
    created_by: str | None = None
    created_at: datetime
    resolved_at: datetime | None = None
    active: bool = True
    verdict: str | None = None
    strategy_family: str | None = None
    required_artifact: str | None = None
    source_investigation_id: str | None = None
    source_answer_id: str | None = None

    @property
    def scope(self) -> str:
        return "investigation" if self.investigation_id else "project"
