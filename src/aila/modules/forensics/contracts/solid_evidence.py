"""Solid evidence contract models.

Analyst-tagged findings from a completed investigation, stored as
first-class rows so the UI can render them on the Solid Evidence tab
and the investigator can inject them into the prompt of every future
run.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "SolidEvidence",
    "TagInvestigationRequest",
    "TagVerdict",
]

TagVerdict = Literal["true", "false"]


class TagInvestigationRequest(BaseModel):
    """Inbound payload when the analyst tags a completed investigation."""

    model_config = ConfigDict(extra="forbid")

    verdict: TagVerdict
    answer_id: str | None = Field(
        default=None,
        description=(
            "When set, the tag is bound to a specific answer candidate "
            "row. When omitted, the investigation's final answer is "
            "used verbatim."
        ),
    )
    notes: str = Field(default="", max_length=4000)


class SolidEvidence(BaseModel):
    """A persisted analyst-tagged finding returned by the API."""

    model_config = ConfigDict(extra="forbid")

    id: str
    project_id: str
    question: str
    answer: str
    verdict: TagVerdict
    confidence: str
    source_investigation_id: str | None = None
    source_answer_id: str | None = None
    source_directive_id: str | None = None
    primary_artifact: str | None = None
    corroboration: list[str] = Field(default_factory=list)
    tagged_by: str | None = None
    tagged_at: datetime
    notes: str = ""
