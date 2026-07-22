"""Pattern catalog contracts (Knowledge Transfer plan GA-41).

The pattern catalog stores reusable techniques extracted from successful
investigations. v1 ships the structured fields + KnowledgeEntryRecord
mirror namespace; success-rate tracking + chain links land in v1.1.
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aila.platform.contracts.enums import PatternConfidence, PatternScope, PatternStatus

__all__ = [
    "PatternConfidence",
    "PatternKind",
    "PatternScope",
    "PatternStatus",
    "VRPatternCreate",
    "VRPatternPatch",
    "VRPatternSummary",
]


class PatternKind(StrEnum):
    """The 5 pattern kinds per GA-41."""

    EXPLOITATION_TECHNIQUE = "exploitation_technique"
    FUZZING_STRATEGY = "fuzzing_strategy"
    SEARCH_HEURISTIC = "search_heuristic"
    TOOL_RECIPE = "tool_recipe"
    TRIAGE_RULE = "triage_rule"


class VRPatternCreate(BaseModel):
    """Operator-created pattern (manual entry path).

    Auto-extracted patterns use the same shape but with ``status=draft``.
    """

    model_config = ConfigDict(extra="forbid")

    workspace_id: str = Field(min_length=1, max_length=64)
    investigation_id: str | None = Field(
        default=None,
        max_length=64,
        description=(
            "Originating investigation when auto-extracted. None for "
            "manual operator-created patterns."
        ),
    )
    kind: PatternKind
    summary: str = Field(
        min_length=1,
        max_length=512,
        description="One-sentence operator-recognizable description.",
    )
    body: str = Field(
        min_length=1,
        description="Full pattern body with example code/queries/output.",
    )
    applicability: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Applicability filter -- keys include target_kinds (list[str]), "
            "languages (list[str]), bug_classes (list[str])."
        ),
    )
    confidence: PatternConfidence = PatternConfidence.MEDIUM
    evidence_refs: list[str] = Field(
        default_factory=list,
        description="Message / outcome IDs that demonstrate the pattern.",
    )
    scope: PatternScope = PatternScope.LOCAL


class VRPatternPatch(BaseModel):
    """Partial update -- operator-driven review + promotion.

    Promotion is one-way (scope can only widen). Demotion goes through
    status=archived instead.
    """

    model_config = ConfigDict(extra="forbid")

    summary: str | None = Field(default=None, min_length=1, max_length=512)
    body: str | None = Field(default=None, min_length=1)
    applicability: dict[str, Any] | None = None
    confidence: PatternConfidence | None = None
    status: PatternStatus | None = None
    scope: PatternScope | None = None
    superseded_by: str | None = Field(default=None, max_length=64)


class VRPatternSummary(BaseModel):
    """Read-only projection of a pattern."""

    model_config = ConfigDict(extra="forbid")

    id: str
    workspace_id: str
    investigation_id: str | None
    kind: PatternKind
    summary: str
    body: str
    applicability: dict[str, Any] = Field(default_factory=dict)
    confidence: PatternConfidence
    evidence_refs: list[str] = Field(default_factory=list)
    status: PatternStatus
    scope: PatternScope
    superseded_by: str | None = None
    knowledge_entry_id: int | None = None
    times_retrieved: int = 0
    last_used_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
