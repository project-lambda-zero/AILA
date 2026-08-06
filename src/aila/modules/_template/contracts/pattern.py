"""Template pattern-catalog contract scaffold.

Mirrors :mod:`aila.modules.vr.contracts.pattern` at the minimum shape a
new module needs to wire the pattern-extractor + pattern-store residue.
Extend :class:`TemplatePatternKind` with module-specific kinds; the base
Pydantic model shape is fixed by
:mod:`aila.platform.services.pattern_store`.
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aila.platform.contracts.enums import (
    PatternConfidence,
    PatternScope,
    PatternStatus,
    PatternTrustTier,
)

__all__ = [
    "PatternConfidence",
    "PatternScope",
    "PatternStatus",
    "TemplatePatternCreate",
    "TemplatePatternKind",
    "TemplatePatternSummary",
]


class TemplatePatternKind(StrEnum):
    """Minimal pattern kind enum. Extend with module-specific kinds."""

    TRIAGE_RULE = "triage_rule"


class TemplatePatternCreate(BaseModel):
    """Pattern-create payload -- same shape as vr / malware."""

    model_config = ConfigDict(extra="forbid")

    workspace_id: str = Field(min_length=1, max_length=64)
    investigation_id: str | None = Field(default=None, max_length=64)
    kind: TemplatePatternKind
    summary: str = Field(min_length=1, max_length=512)
    body: str = Field(min_length=1)
    applicability: dict[str, Any] = Field(default_factory=dict)
    confidence: PatternConfidence = PatternConfidence.MEDIUM
    evidence_refs: list[str] = Field(default_factory=list)
    scope: PatternScope = PatternScope.LOCAL
    # RFC-08 memory-poisoning fields (mirror ``PatternCreateBase``).
    trust_tier: PatternTrustTier = PatternTrustTier.UNREVIEWED
    provenance: dict[str, Any] = Field(default_factory=dict)


class TemplatePatternSummary(BaseModel):
    """Read-only pattern projection returned by the pattern store."""

    model_config = ConfigDict(extra="forbid")

    id: str
    workspace_id: str
    investigation_id: str | None
    kind: TemplatePatternKind
    summary: str
    body: str = ""
    applicability: dict[str, Any] = Field(default_factory=dict)
    confidence: PatternConfidence
    evidence_refs: list[str] = Field(default_factory=list)
    status: PatternStatus
    scope: PatternScope
    superseded_by: str | None = None
    knowledge_entry_id: str | None = None
    times_retrieved: int = 0
    last_used_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    # RFC-08 memory-poisoning fields (mirror ``PatternSummaryBase``).
    trust_tier: PatternTrustTier = PatternTrustTier.UNREVIEWED
    provenance: dict[str, Any] = Field(default_factory=dict)
