"""Forensics pattern catalog contracts (RFC-12 Phase 4).

The forensics pattern catalog stores reusable techniques extracted from
completed investigations. Mirrors the VR and malware pattern contracts;
only the ``kind`` enum carries forensics-domain values. The structured
fields are queryable via ``ForensicsPatternRecord``; the body + embedding
live in a mirrored ``KnowledgeEntryRecord`` under namespace
``forensics.pattern.<scope>.<id>``.
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
    "ForensicsPatternCreate",
    "ForensicsPatternKind",
    "ForensicsPatternPatch",
    "ForensicsPatternSummary",
    "PatternConfidence",
    "PatternScope",
    "PatternStatus",
]


class ForensicsPatternKind(StrEnum):
    """Forensics-domain pattern kinds."""

    EVIDENCE_TECHNIQUE = "evidence_technique"
    ANALYSIS_PATTERN = "analysis_pattern"
    ARTIFACT_SIGNATURE = "artifact_signature"
    TOOL_RECIPE = "tool_recipe"
    TRIAGE_RULE = "triage_rule"


class ForensicsPatternCreate(BaseModel):
    """Pattern create payload.

    Auto-extracted patterns use the same shape with ``status=draft``.
    Forensics uses the project id as the ``workspace_id``.
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
    kind: ForensicsPatternKind
    summary: str = Field(
        min_length=1,
        max_length=512,
        description="One-sentence operator-recognizable description.",
    )
    body: str = Field(
        min_length=1,
        description="Full pattern body with example evidence/queries/output.",
    )
    applicability: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Applicability filter -- keys include artifact_kinds (list[str]), "
            "os_families (list[str]), evidence_classes (list[str])."
        ),
    )
    confidence: PatternConfidence = PatternConfidence.MEDIUM
    evidence_refs: list[str] = Field(
        default_factory=list,
        description="Message / outcome IDs that demonstrate the pattern.",
    )
    scope: PatternScope = PatternScope.LOCAL
    # RFC-08 memory-poisoning fields (mirror ``PatternCreateBase``).
    trust_tier: PatternTrustTier = PatternTrustTier.UNREVIEWED
    provenance: dict[str, Any] = Field(default_factory=dict)


class ForensicsPatternPatch(BaseModel):
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


class ForensicsPatternSummary(BaseModel):
    """Read-only projection of a pattern."""

    model_config = ConfigDict(extra="forbid")

    id: str
    workspace_id: str
    investigation_id: str | None
    kind: ForensicsPatternKind
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
    # RFC-08 memory-poisoning fields (mirror ``PatternSummaryBase``).
    trust_tier: PatternTrustTier = PatternTrustTier.UNREVIEWED
    provenance: dict[str, Any] = Field(default_factory=dict)
