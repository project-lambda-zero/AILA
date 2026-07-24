"""Pattern record + contract bases shared by the investigation engine (RFC-01).

A concrete module pattern collapses to::

    class VRPatternRecord(PatternRecordBase, table=True):
        __tablename__ = "vr_patterns"
        __workspace_tablename__ = "vr_workspaces"
        __investigation_tablename__ = "vr_investigations"

The vr and malware pattern tables carry the same 17 columns. Only the
``kind`` enum differs across modules (five vr kinds vs. six malware
kinds), so the ``kind`` field lives on the concrete Pydantic subclasses
while the DB column stays a plain ``str`` on the record base.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, ClassVar
from uuid import uuid4

from pydantic import BaseModel, ConfigDict
from pydantic import Field as PField
from sqlalchemy import DateTime, Text
from sqlmodel import Field, SQLModel

from aila.storage.mixins import TeamScopedMixin

from ._common import utc_now
from ._naming import TableDerivedConstraintsMixin, TabledFk
from .enums import PatternConfidence, PatternScope, PatternStatus

__all__ = [
    "PatternCreateBase",
    "PatternPatchBase",
    "PatternRecordBase",
    "PatternSummaryBase",
]


class PatternRecordBase(TableDerivedConstraintsMixin, TeamScopedMixin, SQLModel):
    """Shared columns for every module's pattern catalog table (GA-41).

    A concrete subclass MUST set ``__tablename__``,
    ``__workspace_tablename__``, ``__investigation_tablename__``, and
    ``table=True``. The FK constraints are derived from those tablename
    class vars by ``TableDerivedConstraintsMixin`` at class-creation time.
    """

    __workspace_tablename__: ClassVar[str]
    __investigation_tablename__: ClassVar[str]
    __table_args__ = (
        TabledFk("workspace_id", target_attr="__workspace_tablename__"),
        TabledFk("investigation_id", target_attr="__investigation_tablename__"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)

    workspace_id: str = Field(index=True)
    investigation_id: str | None = Field(default=None, index=True)

    kind: str = Field(max_length=32, index=True)         # PatternKind (module-specific)
    summary: str = Field(max_length=512)
    body: str = Field(default="", sa_type=Text, sa_column_kwargs={"nullable": True})

    applicability_json: str = Field(default="{}", sa_type=Text, sa_column_kwargs={"nullable": True})
    confidence: str = Field(default="medium", max_length=16, index=True)
    evidence_refs_json: str = Field(default="[]", sa_type=Text, sa_column_kwargs={"nullable": True})

    status: str = Field(default="draft", max_length=16, index=True)
    scope: str = Field(default="local", max_length=16, index=True)
    superseded_by: str | None = Field(default=None, max_length=64, index=True)

    # Mirror entry id in KnowledgeService -- populated on insert by PatternStore.
    knowledge_entry_id: int | None = Field(default=None, index=True)

    # Usage counters (v1 increments ``times_retrieved`` on retrieve; full
    # success-rate tracking lands in v1.1 via module-side ``*_pattern_usages``).
    times_retrieved: int = Field(default=0)
    last_used_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))

    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class PatternSummaryBase(BaseModel):
    """Shared read-only pattern projection. Modules add their ``kind`` enum."""

    model_config = ConfigDict(extra="forbid")

    id: str
    workspace_id: str
    investigation_id: str | None
    summary: str
    body: str
    applicability: dict[str, Any] = PField(default_factory=dict)
    confidence: PatternConfidence
    evidence_refs: list[str] = PField(default_factory=list)
    status: PatternStatus
    scope: PatternScope
    superseded_by: str | None = None
    knowledge_entry_id: int | None = None
    times_retrieved: int = 0
    last_used_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class PatternCreateBase(BaseModel):
    """Shared pattern create payload. Modules add their ``kind`` enum.

    Auto-extracted patterns use the same shape but with ``status=draft``.
    """

    model_config = ConfigDict(extra="forbid")

    workspace_id: str = PField(min_length=1, max_length=64)
    investigation_id: str | None = PField(
        default=None,
        max_length=64,
        description=(
            "Originating investigation when auto-extracted. None for "
            "manual operator-created patterns."
        ),
    )
    summary: str = PField(
        min_length=1,
        max_length=512,
        description="One-sentence operator-recognizable description.",
    )
    body: str = PField(
        min_length=1,
        description="Full pattern body with example code / queries / output.",
    )
    applicability: dict[str, Any] = PField(
        default_factory=dict,
        description=(
            "Applicability filter -- module-specific keys (target_kinds, "
            "languages, bug_classes, families, capabilities, ...)."
        ),
    )
    confidence: PatternConfidence = PatternConfidence.MEDIUM
    evidence_refs: list[str] = PField(
        default_factory=list,
        description="Observation / message / outcome ids supporting the pattern.",
    )
    scope: PatternScope = PatternScope.LOCAL


class PatternPatchBase(BaseModel):
    """Shared pattern partial-update payload -- operator review + promotion.

    Promotion is one-way (scope can only widen). Demotion goes through
    ``status=archived`` instead.
    """

    model_config = ConfigDict(extra="forbid")

    summary: str | None = PField(default=None, min_length=1, max_length=512)
    body: str | None = PField(default=None, min_length=1)
    applicability: dict[str, Any] | None = None
    confidence: PatternConfidence | None = None
    status: PatternStatus | None = None
    scope: PatternScope | None = None
    superseded_by: str | None = PField(default=None, max_length=64)
