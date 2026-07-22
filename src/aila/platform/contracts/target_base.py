"""Target record + contract bases shared by the investigation engine (RFC-01).

The vr and malware target tables share 18 columns; malware adds two
module-specific columns (``parent_target_id`` for unpack lineage,
``sha256`` for sample identity) that stay OUT of the base and are
declared on the concrete subclass. A concrete module target collapses
to::

    class VRTargetRecord(TargetRecordBase, table=True):
        __tablename__ = "vr_targets"
        __workspace_tablename__ = "vr_workspaces"

The tag-index base (D-52) is zero-domain: both modules already declare
it without ``TeamScopedMixin`` -- ``workspace_id`` carries the effective
scope -- and the base preserves that shape.

Modules subclass ``TargetSummaryBase`` / ``TargetCreateBase`` /
``TargetPatchBase`` to add their per-module ``kind`` enum and any
module-specific projections (e.g. malware's ``capability_profile``).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, ClassVar
from uuid import uuid4

from pydantic import BaseModel, ConfigDict
from pydantic import Field as PField
from sqlalchemy import Column, DateTime, Text
from sqlmodel import Field, SQLModel

from aila.storage.mixins import TeamScopedMixin

from ._common import utc_now
from ._naming import TableDerivedConstraintsMixin, TabledFk, TabledUq
from .enums import AnalysisState, TargetStatus, TargetTagSource

__all__ = [
    "TargetCreateBase",
    "TargetPatchBase",
    "TargetRecordBase",
    "TargetSummaryBase",
    "TargetTag",
    "TargetTagIndexBase",
]


class TargetRecordBase(TableDerivedConstraintsMixin, TeamScopedMixin, SQLModel):
    """Shared columns for every module's target table (D-49/D-50/D-51).

    A concrete subclass MUST set ``__tablename__``,
    ``__workspace_tablename__``, and ``table=True``. Module-specific
    residue (malware's ``parent_target_id`` / ``sha256``) is added by
    the subclass; the base only carries columns BOTH vr and malware
    share.
    """

    __workspace_tablename__: ClassVar[str]
    __table_args__ = (
        TabledFk("workspace_id", target_attr="__workspace_tablename__"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    workspace_id: str = Field(index=True)
    display_name: str = Field(max_length=255)
    kind: str = Field(max_length=64, index=True)
    descriptor_json: str = Field(default="{}", sa_column=Column(Text))
    primary_language: str | None = Field(default=None, max_length=32)
    secondary_languages_json: str = Field(default="[]", sa_column=Column(Text))
    status: str = Field(default="active", index=True, max_length=32)
    capability_profile_json: str = Field(default="{}", sa_column=Column(Text))
    tags_json: str = Field(default="[]", sa_column=Column(Text))
    analysis_state: str = Field(default="pending", index=True, max_length=24)
    analysis_state_message: str | None = Field(default=None, sa_column=Column(Text))
    analysis_started_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    analysis_completed_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    # Backend-only: audit_mcp index_id, ida binary_id, etc. Underscore
    # prefix marks 'internal -- never exposed in contracts or UI'.
    mcp_handles_json: str = Field(
        default="{}",
        sa_column=Column("_mcp_handles_json", Text, nullable=False, server_default="{}"),
    )
    # Per-stage analysis status (migration 060). Replaces the single
    # ``analysis_state`` enum (kept as a roll-up). One JSON object with
    # three keys (ingestion / capability_profile / function_ranking)
    # each carrying state + timestamps + attempts + error message.
    # Mutations go through the module's ``services.stage_tracker`` which
    # handles idempotency, RUNNING-timeout detection, and serialized
    # commits. See contracts/target_stages.py.
    analysis_stages_json: str = Field(
        default="{}",
        sa_column=Column("analysis_stages_json", Text, nullable=False, server_default="{}"),
    )
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class TargetTagIndexBase(TableDerivedConstraintsMixin, SQLModel):
    """Shared columns for every module's target-tag index table (D-52).

    Denormalized tag-to-target index for fast multi-tag filter queries
    from the workspace dashboard. The canonical tag list still lives on
    ``<module>_targets.tags_json``; this table is a read-side index
    maintained by the tag writer service.

    A concrete subclass MUST set ``__tablename__``,
    ``__target_tablename__``, ``__workspace_tablename__``, and
    ``table=True``. Neither vr nor malware scopes this table with
    ``TeamScopedMixin`` -- ``workspace_id`` carries the effective scope.
    """

    __target_tablename__: ClassVar[str]
    __workspace_tablename__: ClassVar[str]
    __table_args__ = (
        TabledUq("target_id", "tag", "tag_source", suffix="target_tag_source"),
        TabledFk("target_id", target_attr="__target_tablename__"),
        TabledFk("workspace_id", target_attr="__workspace_tablename__"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    target_id: str = Field(index=True)
    workspace_id: str = Field(index=True)
    tag: str = Field(index=True, max_length=128)
    tag_source: str = Field(max_length=32)
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class TargetTag(BaseModel):
    """One tag entry -- string label + provenance (D-52)."""

    model_config = ConfigDict(extra="forbid")

    tag: str = PField(min_length=1, max_length=128)
    source: TargetTagSource = TargetTagSource.OPERATOR


class TargetSummaryBase(BaseModel):
    """Shared read-only target projection.

    Modules add their per-module ``kind`` enum (each module's
    ``TargetKind`` values differ) and any module-specific projections
    (e.g. malware's ``capability_profile``).
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    workspace_id: str
    workspace_name: str | None = None
    display_name: str
    descriptor: dict[str, Any] = PField(default_factory=dict)
    uploaded_filename: str | None = PField(
        default=None,
        description=(
            "When the operator uploaded a binary via POST "
            "/<module>/targets/{id}/upload, this is the original filename. "
            "None otherwise. Projected from the backend-internal "
            "mcp_handles_json -- never settable directly."
        ),
    )
    android_package_name: str | None = PField(
        default=None,
        description=(
            "For kind=android_apk only: the Android application package id "
            "(e.g. 'com.examplecorp.selfservis') discovered by android-mcp's "
            "androguard_summary during STATIC_SUMMARY. None until that stage "
            "completes. Projected from mcp_handles_json.android_mcp_package_name "
            "-- never settable directly. Frontend uses this as the row "
            "label once it is populated."
        ),
    )
    apk_overview: dict[str, Any] | None = PField(
        default=None,
        description=(
            "For kind=android_apk only. Projected from mcp_handles_json "
            "after the 5-stage pipeline completes (APK_DECODE -> JADX_DECOMPILE "
            "-> INDEX_DECOMPILED -> STATIC_SUMMARY -> MOBSF_SCAN). None when "
            "kind != android_apk OR the pipeline hasn't progressed far enough "
            "to write any handles."
        ),
    )
    primary_language: str | None = None
    secondary_languages: list[str] = PField(default_factory=list)
    status: TargetStatus
    analysis_state: AnalysisState
    analysis_state_message: str | None = None
    analysis_started_at: str | None = None
    analysis_completed_at: str | None = None
    analysis_stages: dict[str, Any] | None = PField(
        default=None,
        description=(
            "Per-stage analysis status -- ingestion / capability_profile / "
            "function_ranking. Each stage carries its own state (pending / "
            "running / done / failed), started_at, completed_at, attempts, "
            "and error message. UI uses this to show progress + offer "
            "stage-level resume. Migration 060 + StageTracker."
        ),
    )
    tags: list[TargetTag] = PField(default_factory=list)
    created_at: str | None = None
    updated_at: str | None = None


class TargetCreateBase(BaseModel):
    """Shared operator-supplied fields for a new target.

    Modules add their per-module ``kind`` enum. The descriptor carries
    ONLY operator-known fields; backend ingests via
    ``TargetAnalysisService`` asynchronously.
    """

    model_config = ConfigDict(extra="forbid")

    workspace_id: str = PField(min_length=1, max_length=64)
    display_name: str = PField(min_length=1, max_length=255)
    descriptor: dict[str, Any] = PField(
        default_factory=dict,
        description=(
            "Kind-specific operator-known fields. NEVER contains "
            "backend MCP ids -- those are populated automatically."
        ),
    )
    primary_language: str | None = PField(
        default=None,
        max_length=32,
        description="Optional -- backend auto-detects post-ingestion when omitted.",
    )
    secondary_languages: list[str] = PField(default_factory=list)
    tags: list[str] = PField(default_factory=list)


class TargetPatchBase(BaseModel):
    """Shared operator-mutable target fields.

    ``workspace_id``, ``kind``, and ``descriptor`` are immutable after
    creation -- recreate the target instead.
    """

    model_config = ConfigDict(extra="forbid")

    display_name: str | None = PField(default=None, min_length=1, max_length=255)
    primary_language: str | None = PField(default=None, max_length=32)
    secondary_languages: list[str] | None = None
    status: TargetStatus | None = None
    tags: list[str] | None = None
