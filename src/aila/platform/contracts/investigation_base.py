"""Investigation record + contract bases shared by the investigation engine (RFC-01).

A concrete module investigation collapses to::

    class VRInvestigationRecord(InvestigationRecordBase, table=True):
        __tablename__ = "vr_investigations"
        __target_tablename__ = "vr_targets"

The parent_investigation_id FK is self-referential (targets the subclass's own
``__tablename__``); target_id resolves to the module's target table via the
``__target_tablename__`` class variable.

Module-specific residue held by the concrete subclass:

* ``analysis_depth`` (malware only, locked decision #8)
* ``inherit_observations`` (malware only, locked decision #11)

Module-specific INDEX shape held by the concrete subclass:

* vr builds a partial index on ``is_favorite`` (WHERE is_favorite = true)
* malware indexes ``is_favorite`` as a full-column index

Neither is expressible in a single shared base column definition, so
``is_favorite`` is declared here without ``index=True`` and each subclass adds
its own ``__table_args__`` entry.

Field defaults where vr and malware disagree (``kind`` default,
``strategy_family`` default) mirror the vr source verbatim per the RFC-01
authoring rule; the malware subclass overrides the field to inject its own
default. See ``platform/contracts/workspace_base.py`` for the equivalent
override pattern applied to ``WorkspaceRecordBase.theme``.
"""
from __future__ import annotations

from datetime import datetime
from typing import ClassVar
from uuid import uuid4

from pydantic import BaseModel, ConfigDict
from pydantic import Field as PField
from sqlalchemy import DateTime, Text
from sqlmodel import Field, SQLModel

from aila.storage.mixins import TeamScopedMixin

from ._common import utc_now
from ._naming import TableDerivedConstraintsMixin, TabledFk
from .enums import InvestigationPauseReason, InvestigationStatus

__all__ = [
    "InvestigationRecordBase",
    "InvestigationSummaryBase",
]


class InvestigationRecordBase(TableDerivedConstraintsMixin, TeamScopedMixin, SQLModel):
    """Shared columns for every module's investigation table (D-43, D-50).

    A concrete subclass MUST set ``__tablename__``, ``__target_tablename__``,
    and ``table=True``. The parent-investigation FK is derived as
    self-referential against the subclass's own ``__tablename__``; target_id
    resolves via ``__target_tablename__``.
    """

    __target_tablename__: ClassVar[str]
    __table_args__ = (
        TabledFk("parent_investigation_id"),
        TabledFk("target_id", target_attr="__target_tablename__"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str | None = Field(default=None, max_length=64, index=True)
    parent_investigation_id: str | None = Field(default=None, index=True)
    target_id: str = Field(index=True)
    secondary_target_refs_json: str = Field(default="[]", sa_type=Text, sa_column_kwargs={"nullable": True})

    kind: str = Field(default="discovery", index=True, max_length=32)
    title: str = Field(max_length=255)
    initial_question: str = Field(default="", sa_type=Text, sa_column_kwargs={"nullable": True})
    status: str = Field(default="created", index=True, max_length=32)
    pause_reason: str | None = Field(default=None, max_length=32)
    auto_pilot: bool = Field(default=True)
    # Index shape differs per module (vr = partial index, malware = full
    # column). The subclass carries the module-specific Index in its own
    # __table_args__; the base column stays plain.
    is_favorite: bool = Field(default=False)

    strategy_family: str = Field(
        default="vulnerability_research.discovery_research", max_length=64,
    )
    persona_dispatch_json: str = Field(default="{}", sa_type=Text, sa_column_kwargs={"nullable": True})

    cost_budget_usd: float = Field(default=50.0)
    cost_actual_usd: float = Field(default=0.0)
    llm_tokens_cost_usd: float = Field(default=0.0)
    mcp_calls_cost_usd: float = Field(default=0.0)
    fuzz_infra_cost_usd: float = Field(default=0.0)

    primary_outcome_id: str | None = Field(default=None, max_length=64)
    linked_campaign_ids_json: str = Field(default="[]", sa_type=Text, sa_column_kwargs={"nullable": True})
    linked_finding_ids_json: str = Field(default="[]", sa_type=Text, sa_column_kwargs={"nullable": True})

    # RFC-09 criterion 4: pin-per-investigation. First resolve of a prompt
    # key on this row records the current production-alias version here;
    # subsequent resolves for the SAME investigation return the pinned
    # version so a live production-alias flip never rewrites a running
    # investigation. JSON object mapping prompt-key -> resolved version
    # string. Empty object = nothing pinned yet.
    prompt_pins_json: str = Field(
        default="{}", sa_type=Text, sa_column_kwargs={"nullable": True},
    )

    started_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    stopped_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class InvestigationSummaryBase(BaseModel):
    """Shared read-only projection of an investigation.

    Modules add their module-specific ``kind: <ModuleInvestigationKind>``
    field. ``InvestigationKind`` deliberately stays module-owned: vr uses
    DISCOVERY/VARIANT_HUNT/TRIAGE/N_DAY/AUDIT/MASVS_AUDIT while malware uses
    FULL_ANALYSIS/TRIAGE/UNPACK_ONLY/CONFIG_EXTRACT/YARA_GENERATE/
    FAMILY_ATTRIBUTE. Both status + pause_reason vocabularies match, so those
    resolve to the hoisted platform enums.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    target_id: str
    workspace_id: str | None = None
    parent_investigation_id: str | None = None
    status: InvestigationStatus
    pause_reason: InvestigationPauseReason | None = None
    auto_pilot: bool
    is_favorite: bool = False
    strategy_family: str
    cost_budget_usd: float
    cost_actual_usd: float = 0.0
    llm_tokens_cost_usd: float = 0.0
    mcp_calls_cost_usd: float = 0.0
    fuzz_infra_cost_usd: float = 0.0
    branch_count: int = 0
    message_count: int = 0
    outcome_count: int = 0
    primary_outcome_id: str | None = None
    primary_outcome_kind: str | None = None
    primary_outcome_confidence: str | None = None
    primary_outcome_verdict_head: str | None = None
    verifier_verdict: str | None = None
    verifier_confidence: float | None = None
    linked_campaign_ids: list[str] = PField(default_factory=list)
    linked_finding_ids: list[str] = PField(default_factory=list)
    started_at: datetime | None = None
    stopped_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
