"""Investigation table definition (M3.R-1).

Per D-50: one primary target per investigation + N secondary target
references (stored as JSON list).

Per D-43 GA-24: cost tracking has three streams (LLM tokens + MCP calls
+ fuzz infra). Each stream is summed into ``cost_actual_usd``.

Linked artifacts (campaign_ids, finding_ids) are stored as JSON lists
rather than denormalized through join tables — querying 'all findings
from this investigation' is a low-volume operator action that doesn't
need indexed access.
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, ForeignKey, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now
from aila.storage.mixins import TeamScopedMixin

__all__ = ["VRInvestigationRecord"]


class VRInvestigationRecord(TeamScopedMixin, SQLModel, table=True):
    """One operator-initiated reasoning session (D-43, D-50)."""

    __tablename__ = "vr_investigations"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    project_id: str | None = Field(default=None, max_length=64, index=True)
    parent_investigation_id: str | None = Field(
        default=None,
        sa_column=Column(
            "parent_investigation_id",
            ForeignKey("vr_investigations.id"),
            nullable=True,
            index=True,
        ),
    )
    target_id: str = Field(
        sa_column=Column(
            "target_id",
            ForeignKey("vr_targets.id"),
            nullable=False,
            index=True,
        ),
    )
    secondary_target_refs_json: str = Field(default="[]", sa_column=Column(Text))

    kind: str = Field(default="discovery", index=True, max_length=32)
    title: str = Field(max_length=255)
    initial_question: str = Field(default="", sa_column=Column(Text))
    status: str = Field(default="created", index=True, max_length=32)
    pause_reason: str | None = Field(default=None, max_length=32)
    auto_pilot: bool = Field(default=True)
    is_favorite: bool = Field(default=False, index=True)

    strategy_family: str = Field(
        default="vulnerability_research.discovery_research", max_length=64,
    )
    persona_dispatch_json: str = Field(default="{}", sa_column=Column(Text))

    cost_budget_usd: float = Field(default=50.0)
    cost_actual_usd: float = Field(default=0.0)
    llm_tokens_cost_usd: float = Field(default=0.0)
    mcp_calls_cost_usd: float = Field(default=0.0)
    fuzz_infra_cost_usd: float = Field(default=0.0)

    primary_outcome_id: str | None = Field(default=None, max_length=64)
    linked_campaign_ids_json: str = Field(default="[]", sa_column=Column(Text))
    linked_finding_ids_json: str = Field(default="[]", sa_column=Column(Text))

    started_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    stopped_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
