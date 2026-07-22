"""Outcome record + contract bases shared by the investigation engine (RFC-01).

Zero-domain table: the vr and malware investigation-outcome tables carry the
same 13 columns (D-43). A concrete module outcome collapses to::

    class VRInvestigationOutcomeRecord(OutcomeRecordBase, table=True):
        __tablename__ = "vr_investigation_outcomes"
        __investigation_tablename__ = "vr_investigations"
        __branch_tablename__ = "vr_investigation_branches"

The FK columns are plain fields on the base; ``TableDerivedConstraintsMixin``
derives the ForeignKeyConstraints (investigation_id -> the module's
investigation table, branch_id -> the module's investigation-branch table)
from the subclass tablename class vars.

``outcome_kind`` is intentionally stored as a plain string on the base: vr
has 11 kinds and malware has 9 different kinds, so each module subclasses the
Pydantic contract bases and re-declares ``outcome_kind`` with its own StrEnum.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, ClassVar
from uuid import uuid4

from pydantic import BaseModel, ConfigDict
from pydantic import Field as PField
from sqlalchemy import Column, DateTime, Text
from sqlmodel import Field, SQLModel

from ._common import utc_now
from ._naming import TableDerivedConstraintsMixin, TabledFk
from .enums import OutcomeConfidence, OutcomeDispatchStatus

__all__ = [
    "OutcomeCreateBase",
    "OutcomeRecordBase",
    "OutcomeSummaryBase",
]


class OutcomeRecordBase(TableDerivedConstraintsMixin, SQLModel):
    """Shared columns for every module's investigation-outcome table (D-43).

    A concrete subclass MUST set ``__tablename__``, ``__investigation_tablename__``,
    ``__branch_tablename__``, and ``table=True``.
    """

    __investigation_tablename__: ClassVar[str]
    __branch_tablename__: ClassVar[str]
    __table_args__ = (
        TabledFk("investigation_id", target_attr="__investigation_tablename__"),
        TabledFk("branch_id", target_attr="__branch_tablename__"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    investigation_id: str = Field(index=True)
    branch_id: str = Field(index=True)

    outcome_kind: str = Field(max_length=32, index=True)
    payload_json: str = Field(default="{}", sa_column=Column(Text))
    confidence: str = Field(max_length=16)
    evidence_refs_json: str = Field(default="[]", sa_column=Column(Text))

    accepted_by_operator: bool = Field(default=False)
    accepted_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))

    # Draft-outcome lifecycle (migration 062). 'draft' = pending sibling
    # review; 'approved' = quorum reached, dispatch may proceed; 'rejected'
    # = at least one sibling refused; 'dispatched' = terminal, dispatch
    # actually shipped to its downstream (findings row, child investigation,
    # knowledge memo, etc.). The OutcomeDispatcher refuses any outcome
    # whose state is not 'approved'.
    state: str = Field(default="draft", index=True, max_length=16)

    dispatch_status: str = Field(default="pending", index=True, max_length=16)
    dispatch_target: str | None = Field(default=None, max_length=128)

    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class OutcomeSummaryBase(BaseModel):
    """Shared read-only outcome projection. Modules add their ``outcome_kind`` enum."""

    model_config = ConfigDict(extra="forbid")

    id: str
    investigation_id: str
    branch_id: str
    payload: dict[str, Any] = PField(default_factory=dict)
    confidence: OutcomeConfidence
    evidence_refs: list[str] = PField(default_factory=list)
    accepted_by_operator: bool = False
    accepted_at: datetime | None = None
    dispatch_status: OutcomeDispatchStatus = OutcomeDispatchStatus.PENDING
    dispatch_target: str | None = PField(
        default=None,
        description=(
            "Downstream artifact id -- campaign_id / finding_id / spawned "
            "investigation_id / audit_memo_id."
        ),
    )
    created_at: datetime | None = None
    state: str = PField(
        default="dispatched",
        description=(
            "Draft outcome lifecycle: 'draft' (pending sibling review), "
            "'approved' (quorum reached, dispatch may fire), 'rejected' "
            "(vetoed by sibling), 'dispatched' (shipped to downstream)."
        ),
    )
    approve_count: int = PField(default=0, ge=0)
    reject_count: int = PField(default=0, ge=0)
    request_edit_count: int = PField(default=0, ge=0)
    abstain_count: int = PField(default=0, ge=0)
    quorum_k: int = PField(default=0, ge=0)


class OutcomeCreateBase(BaseModel):
    """Shared outcome create payload. Modules add their ``outcome_kind`` enum.

    Engine emits via internal API (not exposed externally as POST). This
    shape exists for typed validation inside the reasoning loop and for
    the outcome-acceptance API (operator confirms).
    """

    model_config = ConfigDict(extra="forbid")

    branch_id: str = PField(min_length=1, max_length=64)
    payload: dict[str, Any] = PField(default_factory=dict)
    confidence: OutcomeConfidence
    evidence_refs: list[str] = PField(default_factory=list)
