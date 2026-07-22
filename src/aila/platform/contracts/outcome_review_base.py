"""Outcome-review record + contract bases shared by the investigation engine (RFC-01).

Zero-domain table: the vr and malware outcome-review tables (migration 062)
carry the same 8 columns and the same ``UNIQUE(outcome_id, reviewer_branch_id)``
guard that keeps a single reviewing branch to one vote per outcome. A
concrete module review collapses to::

    class VRInvestigationOutcomeReviewRecord(OutcomeReviewRecordBase, table=True):
        __tablename__ = "vr_outcome_reviews"
        __outcome_tablename__ = "vr_investigation_outcomes"
        __branch_tablename__ = "vr_investigation_branches"

The FK columns are plain fields on the base; ``TableDerivedConstraintsMixin``
derives the ForeignKeyConstraints from the subclass tablename class vars.

The concrete tables also declare ``ON DELETE CASCADE`` on both FKs (migration
062 emits the constraint that way), so both ``TabledFk`` markers pass
``ondelete="CASCADE"`` and the derived ``ForeignKeyConstraint`` carries it into
the ORM metadata, matching the physical schema.
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
from ._naming import TableDerivedConstraintsMixin, TabledFk, TabledUq

__all__ = [
    "OutcomeReviewCreateBase",
    "OutcomeReviewRecordBase",
    "OutcomeReviewSummaryBase",
]


class OutcomeReviewRecordBase(TableDerivedConstraintsMixin, SQLModel):
    """Shared columns for every module's outcome-review table (migration 062).

    A concrete subclass MUST set ``__tablename__``, ``__outcome_tablename__``,
    ``__branch_tablename__``, and ``table=True``.
    """

    __outcome_tablename__: ClassVar[str]
    __branch_tablename__: ClassVar[str]
    __table_args__ = (
        TabledUq("outcome_id", "reviewer_branch_id", suffix="outcome_reviewer"),
        TabledFk("outcome_id", target_attr="__outcome_tablename__", ondelete="CASCADE"),
        TabledFk("reviewer_branch_id", target_attr="__branch_tablename__", ondelete="CASCADE"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)

    outcome_id: str = Field(index=True)
    reviewer_branch_id: str = Field()

    # Copied from the reviewing branch's persona_voice for fast joinless
    # display ("Halvar voted reject"). Always derived from the branch row
    # at insert time; never updated.
    reviewer_persona: str = Field(max_length=64)

    # 'approve' | 'reject' | 'request_edit' | 'abstain'
    vote: str = Field(max_length=16, index=True)
    comment: str = Field(default="", sa_column=Column(Text))
    suggested_edits_json: str = Field(default="{}", sa_column=Column(Text))

    created_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True),
    )


class OutcomeReviewSummaryBase(BaseModel):
    """Shared read-only projection of one outcome review."""

    model_config = ConfigDict(extra="forbid")

    id: str
    outcome_id: str
    reviewer_branch_id: str
    reviewer_persona: str
    vote: str
    comment: str = ""
    suggested_edits: dict[str, Any] = PField(default_factory=dict)
    created_at: datetime | None = None


class OutcomeReviewCreateBase(BaseModel):
    """Shared operator-facing payload for submitting a sibling review.

    Reviewer branch id is the source-of-truth identity; operator review posts
    (where there's no agent branch) MAY pass any sibling branch id from the
    same investigation to register a vote on behalf of that reviewer (treated
    as a manual override of the agent's judgment).
    """

    model_config = ConfigDict(extra="forbid")

    reviewer_branch_id: str = PField(min_length=1, max_length=64)
    vote: str = PField(
        pattern=r"^(approve|reject|request_edit|abstain)$",
        description="approve | reject | request_edit | abstain",
    )
    comment: str = PField(default="", max_length=4096)
    suggested_edits: dict[str, Any] = PField(default_factory=dict)
