"""Resolution result model for SbD NFR.

Covers: SbdNfrResolutionResultRecord.

Design references: D-10, D-12.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now
from aila.storage.mixins import TeamScopedMixin


class SbdNfrResolutionResultRecord(TeamScopedMixin, SQLModel, table=True):
    """One classified SbD sub-task component for a resolved session (D-10, D-12).

    Stores the LLM's classification output for a single sub-task component.
    A fully resolved session has exactly 25 rows in this table (one per
    SbdNfrSubtaskComponentRecord).

    The unique constraint on (session_id, subtask_key) enforces one result per
    component per session.  Re-resolution (D-12) deletes all existing rows for
    the session and inserts 25 new rows in a single transaction.

    cited_question_ids_json: JSON-encoded list[str] of question IDs cited by
    the LLM as evidence for this classification.

    resolved_at: UTC timestamp of when this classification was written.

    Written by: resolution_service._run_resolution_async() on completion.
    Consumed by: GET /sessions/{id}/resolution (Plan 135-02).
    """

    __tablename__ = "sbd_nfr_resolution_result_record"
    __table_args__ = (
        UniqueConstraint("session_id", "subtask_key", name="uq_resolution_result"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    session_id: str = Field(index=True)
    subtask_key: str = Field(index=True)
    classification: str  # "triggered" | "not_triggered" | "uncertain"
    confidence: float
    reasoning: str = Field(sa_column=Column(Text))
    cited_question_ids_json: str = Field(default="[]", sa_column=Column(Text))
    resolved_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


__all__ = ["SbdNfrResolutionResultRecord"]
