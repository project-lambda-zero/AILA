"""Session, answer, activity, and system-association models for SbD NFR.

Covers: SbdNfrSessionRecord, SbdNfrAnswerRecord, SbdNfrActivityRecord,
SbdNfrSessionSystemRecord.

Design references: D-03, D-06, D-20, D-23a, D-23b, D-24, D-29, D-35a,
D-36, D-41, D-50, D-51, D-53, D-55, D-60, D-62, D-65.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now
from aila.storage.mixins import TeamScopedMixin


class SbdNfrSessionRecord(TeamScopedMixin, SQLModel, table=True):
    """An NFR assessment session owned by a requester (D-20, D-36, D-23a, D-51,
    D-55, D-60, D-24, D-62, D-53, D-35a).

    One session covers one project assessment lifecycle: from scope selection
    through requirement answering to architect review and resolution.

    ``status``: "draft" | "in_progress" | "completed" | "resolving" | "resolved" | "resolution_failed" | "expired" (D-20).
    ``share_token``: UUID used in public share links (unique, indexed).
    ``cloned_from``: session id of the template session if this was cloned (D-55).
    ``is_template``: marks sessions that can be cloned as templates (D-60).
    ``is_deleted``: soft-delete flag (D-35a).
    ``tags_json``: JSON-encoded list of string tags (D-55).
    ``expires_at``: optional expiry for temporary share links (D-60).

    Written by: POST /sbd_nfr/sessions (API).
    Consumed by: session listing, architect review dashboard.
    """

    __tablename__ = "sbd_nfr_session_record"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    schema_version_at_start: int
    owner_id: str = Field(index=True)
    assigned_architect_id: str | None = Field(default=None, sa_column=Column(Text, nullable=True, index=True))
    status: str = Field(default="draft", index=True)
    project_name: str
    description: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    business_unit: str | None = Field(default=None, sa_column=Column(Text, nullable=True, index=True))
    requestor_name: str
    requestor_email: str
    target_date: datetime | None = Field(default=None, nullable=True, sa_type=DateTime(timezone=True))
    share_token: str = Field(default_factory=lambda: str(uuid4()), unique=True, index=True)
    cloned_from: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    is_template: bool = Field(default=False)
    template_name: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    is_deleted: bool = Field(default=False, index=True)
    resolution_error: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    resolution_json: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    expires_at: datetime | None = Field(default=None, nullable=True, sa_type=DateTime(timezone=True))
    tags_json: str = Field(default="[]", sa_column=Column(Text))
    # Architect review fields (Phase 145: D-04, D-05)
    architect_notes: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    architect_override_json: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    # Report integrity hash (Phase 147: EXEC-04)
    # SHA-256 hex digest of the PDF bytes, computed and stored on first PDF generation.
    # Once set, this value is never overwritten — it certifies that specific artifact.
    report_hash_sha256: str | None = Field(
        default=None,
        sa_column=Column(Text, nullable=True),
    )
    report_hash_generated_at: datetime | None = Field(
        default=None,
        nullable=True,
        sa_type=DateTime(timezone=True),
    )
    # Scoring fields (Phase 154: SCORE-01, SCORE-02)
    # Set when session status transitions to "completed".
    # risk_tier: "LOW"|"MEDIUM"|"HIGH"|"CRITICAL" derived from scope answers.
    # posture_index: 0.0-3.0 aggregate maturity score across all NFR sections.
    # Run ALTER TABLE sbd_nfr_session_record ADD COLUMN risk_tier TEXT;
    #     ALTER TABLE sbd_nfr_session_record ADD COLUMN posture_index REAL;
    # when upgrading an existing DB instead of re-running create_all().
    risk_tier: str | None = Field(
        default=None,
        sa_column=Column(Text, nullable=True),
    )
    posture_index: float | None = Field(
        default=None,
        nullable=True,
    )
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class SbdNfrAnswerRecord(TeamScopedMixin, SQLModel, table=True):
    """One captured answer for a question within a session (D-06, D-23b, D-29, D-41).

    The unique constraint on (session_id, question_id) enforces one answer
    per question per session.  Updating an answer uses an upsert; the
    previous answer is overwritten, not archived.

    ``answer_value``: the selected option value (e.g. "Yes", "New service…").
    ``note_text``: optional free-text commentary attached to the answer.
    ``answered_by_*``: identity of the person who submitted this answer.
    ``schema_version``: snapshot of the questionnaire schema version at answer time.

    Written by: PUT /sbd_nfr/sessions/{id}/answers (API).
    Consumed by: session detail, workbook generation, completion tracking.
    """

    __tablename__ = "sbd_nfr_answer_record"
    __table_args__ = (
        UniqueConstraint("session_id", "question_id", name="uq_session_question"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    session_id: str = Field(index=True)
    question_id: str = Field(index=True)
    answer_value: str
    note_text: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    answered_by_name: str
    answered_by_email: str
    schema_version: int
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class SbdNfrActivityRecord(TeamScopedMixin, SQLModel, table=True):
    """Immutable activity log for a session (D-65).

    Records every user-initiated event: creation, answer submission, status
    transitions, architect assignment, share link creation, etc.  Records are
    append-only; no UPDATE or DELETE is permitted on this table.

    ``event_type``: short slug describing the event (e.g. "session_created",
    "answer_submitted", "status_changed").
    ``detail_json``: JSON-encoded dict with event-specific fields.

    Written by: any API operation that mutates session state.
    Consumed by: activity timeline on the session detail page.
    """

    __tablename__ = "sbd_nfr_activity_record"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    session_id: str = Field(index=True)
    event_type: str = Field(index=True)
    actor_name: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    actor_email: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    detail_json: str = Field(default="{}", sa_column=Column(Text))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class SbdNfrSessionSystemRecord(TeamScopedMixin, SQLModel, table=True):
    """Associates a session with a registered platform system (D-50).

    Allows an NFR assessment session to be linked to one or more systems
    already registered in the AILA platform (ManagedSystemRecord.id).  The
    unique constraint prevents duplicate associations.

    Written by: PUT /sbd_nfr/sessions/{id}/systems (API).
    Consumed by: GET /systems/{id} system summary, session detail.

    pre_triage_context_json: JSON-encoded TriageContext dict (Phase 154: TRIAGE-01, TRIAGE-02).
        Written when the linked session completes (complete_session call).
        Null until the session completes.  Stores data_sensitivity, internet_exposure,
        business_impact_tier, risk_tier, and severity_multiplier derived from scope answers.

    updated_at: Last-write timestamp.  Set to utc_now() when pre_triage_context_json
        is written.  Enables ordering by recency in the triage-context endpoint.

    DB migration note (if upgrading an existing schema without re-running create_all):
        ALTER TABLE sbd_nfr_session_system_record ADD COLUMN pre_triage_context_json TEXT;
        ALTER TABLE sbd_nfr_session_system_record ADD COLUMN updated_at TIMESTAMPTZ DEFAULT now();
    """

    __tablename__ = "sbd_nfr_session_system_record"
    __table_args__ = (
        UniqueConstraint("session_id", "system_id", name="uq_session_system"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    session_id: str = Field(index=True)
    system_id: int = Field(index=True)
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    # Pre-triage risk context (Phase 154: TRIAGE-01, TRIAGE-02)
    # JSON-encoded TriageContext dict, written when the linked session is completed.
    # Null until the session completes.
    pre_triage_context_json: str | None = Field(
        default=None,
        sa_column=Column(Text, nullable=True),
    )
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


__all__ = [
    "SbdNfrSessionRecord",
    "SbdNfrAnswerRecord",
    "SbdNfrActivityRecord",
    "SbdNfrSessionSystemRecord",
]
