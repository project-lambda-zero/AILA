"""Schema versioning and questionnaire structure models for SbD NFR.

Covers: SbdNfrSchemaVersionRecord, SbdNfrSectionRecord, SbdNfrSubgroupRecord,
SbdNfrQuestionRecord, SbdNfrQuestionOptionRecord, SbdNfrSubtaskComponentRecord,
SbdNfrQuestionSubtaskMapRecord.

Design references: D-01, D-09, D-13, D-14, D-16, D-19, D-37, D-40, D-63, D-64.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now


class SbdNfrSchemaVersionRecord(SQLModel, table=True):
    """Tracks questionnaire schema versions (D-37).

    A new row is inserted every time seed_data() runs a structural change.
    The version field is monotonically increasing and unique; seed logic
    writes to it via ``INSERT`` only, never ``UPDATE``.

    Written by: seed_data() in module.py.
    Consumed by: section/subgroup/question rows (schema_version FK-by-value).
    """

    __tablename__ = "sbd_nfr_schema_version_record"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    version: int = Field(index=True, unique=True)
    change_summary: str
    changed_by: str
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class SbdNfrSectionRecord(SQLModel, table=True):
    """One assessment section (scope + 9 NFR sections) (D-16, D-07).

    Each section owns a set of subgroups which in turn own questions.
    ``depends_on_question_id`` + ``expected_when`` implement skip logic so
    optional sections are hidden until the triggering scope answer is given.

    Written by: seed_data() (upsert by section_key + schema_version).
    Consumed by: questionnaire rendering, skip-logic evaluation.
    """

    __tablename__ = "sbd_nfr_section_record"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    schema_version: int = Field(index=True)
    section_key: str = Field(index=True)
    label: str
    description: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    icon_hint: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    display_order: int = Field(default=0)
    is_active: bool = Field(default=True, index=True)
    depends_on_question_id: str | None = Field(default=None, sa_column=Column(Text, nullable=True, index=True))
    expected_when: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    # JSON-encoded multi-condition expression for AND/OR gating. When set, takes
    # precedence over single depends_on_question_id + expected_when. Format:
    # {"op": "and"|"or", "conditions": [{"question_id": str, "expected": str}, ...]}
    condition_expr_json: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class SbdNfrSubgroupRecord(SQLModel, table=True):
    """A logical grouping within a section (D-16).

    Subgroups are the display-level container between section and individual
    questions.  They carry no skip logic of their own; that lives at the
    section level.

    Written by: seed_data() (upsert by subgroup_key + schema_version).
    Consumed by: questionnaire rendering.
    """

    __tablename__ = "sbd_nfr_subgroup_record"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    schema_version: int = Field(index=True)
    section_id: str = Field(index=True)
    subgroup_key: str = Field(index=True)
    label: str
    description: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    display_order: int = Field(default=0)
    is_active: bool = Field(default=True, index=True)
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class SbdNfrQuestionRecord(SQLModel, table=True):
    """One assessment question (D-14, D-19, D-40, D-07, D-64).

    Primary key is the semantic ID (e.g. ``SCOPE-01``, ``HYGN-03``) — NOT an
    auto-generated UUID — so foreign references in other tables are human-
    readable without a join.

    ``question_type``: "scope" for the 13 scope questions, "requirement" for
    the 200 NFR requirement questions.

    ``depth_level``: "scope" | "standard" | "specialist".  Specialist questions
    are documentation-only (no compliance answer required).

    ``answer_type``: "single_choice" (scope), "compliance" (NFR requirement),
    "free_text", or "none" (group headers, documentation rows).

    Skip logic (D-07, D-08): ``depends_on_question_id`` + ``expected_when``
    mirror the same pattern used at the section level.

    Written by: seed_data() (upsert by id).
    Consumed by: questionnaire rendering, answer validation, skip-logic.
    """

    __tablename__ = "sbd_nfr_question_record"

    id: str = Field(primary_key=True)  # semantic ID — not auto-generated
    schema_version: int = Field(index=True)
    subgroup_id: str = Field(index=True)
    question_type: str  # "scope" | "requirement"
    depth_level: str  # "scope" | "standard" | "specialist"
    answer_type: str  # "single_choice" | "compliance" | "free_text" | "none"
    label: str = Field(sa_column=Column(Text))
    instruction: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    guideline: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    help_text: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    is_required: bool = Field(default=True)
    is_active: bool = Field(default=True, index=True)
    depends_on_question_id: str | None = Field(default=None, sa_column=Column(Text, nullable=True, index=True))
    expected_when: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    # JSON-encoded multi-condition expression for AND/OR gating. When set, takes
    # precedence over single depends_on_question_id + expected_when. Format:
    # {"op": "and"|"or", "conditions": [{"question_id": str, "expected": str}, ...]}
    condition_expr_json: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    display_order: int = Field(default=0)
    max_length: int | None = Field(default=None, nullable=True)
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class SbdNfrQuestionOptionRecord(SQLModel, table=True):
    """Available answer options for a single question (D-63).

    Scope questions have 2–4 options loaded from seed_options.json.  Compliance
    questions share the same 4 options (Yes/Partial/No/Not applicable) loaded
    via the ``__COMPLIANCE__`` template expansion in seed_data().

    Written by: seed_data() (delete-and-reinsert by question_id on each seed run).
    Consumed by: frontend option rendering, answer validation.
    """

    __tablename__ = "sbd_nfr_question_option_record"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    question_id: str = Field(index=True)
    value: str
    label: str
    description: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    display_order: int = Field(default=0)
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class SbdNfrSubtaskComponentRecord(SQLModel, table=True):
    """One SbD sub-task component (D-13).

    Maps directly to the 25 entries in ``_RECOMMENDATION_CATALOG`` from the
    AILA NFR Assessment.  The primary key is the semantic ``key`` string (e.g.
    ``"network_security"``) used throughout the mapping table.

    Written by: seed_data() (upsert by key — never deletes existing rows,
    Pitfall 4).
    Consumed by: Jira draft generation, next-steps recommendations.
    """

    __tablename__ = "sbd_nfr_subtask_component_record"

    key: str = Field(primary_key=True)  # semantic key — not auto-generated
    label: str
    category: str
    description: str = Field(sa_column=Column(Text))
    icon_hint: str = Field(default="")
    display_order: int = Field(default=0)
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    updated_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


class SbdNfrQuestionSubtaskMapRecord(SQLModel, table=True):
    """Many-to-many mapping between questions and sub-task components (D-09).

    Each row declares that a question contributes evidence toward a SbD
    sub-task component.  The unique constraint prevents duplicate mappings.

    Written by: seed_data() (delete-and-reinsert by schema_version on each seed run).
    Consumed by: Jira draft generation (sub-task coverage scoring).
    """

    __tablename__ = "sbd_nfr_question_subtask_map"
    __table_args__ = (
        UniqueConstraint("question_id", "subtask_key", name="uq_question_subtask"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    question_id: str = Field(index=True)
    subtask_key: str = Field(index=True)
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))


__all__ = [
    "SbdNfrSchemaVersionRecord",
    "SbdNfrSectionRecord",
    "SbdNfrSubgroupRecord",
    "SbdNfrQuestionRecord",
    "SbdNfrQuestionOptionRecord",
    "SbdNfrSubtaskComponentRecord",
    "SbdNfrQuestionSubtaskMapRecord",
]
