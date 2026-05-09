"""Pydantic response and request models for the SbD NFR schema tree API.

Design references: D-02, D-11, D-63, D-64.

These models define the API surface for schema-tree reads and admin CRUD
mutations.  They are pure Pydantic models — no SQLModel, no DB access.
"""

from __future__ import annotations

from pydantic import ConfigDict, Field

from aila.api.schemas.common import APIModel

__all__ = [
    "QuestionOptionResponse",
    "SubtaskMappingResponse",
    "QuestionResponse",
    "SubgroupResponse",
    "SectionResponse",
    "SubtaskComponentResponse",
    "SchemaTreeResponse",
    # Admin CRUD request models
    "SectionCreateRequest",
    "SectionUpdateRequest",
    "QuestionCreateRequest",
    "QuestionUpdateRequest",
    # Subgroup CRUD (Phase 155)
    "SubgroupCreateRequest",
    "SubgroupUpdateRequest",
    "SubgroupListResponse",
    # Option CRUD (Phase 155)
    "OptionCreateRequest",
    "OptionUpdateRequest",
    "OptionResponse",
    # Subtask mapping CRUD (Phase 155)
    "MappingCreateRequest",
    "MappingResponse",
    # Version publish (Phase 155)
    "SchemaVersionResponse",
    # Flat list responses for sections and questions (Phase 155)
    "SectionListResponse",
    "QuestionListResponse",
]


# ---------------------------------------------------------------------------
# Read (response) models
# ---------------------------------------------------------------------------


class QuestionOptionResponse(APIModel):
    """One selectable answer option for a question."""

    model_config = ConfigDict(extra="forbid")

    value: str
    label: str
    description: str | None = None
    display_order: int


class SubtaskMappingResponse(APIModel):
    """Maps a question to a SbD sub-task component key."""

    subtask_key: str


class QuestionResponse(APIModel):
    """Full representation of a single assessment question.

    Includes answer options and sub-task mappings so the frontend has
    everything it needs without additional requests.
    """

    id: str
    question_type: str
    depth_level: str
    answer_type: str
    label: str
    instruction: str | None = None
    guideline: str | None = None
    help_text: str | None = None
    is_required: bool
    depends_on_question_id: str | None = None
    expected_when: str | None = None
    condition_expr_json: str | None = None
    display_order: int
    max_length: int | None = None
    options: list[QuestionOptionResponse] = Field(default_factory=list)
    subtask_mappings: list[SubtaskMappingResponse] = Field(default_factory=list)


class SubgroupResponse(APIModel):
    """A logical grouping within a section, containing ordered questions."""

    id: str
    subgroup_key: str
    label: str
    description: str | None = None
    display_order: int
    questions: list[QuestionResponse] = Field(default_factory=list)


class SectionResponse(APIModel):
    """One top-level assessment section with its subgroups.

    Skip logic fields (depends_on_question_id / expected_when) are included
    so the frontend can evaluate section visibility client-side.
    """

    id: str
    section_key: str
    label: str
    description: str | None = None
    icon_hint: str | None = None
    display_order: int
    depends_on_question_id: str | None = None
    expected_when: str | None = None
    condition_expr_json: str | None = None
    subgroups: list[SubgroupResponse] = Field(default_factory=list)


class SubtaskComponentResponse(APIModel):
    """One SbD sub-task component from the recommendation catalog."""

    key: str
    label: str
    category: str
    description: str
    icon_hint: str
    display_order: int
    is_active: bool


class SchemaTreeResponse(APIModel):
    """Full schema tree: sections + sub-task component catalog.

    Returned by GET /sbd_nfr/schema.  Contains the complete nested
    section → subgroup → question tree plus the sub-task catalog.
    """

    schema_version: int
    sections: list[SectionResponse]
    subtask_components: list[SubtaskComponentResponse] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Admin CRUD request models (D-02)
# ---------------------------------------------------------------------------


class SectionCreateRequest(APIModel):
    """Request body for creating a new questionnaire section."""

    section_key: str = Field(min_length=1, max_length=100)
    label: str = Field(min_length=1, max_length=200)
    description: str | None = None
    icon_hint: str | None = None
    display_order: int = Field(ge=0)
    depends_on_question_id: str | None = None
    expected_when: str | None = None


class SectionUpdateRequest(APIModel):
    """Request body for updating an existing questionnaire section.

    All fields are optional so callers can issue partial updates.
    """

    label: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None
    icon_hint: str | None = None
    display_order: int | None = Field(default=None, ge=0)
    depends_on_question_id: str | None = None
    expected_when: str | None = None
    is_active: bool | None = None


class QuestionCreateRequest(APIModel):
    """Request body for creating a new question within a subgroup."""

    subgroup_id: str = Field(min_length=1)
    question_id: str | None = Field(default=None, min_length=1, max_length=50)
    question_type: str = Field(min_length=1)
    depth_level: str = Field(min_length=1)
    answer_type: str = Field(min_length=1)
    label: str = Field(min_length=1)
    instruction: str | None = None
    guideline: str | None = None
    help_text: str | None = None
    is_required: bool = True
    depends_on_question_id: str | None = None
    expected_when: str | None = None
    condition_expr_json: str | None = None
    display_order: int = Field(ge=0, default=0)
    max_length: int | None = Field(default=None, ge=1)


class QuestionUpdateRequest(APIModel):
    """Request body for updating an existing question.

    All fields are optional so callers can issue partial updates.
    """

    label: str | None = Field(default=None, min_length=1)
    question_type: str | None = Field(default=None, min_length=1)
    depth_level: str | None = Field(default=None, min_length=1)
    answer_type: str | None = Field(default=None, min_length=1)
    instruction: str | None = None
    guideline: str | None = None
    help_text: str | None = None
    is_required: bool | None = None
    depends_on_question_id: str | None = None
    expected_when: str | None = None
    condition_expr_json: str | None = None
    display_order: int | None = Field(default=None, ge=0)
    max_length: int | None = Field(default=None, ge=1)
    is_active: bool | None = None


# ---------------------------------------------------------------------------
# Subgroup CRUD request/response models (Phase 155 — EDIT-07)
# ---------------------------------------------------------------------------


class SubgroupCreateRequest(APIModel):
    """Request body for creating a new subgroup within a section."""

    model_config = ConfigDict(extra="forbid")

    section_id: str = Field(min_length=1)
    subgroup_key: str = Field(min_length=1, max_length=100)
    label: str = Field(min_length=1, max_length=200)
    description: str | None = None
    display_order: int = Field(ge=0)


class SubgroupUpdateRequest(APIModel):
    """Request body for partially updating an existing subgroup.

    All fields are optional so callers can issue partial updates.
    """

    model_config = ConfigDict(extra="forbid")

    label: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None
    display_order: int | None = Field(default=None, ge=0)
    is_active: bool | None = None


class SubgroupListResponse(APIModel):
    """Flat subgroup representation for list endpoints.

    Distinct from SubgroupResponse (which nests questions).  This model
    is used by list_sections / create_subgroup / update_subgroup responses
    where the nested question tree is not required.
    """

    id: str
    subgroup_key: str
    label: str
    description: str | None = None
    display_order: int
    section_id: str
    is_active: bool


# ---------------------------------------------------------------------------
# Option CRUD request/response models (Phase 155 — EDIT-07)
# ---------------------------------------------------------------------------


class OptionCreateRequest(APIModel):
    """Request body for creating a new answer option for a question."""

    model_config = ConfigDict(extra="forbid")

    question_id: str = Field(min_length=1)
    value: str = Field(min_length=1)
    label: str = Field(min_length=1)
    description: str | None = None
    display_order: int = Field(ge=0)


class OptionUpdateRequest(APIModel):
    """Request body for partially updating an existing answer option.

    All fields are optional so callers can issue partial updates.
    """

    model_config = ConfigDict(extra="forbid")

    value: str | None = Field(default=None, min_length=1)
    label: str | None = Field(default=None, min_length=1)
    description: str | None = None
    display_order: int | None = Field(default=None, ge=0)


class OptionResponse(APIModel):
    """Full representation of a single answer option, including its ID and question link.

    Distinct from QuestionOptionResponse (which is embedded in the schema tree and
    omits id and question_id).  This model is used by list_options / create_option /
    update_option responses where the caller needs the identifiers for mutation.
    """

    id: str
    question_id: str
    value: str
    label: str
    description: str | None = None
    display_order: int


# ---------------------------------------------------------------------------
# Subtask mapping CRUD request/response models (Phase 155 — EDIT-07)
# ---------------------------------------------------------------------------


class MappingCreateRequest(APIModel):
    """Request body for creating a question-to-subtask mapping."""

    model_config = ConfigDict(extra="forbid")

    question_id: str = Field(min_length=1)
    subtask_key: str = Field(min_length=1)


class MappingResponse(APIModel):
    """Full representation of a question-to-subtask mapping record."""

    id: str
    question_id: str
    subtask_key: str
    created_at: str  # ISO-8601 string; datetime serialised by APIModel


# ---------------------------------------------------------------------------
# Schema version publish response model (Phase 155 — EDIT-07)
# ---------------------------------------------------------------------------


class SchemaVersionResponse(APIModel):
    """Response for a schema version publish operation."""

    version: int
    change_summary: str
    changed_by: str
    created_at: str  # ISO-8601 string


# ---------------------------------------------------------------------------
# Flat list response models for sections and questions (Phase 155 — EDIT-07)
# ---------------------------------------------------------------------------


class SectionListResponse(APIModel):
    """Flat section representation for list endpoints.

    Does not nest subgroups.  Used by list_sections() to return a lightweight
    list suitable for admin UI dropdowns and reorder controls.
    """

    id: str
    section_key: str
    label: str
    description: str | None = None
    icon_hint: str | None = None
    display_order: int
    is_active: bool
    schema_version: int
    depends_on_question_id: str | None = None
    expected_when: str | None = None
    condition_expr_json: str | None = None


class QuestionListResponse(APIModel):
    """Flat question representation for list endpoints.

    Does not nest options or subtask mappings.  Used by list_questions() to
    return a lightweight list suitable for admin UI and schema editor.
    """

    id: str
    subgroup_id: str
    question_type: str
    depth_level: str
    answer_type: str
    label: str
    instruction: str | None = None
    guideline: str | None = None
    help_text: str | None = None
    is_required: bool
    is_active: bool
    display_order: int
    schema_version: int
    depends_on_question_id: str | None = None
    expected_when: str | None = None
    condition_expr_json: str | None = None
    max_length: int | None = None
