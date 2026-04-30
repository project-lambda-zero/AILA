"""Schema tree query service and admin CRUD for the SbD NFR module.

Design references: D-02, D-11, D-17, D-18, D-37, D-38, D-39.

Each public function manages its own database session via UnitOfWork.
Private helpers (underscore-prefixed) accept a db session from the caller
for within-transaction atomicity.

Admin CRUD functions:
- Bump the schema version on every mutation (D-37).
- Emit a module-level activity record (analogous to D-17 audit events).
- Cascade soft-deletes in bulk UPDATE statements, not row-by-row loops (Pitfall 2).

Schema versioning:
- _bump_schema_version() inserts a new SbdNfrSchemaVersionRecord with the
  incremented version and returns the new version integer.
- All new records (sections, questions) have schema_version set to the bumped value.

Session compatibility:
- Uses db.exec() (SQLModel) returning model instances directly via .all() / .first() /
  .one_or_none() — no .scalars() wrapper needed.

Thread-safety:
- Functions are async; each opens its own session via UnitOfWork.
- No module-level mutable state.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import delete, update
from sqlmodel import select
from sqlalchemy.exc import IntegrityError

from aila.modules.sbd_nfr.contracts.schema import (
    MappingCreateRequest,
    MappingResponse,
    OptionCreateRequest,
    OptionResponse,
    OptionUpdateRequest,
    QuestionCreateRequest,
    QuestionListResponse,
    QuestionOptionResponse,
    QuestionResponse,
    QuestionUpdateRequest,
    SchemaTreeResponse,
    SchemaVersionResponse,
    SectionCreateRequest,
    SectionListResponse,
    SectionResponse,
    SectionUpdateRequest,
    SubgroupCreateRequest,
    SubgroupListResponse,
    SubgroupResponse,
    SubgroupUpdateRequest,
    SubtaskComponentResponse,
    SubtaskMappingResponse,
)
from aila.modules.sbd_nfr.db_models import (
    SbdNfrActivityRecord,
    SbdNfrQuestionOptionRecord,
    SbdNfrQuestionRecord,
    SbdNfrQuestionSubtaskMapRecord,
    SbdNfrSchemaVersionRecord,
    SbdNfrSectionRecord,
    SbdNfrSubgroupRecord,
    SbdNfrSubtaskComponentRecord,
)
from aila.platform.uow import UnitOfWork

__all__ = [
    "get_current_schema_version",
    "get_schema_tree",
    "get_subtask_components",
    "create_section",
    "update_section",
    "deactivate_section",
    "create_question",
    "update_question",
    "deactivate_question",
    # Phase 155 — EDIT-07
    "list_sections",
    "create_subgroup",
    "update_subgroup",
    "deactivate_subgroup",
    "list_questions",
    "list_options",
    "create_option",
    "update_option",
    "delete_option",
    "list_subtask_mappings",
    "create_subtask_mapping",
    "delete_subtask_mapping",
    "publish_schema_version",
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


async def _record_activity(
    db: object,
    *,
    event_type: str,
    actor: str,
    detail: dict,
) -> None:
    """Append a module-level activity record to SbdNfrActivityRecord.

    This is the sbd_nfr equivalent of D-17 audit events.  Records are
    append-only; no UPDATE or DELETE is permitted on this table.

    The session is NOT committed here — the caller's transaction controls timing.
    """
    try:
        detail_json = json.dumps(detail, sort_keys=True)
    except TypeError as exc:
        raise ValueError("activity detail must be JSON-serializable") from exc
    db.add(
        SbdNfrActivityRecord(
            id=str(uuid4()),
            session_id="__schema__",  # sentinel: not tied to a user session
            event_type=event_type,
            actor_name=actor,
            actor_email=actor,
            detail_json=detail_json,
            created_at=_utc_now(),
        )
    )


async def _bump_schema_version(
    db: object,
    change_summary: str,
    changed_by: str,
) -> int:
    """Insert a new SbdNfrSchemaVersionRecord and return the new version integer.

    Reads the current maximum version, increments by 1, and inserts the new
    record.  The session is NOT committed here.
    """
    current = await _get_current_schema_version(db)
    new_version = current + 1
    db.add(
        SbdNfrSchemaVersionRecord(
            id=str(uuid4()),
            version=new_version,
            change_summary=change_summary,
            changed_by=changed_by,
            created_at=_utc_now(),
        )
    )
    return new_version


async def _get_current_schema_version(db: object) -> int:
    """Return the highest version integer from SbdNfrSchemaVersionRecord (private helper).

    Returns 0 if no version records exist (initial state before seed_data()).
    Accepts a db session for within-transaction use.
    """
    row = (await db.exec(
        select(SbdNfrSchemaVersionRecord.version).order_by(
            SbdNfrSchemaVersionRecord.version.desc()  # type: ignore[union-attr]
        ).limit(1)
    )).one_or_none()
    # With PostgreSQL + SQLModel AsyncSession, column projections return Row
    # tuples rather than scalars; extract the first element when present.
    if row is None:
        return 0
    return int(row[0]) if hasattr(row, "__getitem__") else int(row)

async def _fallback_question_id(db: object, subgroup_id: str, label: str) -> str:
    """Build a fallback question id when the editor does not provide one."""
    subgroup = (await db.exec(
        select(SbdNfrSubgroupRecord).where(SbdNfrSubgroupRecord.id == subgroup_id)
    )).first()
    prefix_source = subgroup.subgroup_key if subgroup is not None else subgroup_id
    prefix = "".join(ch if ch.isalnum() else "_" for ch in prefix_source).strip("_").upper() or "QUESTION"
    label_part = "".join(ch if ch.isalnum() else "_" for ch in label).strip("_").upper() or "QUESTION"
    return f"{prefix}-{label_part}"[:50]


async def _get_subtask_components(db: object) -> list[SubtaskComponentResponse]:
    """Return all active sub-task components ordered by display_order (private helper)."""
    records = (await db.exec(
        select(SbdNfrSubtaskComponentRecord)
        .where(SbdNfrSubtaskComponentRecord.is_active == True)
        .order_by(SbdNfrSubtaskComponentRecord.display_order)
    )).all()
    return [
        SubtaskComponentResponse(
            key=r.key,
            label=r.label,
            category=r.category,
            description=r.description,
            icon_hint=r.icon_hint,
            display_order=r.display_order,
            is_active=r.is_active,
        )
        for r in records
    ]


# ---------------------------------------------------------------------------
# Schema tree query functions
# ---------------------------------------------------------------------------


async def get_current_schema_version() -> int:
    """Return the highest version integer from SbdNfrSchemaVersionRecord.

    Returns 0 if no version records exist (initial state before seed_data()).
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        return await _get_current_schema_version(db)


async def get_subtask_components() -> list[SubtaskComponentResponse]:
    """Return all active sub-task components ordered by display_order."""
    async with UnitOfWork() as _uow:
        db = _uow.session
        return await _get_subtask_components(db)


async def get_schema_tree(
    version: int | None = None,
) -> SchemaTreeResponse:
    """Build the nested section -> subgroup -> question tree for a schema version.

    Per D-11: returns all active sections with their subgroups, each subgroup
    with its active questions, each question with its options and sub-task
    mappings.  Ordered by display_order at every level.

    Args:
        version: Schema version to query.  Defaults to the current (latest) version.

    Returns:
        SchemaTreeResponse with the full nested tree and sub-task catalog.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        schema_version = version if version is not None else await _get_current_schema_version(db)

        # --- Sections ---
        sections = (await db.exec(
            select(SbdNfrSectionRecord)
            .where(
                SbdNfrSectionRecord.schema_version == schema_version,
                SbdNfrSectionRecord.is_active == True,
            )
            .order_by(SbdNfrSectionRecord.display_order)
        )).all()

        # --- Subgroups (bulk fetch, grouped in Python to avoid N+1) ---
        section_ids = [s.id for s in sections]
        subgroups_by_section: dict[str, list[SbdNfrSubgroupRecord]] = {}
        all_subgroups: list[SbdNfrSubgroupRecord] = []
        if section_ids:
            all_subgroups = list((await db.exec(
                select(SbdNfrSubgroupRecord)
                .where(
                    SbdNfrSubgroupRecord.schema_version == schema_version,
                    SbdNfrSubgroupRecord.is_active == True,
                    SbdNfrSubgroupRecord.section_id.in_(section_ids),  # type: ignore[union-attr]
                )
                .order_by(SbdNfrSubgroupRecord.display_order)
            )).all())
            for sg in all_subgroups:
                subgroups_by_section.setdefault(sg.section_id, []).append(sg)

        # --- Questions (bulk fetch) ---
        subgroup_ids = [sg.id for sg in all_subgroups]
        questions_by_subgroup: dict[str, list[SbdNfrQuestionRecord]] = {}
        all_questions: list[SbdNfrQuestionRecord] = []
        if subgroup_ids:
            all_questions = list((await db.exec(
                select(SbdNfrQuestionRecord)
                .where(
                    SbdNfrQuestionRecord.schema_version == schema_version,
                    SbdNfrQuestionRecord.is_active == True,
                    SbdNfrQuestionRecord.subgroup_id.in_(subgroup_ids),  # type: ignore[union-attr]
                )
                .order_by(SbdNfrQuestionRecord.display_order)
            )).all())
            for q in all_questions:
                questions_by_subgroup.setdefault(q.subgroup_id, []).append(q)

        # --- Options (bulk fetch) ---
        question_ids = [q.id for q in all_questions]
        options_by_question: dict[str, list[SbdNfrQuestionOptionRecord]] = {}
        if question_ids:
            all_options = list((await db.exec(
                select(SbdNfrQuestionOptionRecord)
                .where(SbdNfrQuestionOptionRecord.question_id.in_(question_ids))  # type: ignore[union-attr]
                .order_by(SbdNfrQuestionOptionRecord.display_order)
            )).all())
            for opt in all_options:
                options_by_question.setdefault(opt.question_id, []).append(opt)

        # --- Sub-task mappings (bulk fetch) ---
        maps_by_question: dict[str, list[SbdNfrQuestionSubtaskMapRecord]] = {}
        if question_ids:
            all_maps = list((await db.exec(
                select(SbdNfrQuestionSubtaskMapRecord)
                .where(SbdNfrQuestionSubtaskMapRecord.question_id.in_(question_ids))  # type: ignore[union-attr]
            )).all())
            for m in all_maps:
                maps_by_question.setdefault(m.question_id, []).append(m)

        # --- Assemble tree ---
        section_responses: list[SectionResponse] = []
        for sec in sections:
            subgroup_responses: list[SubgroupResponse] = []
            for sg in subgroups_by_section.get(sec.id, []):
                question_responses: list[QuestionResponse] = []
                for q in questions_by_subgroup.get(sg.id, []):
                    opts = [
                        QuestionOptionResponse(
                            value=o.value,
                            label=o.label,
                            description=o.description,
                            display_order=o.display_order,
                        )
                        for o in options_by_question.get(q.id, [])
                    ]
                    maps = [
                        SubtaskMappingResponse(subtask_key=m.subtask_key)
                        for m in maps_by_question.get(q.id, [])
                    ]
                    question_responses.append(
                        QuestionResponse(
                            id=q.id,
                            question_type=q.question_type,
                            depth_level=q.depth_level,
                            answer_type=q.answer_type,
                            label=q.label,
                            instruction=q.instruction,
                            guideline=q.guideline,
                            help_text=q.help_text,
                            is_required=q.is_required,
                            depends_on_question_id=q.depends_on_question_id,
                            expected_when=q.expected_when,
                            condition_expr_json=q.condition_expr_json,
                            display_order=q.display_order,
                            max_length=q.max_length,
                            options=opts,
                            subtask_mappings=maps,
                        )
                    )
                subgroup_responses.append(
                    SubgroupResponse(
                        id=sg.id,
                        subgroup_key=sg.subgroup_key,
                        label=sg.label,
                        description=sg.description,
                        display_order=sg.display_order,
                        questions=question_responses,
                    )
                )
            section_responses.append(
                SectionResponse(
                    id=sec.id,
                    section_key=sec.section_key,
                    label=sec.label,
                    description=sec.description,
                    icon_hint=sec.icon_hint,
                    display_order=sec.display_order,
                    depends_on_question_id=sec.depends_on_question_id,
                    expected_when=sec.expected_when,
                    condition_expr_json=sec.condition_expr_json,
                    subgroups=subgroup_responses,
                )
            )

        subtask_components = await _get_subtask_components(db)

        return SchemaTreeResponse(
            schema_version=schema_version,
            sections=section_responses,
            subtask_components=subtask_components,
        )


# ---------------------------------------------------------------------------
# Admin CRUD — sections
# ---------------------------------------------------------------------------


async def create_section(
    data: SectionCreateRequest,
    changed_by: str,
) -> SectionResponse:
    """Create a new section, bump schema version, and emit an activity record.

    Args:
        data: Validated section create payload.
        changed_by: Identity string of the admin performing the action.

    Returns:
        SectionResponse for the newly created section.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        new_version = await _bump_schema_version(
            db,
            change_summary=f"Created section '{data.section_key}'",
            changed_by=changed_by,
        )
        now = _utc_now()
        section = SbdNfrSectionRecord(
            id=str(uuid4()),
            schema_version=new_version,
            section_key=data.section_key,
            label=data.label,
            description=data.description,
            icon_hint=data.icon_hint,
            display_order=data.display_order,
            is_active=True,
            depends_on_question_id=data.depends_on_question_id,
            expected_when=data.expected_when,
            created_at=now,
            updated_at=now,
        )
        db.add(section)
        await _record_activity(
            db,
            event_type="sbd_nfr.section.created",
            actor=changed_by,
            detail={"section_key": data.section_key, "schema_version": new_version},
        )
        await db.commit()
        return SectionResponse(
            id=section.id,
            section_key=section.section_key,
            label=section.label,
            description=section.description,
            icon_hint=section.icon_hint,
            display_order=section.display_order,
            depends_on_question_id=section.depends_on_question_id,
            expected_when=section.expected_when,
        )


async def update_section(
    section_id: str,
    data: SectionUpdateRequest,
    changed_by: str,
) -> SectionResponse:
    """Update section fields, bump schema version, and emit an activity record.

    Args:
        section_id: Primary key of the section to update.
        data: Validated partial update payload.
        changed_by: Identity string of the admin performing the action.

    Returns:
        Updated SectionResponse.

    Raises:
        ValueError: If the section does not exist.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        section = (await db.exec(
            select(SbdNfrSectionRecord).where(SbdNfrSectionRecord.id == section_id)
        )).first()
        if section is None:
            raise ValueError(f"Section {section_id!r} not found")

        new_version = await _bump_schema_version(
            db,
            change_summary=f"Updated section '{section.section_key}'",
            changed_by=changed_by,
        )

        # Apply only the fields provided (non-None values in the request)
        if data.label is not None:
            section.label = data.label
        if data.description is not None:
            section.description = data.description
        if data.icon_hint is not None:
            section.icon_hint = data.icon_hint
        if data.display_order is not None:
            section.display_order = data.display_order
        if data.depends_on_question_id is not None:
            section.depends_on_question_id = data.depends_on_question_id
        if data.expected_when is not None:
            section.expected_when = data.expected_when
        if data.is_active is not None:
            section.is_active = data.is_active
        section.schema_version = new_version
        section.updated_at = _utc_now()

        db.add(section)
        await _record_activity(
            db,
            event_type="sbd_nfr.section.updated",
            actor=changed_by,
            detail={"section_id": section_id, "schema_version": new_version},
        )
        await db.commit()
        return SectionResponse(
            id=section.id,
            section_key=section.section_key,
            label=section.label,
            description=section.description,
            icon_hint=section.icon_hint,
            display_order=section.display_order,
            depends_on_question_id=section.depends_on_question_id,
            expected_when=section.expected_when,
        )


async def deactivate_section(
    section_id: str,
    changed_by: str,
) -> None:
    """Soft-delete a section and cascade to all its subgroups and questions.

    Per D-39 and Pitfall 2: cascading deactivation uses bulk UPDATE statements
    in a single transaction, NOT row-by-row loops.

    Args:
        section_id: Primary key of the section to deactivate.
        changed_by: Identity string of the admin performing the action.

    Raises:
        ValueError: If the section does not exist.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        check_result = await db.exec(
            select(SbdNfrSectionRecord.id, SbdNfrSectionRecord.section_key).where(
                SbdNfrSectionRecord.id == section_id
            )
        )
        row = check_result.first()
        if row is None:
            raise ValueError(f"Section {section_id!r} not found")
        section_key = row[1]

        # Collect subgroup IDs for cascading question deactivation
        subgroup_result = await db.exec(
            select(SbdNfrSubgroupRecord.id).where(
                SbdNfrSubgroupRecord.section_id == section_id
            )
        )
        subgroup_ids = [r[0] for r in subgroup_result.all()]

        now = _utc_now()

        # Bulk UPDATE 1: deactivate all questions in affected subgroups
        if subgroup_ids:
            await db.exec(
                update(SbdNfrQuestionRecord)
                .where(SbdNfrQuestionRecord.subgroup_id.in_(subgroup_ids))  # type: ignore[union-attr]
                .values(is_active=False, updated_at=now)
            )

        # Bulk UPDATE 2: deactivate all subgroups in the section
        await db.exec(
            update(SbdNfrSubgroupRecord)
            .where(SbdNfrSubgroupRecord.section_id == section_id)
            .values(is_active=False, updated_at=now)
        )

        # Bulk UPDATE 3: deactivate the section itself
        await db.exec(
            update(SbdNfrSectionRecord)
            .where(SbdNfrSectionRecord.id == section_id)
            .values(is_active=False, updated_at=now)
        )

        await _record_activity(
            db,
            event_type="sbd_nfr.section.deactivated",
            actor=changed_by,
            detail={
                "section_id": section_id,
                "section_key": section_key,
                "subgroups_affected": len(subgroup_ids),
            },
        )
        await db.commit()


# ---------------------------------------------------------------------------
# Admin CRUD — questions
# ---------------------------------------------------------------------------


async def create_question(
    data: QuestionCreateRequest,
    changed_by: str,
) -> QuestionResponse:
    """Create a new question in a subgroup, bump schema version, emit activity.

    Args:
        data: Validated question create payload.
        changed_by: Identity string of the admin performing the action.

    Returns:
        QuestionResponse for the newly created question.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        question_id = data.question_id or await _fallback_question_id(
            db,
            data.subgroup_id,
            data.label,
        )
        new_version = await _bump_schema_version(
            db,
            change_summary=f"Created question '{question_id}'",
            changed_by=changed_by,
        )
        now = _utc_now()
        question = SbdNfrQuestionRecord(
            id=question_id,
            schema_version=new_version,
            subgroup_id=data.subgroup_id,
            question_type=data.question_type,
            depth_level=data.depth_level,
            answer_type=data.answer_type,
            label=data.label,
            instruction=data.instruction,
            guideline=data.guideline,
            help_text=data.help_text,
            is_required=data.is_required,
            is_active=True,
            depends_on_question_id=data.depends_on_question_id,
            expected_when=data.expected_when,
            condition_expr_json=data.condition_expr_json,
            display_order=data.display_order,
            max_length=data.max_length,
            created_at=now,
            updated_at=now,
        )
        db.add(question)
        await _record_activity(
            db,
            event_type="sbd_nfr.question.created",
            actor=changed_by,
            detail={"question_id": question_id, "schema_version": new_version},
        )
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            raise ValueError(
                f"Question id {question_id!r} already exists. Rename the question or adjust the subgroup key."
            )
        return QuestionResponse(
            id=question.id,
            question_type=question.question_type,
            depth_level=question.depth_level,
            answer_type=question.answer_type,
            label=question.label,
            instruction=question.instruction,
            guideline=question.guideline,
            help_text=question.help_text,
            is_required=question.is_required,
            depends_on_question_id=question.depends_on_question_id,
            expected_when=question.expected_when,
            condition_expr_json=question.condition_expr_json,
            display_order=question.display_order,
            max_length=question.max_length,
            options=[],
            subtask_mappings=[],
        )


async def update_question(
    question_id: str,
    data: QuestionUpdateRequest,
    changed_by: str,
) -> QuestionResponse:
    """Update question fields, bump schema version, and emit an activity record.

    Args:
        question_id: Primary key of the question to update.
        data: Validated partial update payload.
        changed_by: Identity string of the admin performing the action.

    Returns:
        Updated QuestionResponse.

    Raises:
        ValueError: If the question does not exist.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        question = (await db.exec(
            select(SbdNfrQuestionRecord).where(SbdNfrQuestionRecord.id == question_id)
        )).first()
        if question is None:
            raise ValueError(f"Question {question_id!r} not found")

        new_version = await _bump_schema_version(
            db,
            change_summary=f"Updated question '{question_id}'",
            changed_by=changed_by,
        )

        if data.label is not None:
            question.label = data.label
        if data.question_type is not None:
            question.question_type = data.question_type
        if data.depth_level is not None:
            question.depth_level = data.depth_level
        if data.answer_type is not None:
            question.answer_type = data.answer_type
        if data.instruction is not None:
            question.instruction = data.instruction
        if data.guideline is not None:
            question.guideline = data.guideline
        if data.help_text is not None:
            question.help_text = data.help_text
        if data.is_required is not None:
            question.is_required = data.is_required
        if data.depends_on_question_id is not None:
            question.depends_on_question_id = data.depends_on_question_id
        if data.expected_when is not None:
            question.expected_when = data.expected_when
        if data.condition_expr_json is not None:
            question.condition_expr_json = data.condition_expr_json
        if data.display_order is not None:
            question.display_order = data.display_order
        if data.max_length is not None:
            question.max_length = data.max_length
        if data.is_active is not None:
            question.is_active = data.is_active
        question.schema_version = new_version
        question.updated_at = _utc_now()

        db.add(question)
        await _record_activity(
            db,
            event_type="sbd_nfr.question.updated",
            actor=changed_by,
            detail={"question_id": question_id, "schema_version": new_version},
        )
        await db.commit()
        return QuestionResponse(
            id=question.id,
            question_type=question.question_type,
            depth_level=question.depth_level,
            answer_type=question.answer_type,
            label=question.label,
            instruction=question.instruction,
            guideline=question.guideline,
            help_text=question.help_text,
            is_required=question.is_required,
            depends_on_question_id=question.depends_on_question_id,
            expected_when=question.expected_when,
            condition_expr_json=question.condition_expr_json,
            display_order=question.display_order,
            max_length=question.max_length,
            options=[],
            subtask_mappings=[],
        )


async def deactivate_question(
    question_id: str,
    changed_by: str,
) -> None:
    """Soft-delete a question by setting is_active=False.

    Args:
        question_id: Primary key of the question to deactivate.
        changed_by: Identity string of the admin performing the action.

    Raises:
        ValueError: If the question does not exist.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        check_result = await db.exec(
            select(SbdNfrQuestionRecord.id).where(SbdNfrQuestionRecord.id == question_id)
        )
        row = check_result.first()
        if row is None:
            raise ValueError(f"Question {question_id!r} not found")

        await db.exec(
            update(SbdNfrQuestionRecord)
            .where(SbdNfrQuestionRecord.id == question_id)
            .values(is_active=False, updated_at=_utc_now())
        )
        await _record_activity(
            db,
            event_type="sbd_nfr.question.deactivated",
            actor=changed_by,
            detail={"question_id": question_id},
        )
        await db.commit()


# ---------------------------------------------------------------------------
# Phase 155 — EDIT-07: sections flat list, subgroup CRUD
# ---------------------------------------------------------------------------


async def list_sections(
    schema_version: int | None = None,
    include_inactive: bool = False,
) -> list[SectionListResponse]:
    """Return a flat ordered list of sections.

    Args:
        schema_version: Version to query.  Defaults to the current (latest) version.
        include_inactive: When True, inactive sections are included.

    Returns:
        List of SectionListResponse ordered by display_order.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        version = schema_version if schema_version is not None else await _get_current_schema_version(db)
        stmt = (
            select(SbdNfrSectionRecord)
            .where(SbdNfrSectionRecord.schema_version == version)
            .order_by(SbdNfrSectionRecord.display_order)
        )
        if not include_inactive:
            stmt = stmt.where(SbdNfrSectionRecord.is_active == True)
        records = (await db.exec(stmt)).all()
        return [
            SectionListResponse(
                id=r.id,
                section_key=r.section_key,
                label=r.label,
                description=r.description,
                icon_hint=r.icon_hint,
                display_order=r.display_order,
                is_active=r.is_active,
                schema_version=r.schema_version,
                depends_on_question_id=r.depends_on_question_id,
                expected_when=r.expected_when,
                condition_expr_json=r.condition_expr_json,
            )
            for r in records
        ]


async def create_subgroup(
    data: SubgroupCreateRequest,
    changed_by: str,
) -> SubgroupListResponse:
    """Create a new subgroup within a section, bump schema version, emit activity.

    Args:
        data: Validated subgroup create payload.
        changed_by: Identity string of the admin performing the action.

    Returns:
        SubgroupListResponse for the newly created subgroup.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        new_version = await _bump_schema_version(
            db,
            change_summary=f"Created subgroup '{data.subgroup_key}'",
            changed_by=changed_by,
        )
        now = _utc_now()
        subgroup = SbdNfrSubgroupRecord(
            id=str(uuid4()),
            schema_version=new_version,
            section_id=data.section_id,
            subgroup_key=data.subgroup_key,
            label=data.label,
            description=data.description,
            display_order=data.display_order,
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        db.add(subgroup)
        await _record_activity(
            db,
            event_type="sbd_nfr.subgroup.created",
            actor=changed_by,
            detail={"subgroup_key": data.subgroup_key, "section_id": data.section_id, "schema_version": new_version},
        )
        await db.commit()
        return SubgroupListResponse(
            id=subgroup.id,
            subgroup_key=subgroup.subgroup_key,
            label=subgroup.label,
            description=subgroup.description,
            display_order=subgroup.display_order,
            section_id=subgroup.section_id,
            is_active=subgroup.is_active,
        )


async def update_subgroup(
    subgroup_id: str,
    data: SubgroupUpdateRequest,
    changed_by: str,
) -> SubgroupListResponse:
    """Update subgroup fields, bump schema version, and emit an activity record.

    All fields in data are optional; only non-None values are applied.

    Args:
        subgroup_id: Primary key of the subgroup to update.
        data: Validated partial update payload.
        changed_by: Identity string of the admin performing the action.

    Returns:
        Updated SubgroupListResponse.

    Raises:
        ValueError: If the subgroup does not exist.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        subgroup = (await db.exec(
            select(SbdNfrSubgroupRecord).where(SbdNfrSubgroupRecord.id == subgroup_id)
        )).first()
        if subgroup is None:
            raise ValueError(f"Subgroup {subgroup_id!r} not found")

        new_version = await _bump_schema_version(
            db,
            change_summary=f"Updated subgroup '{subgroup.subgroup_key}'",
            changed_by=changed_by,
        )

        if data.label is not None:
            subgroup.label = data.label
        if data.description is not None:
            subgroup.description = data.description
        if data.display_order is not None:
            subgroup.display_order = data.display_order
        if data.is_active is not None:
            subgroup.is_active = data.is_active
        subgroup.schema_version = new_version
        subgroup.updated_at = _utc_now()

        db.add(subgroup)
        await _record_activity(
            db,
            event_type="sbd_nfr.subgroup.updated",
            actor=changed_by,
            detail={"subgroup_id": subgroup_id, "schema_version": new_version},
        )
        await db.commit()
        return SubgroupListResponse(
            id=subgroup.id,
            subgroup_key=subgroup.subgroup_key,
            label=subgroup.label,
            description=subgroup.description,
            display_order=subgroup.display_order,
            section_id=subgroup.section_id,
            is_active=subgroup.is_active,
        )


async def deactivate_subgroup(
    subgroup_id: str,
    changed_by: str,
) -> None:
    """Soft-delete a subgroup and cascade to all its questions.

    Per Pitfall 2: cascading deactivation uses bulk UPDATE statements, not
    row-by-row loops.

    Args:
        subgroup_id: Primary key of the subgroup to deactivate.
        changed_by: Identity string of the admin performing the action.

    Raises:
        ValueError: If the subgroup does not exist.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        check_result = await db.exec(
            select(SbdNfrSubgroupRecord.id, SbdNfrSubgroupRecord.subgroup_key).where(
                SbdNfrSubgroupRecord.id == subgroup_id
            )
        )
        row = check_result.first()
        if row is None:
            raise ValueError(f"Subgroup {subgroup_id!r} not found")
        subgroup_key = row[1]

        now = _utc_now()

        # Bulk UPDATE 1: deactivate all questions in the subgroup
        await db.exec(
            update(SbdNfrQuestionRecord)
            .where(SbdNfrQuestionRecord.subgroup_id == subgroup_id)
            .values(is_active=False, updated_at=now)
        )

        # Bulk UPDATE 2: deactivate the subgroup itself
        await db.exec(
            update(SbdNfrSubgroupRecord)
            .where(SbdNfrSubgroupRecord.id == subgroup_id)
            .values(is_active=False, updated_at=now)
        )

        await _record_activity(
            db,
            event_type="sbd_nfr.subgroup.deactivated",
            actor=changed_by,
            detail={"subgroup_id": subgroup_id, "subgroup_key": subgroup_key},
        )
        await db.commit()


# ---------------------------------------------------------------------------
# Phase 155 — EDIT-07: questions flat list
# ---------------------------------------------------------------------------


async def list_questions(
    subgroup_id: str | None = None,
    schema_version: int | None = None,
    include_inactive: bool = False,
) -> list[QuestionListResponse]:
    """Return a flat ordered list of questions.

    Args:
        subgroup_id: Optional filter by subgroup.
        schema_version: Version to query.  Defaults to the current (latest) version.
        include_inactive: When True, inactive questions are included.

    Returns:
        List of QuestionListResponse ordered by display_order.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        version = schema_version if schema_version is not None else await _get_current_schema_version(db)
        stmt = (
            select(SbdNfrQuestionRecord)
            .where(SbdNfrQuestionRecord.schema_version == version)
            .order_by(SbdNfrQuestionRecord.display_order)
        )
        if not include_inactive:
            stmt = stmt.where(SbdNfrQuestionRecord.is_active == True)
        if subgroup_id is not None:
            stmt = stmt.where(SbdNfrQuestionRecord.subgroup_id == subgroup_id)
        records = (await db.exec(stmt)).all()
        return [
            QuestionListResponse(
                id=r.id,
                subgroup_id=r.subgroup_id,
                question_type=r.question_type,
                depth_level=r.depth_level,
                answer_type=r.answer_type,
                label=r.label,
                instruction=r.instruction,
                guideline=r.guideline,
                help_text=r.help_text,
                is_required=r.is_required,
                is_active=r.is_active,
                display_order=r.display_order,
                schema_version=r.schema_version,
                depends_on_question_id=r.depends_on_question_id,
                expected_when=r.expected_when,
                condition_expr_json=r.condition_expr_json,
                max_length=r.max_length,
            )
            for r in records
        ]


# ---------------------------------------------------------------------------
# Phase 155 — EDIT-07: option CRUD
# ---------------------------------------------------------------------------


async def list_options(
    question_id: str,
) -> list[OptionResponse]:
    """Return all answer options for a question, ordered by display_order.

    Args:
        question_id: The question whose options are returned.

    Returns:
        List of OptionResponse ordered by display_order.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        records = (await db.exec(
            select(SbdNfrQuestionOptionRecord)
            .where(SbdNfrQuestionOptionRecord.question_id == question_id)
            .order_by(SbdNfrQuestionOptionRecord.display_order)
        )).all()
        return [
            OptionResponse(
                id=r.id,
                question_id=r.question_id,
                value=r.value,
                label=r.label,
                description=r.description,
                display_order=r.display_order,
            )
            for r in records
        ]


async def create_option(
    data: OptionCreateRequest,
    changed_by: str,
) -> OptionResponse:
    """Create a new answer option for a question and emit an activity record.

    Options are data, not structural schema — no schema version bump is issued.

    Args:
        data: Validated option create payload.
        changed_by: Identity string of the admin performing the action.

    Returns:
        OptionResponse for the newly created option.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        now = _utc_now()
        option = SbdNfrQuestionOptionRecord(
            id=str(uuid4()),
            question_id=data.question_id,
            value=data.value,
            label=data.label,
            description=data.description,
            display_order=data.display_order,
            created_at=now,
        )
        db.add(option)
        await _record_activity(
            db,
            event_type="sbd_nfr.option.created",
            actor=changed_by,
            detail={"question_id": data.question_id, "value": data.value},
        )
        await db.commit()
        return OptionResponse(
            id=option.id,
            question_id=option.question_id,
            value=option.value,
            label=option.label,
            description=option.description,
            display_order=option.display_order,
        )


async def update_option(
    option_id: str,
    data: OptionUpdateRequest,
    changed_by: str,
) -> OptionResponse:
    """Update answer option fields and emit an activity record.

    All fields in data are optional; only non-None values are applied.
    No schema version bump — options are data, not structural schema.

    Args:
        option_id: Primary key of the option to update.
        data: Validated partial update payload.
        changed_by: Identity string of the admin performing the action.

    Returns:
        Updated OptionResponse.

    Raises:
        ValueError: If the option does not exist.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        option = (await db.exec(
            select(SbdNfrQuestionOptionRecord).where(SbdNfrQuestionOptionRecord.id == option_id)
        )).first()
        if option is None:
            raise ValueError(f"Option {option_id!r} not found")

        if data.value is not None:
            option.value = data.value
        if data.label is not None:
            option.label = data.label
        if data.description is not None:
            option.description = data.description
        if data.display_order is not None:
            option.display_order = data.display_order

        db.add(option)
        await _record_activity(
            db,
            event_type="sbd_nfr.option.updated",
            actor=changed_by,
            detail={"option_id": option_id, "question_id": option.question_id},
        )
        await db.commit()
        return OptionResponse(
            id=option.id,
            question_id=option.question_id,
            value=option.value,
            label=option.label,
            description=option.description,
            display_order=option.display_order,
        )


async def delete_option(
    option_id: str,
    changed_by: str,
) -> None:
    """Hard-delete an answer option and emit an activity record.

    SbdNfrQuestionOptionRecord has no is_active field; removal is a hard DELETE.

    Args:
        option_id: Primary key of the option to delete.
        changed_by: Identity string of the admin performing the action.

    Raises:
        ValueError: If the option does not exist.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        check_result = await db.exec(
            select(SbdNfrQuestionOptionRecord.id, SbdNfrQuestionOptionRecord.question_id).where(
                SbdNfrQuestionOptionRecord.id == option_id
            )
        )
        row = check_result.first()
        if row is None:
            raise ValueError(f"Option {option_id!r} not found")
        question_id = row[1]

        await db.exec(
            delete(SbdNfrQuestionOptionRecord).where(SbdNfrQuestionOptionRecord.id == option_id)
        )
        await _record_activity(
            db,
            event_type="sbd_nfr.option.deleted",
            actor=changed_by,
            detail={"option_id": option_id, "question_id": question_id},
        )
        await db.commit()


# ---------------------------------------------------------------------------
# Phase 155 — EDIT-07: subtask mapping CRUD
# ---------------------------------------------------------------------------


async def list_subtask_mappings(
    question_id: str | None = None,
    subtask_key: str | None = None,
) -> list[MappingResponse]:
    """Return subtask mappings with optional filters.

    Args:
        question_id: Optional filter by question.
        subtask_key: Optional filter by subtask component key.

    Returns:
        List of MappingResponse.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        stmt = select(SbdNfrQuestionSubtaskMapRecord)
        if question_id is not None:
            stmt = stmt.where(SbdNfrQuestionSubtaskMapRecord.question_id == question_id)
        if subtask_key is not None:
            stmt = stmt.where(SbdNfrQuestionSubtaskMapRecord.subtask_key == subtask_key)
        records = (await db.exec(stmt)).all()
        return [
            MappingResponse(
                id=r.id,
                question_id=r.question_id,
                subtask_key=r.subtask_key,
                created_at=r.created_at.isoformat(),
            )
            for r in records
        ]


async def create_subtask_mapping(
    data: MappingCreateRequest,
    changed_by: str,
) -> MappingResponse:
    """Create a question-to-subtask mapping and emit an activity record.

    The unique constraint (question_id, subtask_key) is enforced at the DB level.
    An IntegrityError on duplicate is caught and re-raised as ValueError so the
    router can return HTTP 409 (T-155-01).

    Args:
        data: Validated mapping create payload.
        changed_by: Identity string of the admin performing the action.

    Returns:
        MappingResponse for the newly created mapping.

    Raises:
        ValueError: If a mapping for (question_id, subtask_key) already exists.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        now = _utc_now()
        mapping = SbdNfrQuestionSubtaskMapRecord(
            id=str(uuid4()),
            question_id=data.question_id,
            subtask_key=data.subtask_key,
            created_at=now,
        )
        db.add(mapping)
        await _record_activity(
            db,
            event_type="sbd_nfr.mapping.created",
            actor=changed_by,
            detail={"question_id": data.question_id, "subtask_key": data.subtask_key},
        )
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            raise ValueError(
                f"Mapping for question {data.question_id!r} → subtask {data.subtask_key!r} already exists"
            )
        return MappingResponse(
            id=mapping.id,
            question_id=mapping.question_id,
            subtask_key=mapping.subtask_key,
            created_at=mapping.created_at.isoformat(),
        )


async def delete_subtask_mapping(
    mapping_id: str,
    changed_by: str,
) -> None:
    """Hard-delete a question-to-subtask mapping and emit an activity record.

    Args:
        mapping_id: Primary key of the mapping to delete.
        changed_by: Identity string of the admin performing the action.

    Raises:
        ValueError: If the mapping does not exist.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        check_result = await db.exec(
            select(
                SbdNfrQuestionSubtaskMapRecord.id,
                SbdNfrQuestionSubtaskMapRecord.question_id,
                SbdNfrQuestionSubtaskMapRecord.subtask_key,
            ).where(SbdNfrQuestionSubtaskMapRecord.id == mapping_id)
        )
        row = check_result.first()
        if row is None:
            raise ValueError(f"Mapping {mapping_id!r} not found")
        question_id, subtask_key = row[1], row[2]

        await db.exec(
            delete(SbdNfrQuestionSubtaskMapRecord).where(
                SbdNfrQuestionSubtaskMapRecord.id == mapping_id
            )
        )
        await _record_activity(
            db,
            event_type="sbd_nfr.mapping.deleted",
            actor=changed_by,
            detail={"mapping_id": mapping_id, "question_id": question_id, "subtask_key": subtask_key},
        )
        await db.commit()


# ---------------------------------------------------------------------------
# Phase 155 — EDIT-07: schema version publish
# ---------------------------------------------------------------------------


async def publish_schema_version(
    change_summary: str,
    changed_by: str,
) -> SchemaVersionResponse:
    """Publish a new schema version by bumping the version counter.

    Inserts a new SbdNfrSchemaVersionRecord (via _bump_schema_version), records
    a publish activity event, commits, and returns the new version details.

    Args:
        change_summary: Human-readable description of what changed.
        changed_by: Identity string of the admin performing the action.

    Returns:
        SchemaVersionResponse with the newly published version details.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        now = _utc_now()
        new_version = await _bump_schema_version(db, change_summary=change_summary, changed_by=changed_by)
        await _record_activity(
            db,
            event_type="sbd_nfr.schema.published",
            actor=changed_by,
            detail={"schema_version": new_version, "change_summary": change_summary},
        )
        await db.commit()
        return SchemaVersionResponse(
            version=new_version,
            change_summary=change_summary,
            changed_by=changed_by,
            created_at=now.isoformat(),
        )
