"""Answer CRUD service for the SbD NFR module.

Design references: D-21, D-29, D-31, D-34, D-41, Pitfall 5, T-134-10, T-134-11.

Each public function manages its own database session via UnitOfWork.
Private helpers (underscore-prefixed) accept a db session from the caller
for within-transaction atomicity.

Key design decisions:
  - bulk_upsert_answers: single-transaction upsert per section (D-31).
    Last-write-wins for existing answers (D-41). Updates session status
    from 'draft' to 'in_progress' on first save (D-20). Resets expiry (D-62).
  - _validate_completion: uses compute_visible_question_ids() to exclude
    hidden questions from the missing list (Pitfall 5, D-34).
  - T-134-11: BulkAnswerRequest.answers is already bounded by Field(max_length=500)
    in contracts/session.py; no further limit needed here.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlmodel import select

from aila.modules.sbd_nfr.contracts.session import (
    AnswerInput,
    SectionProgressResponse,
)
from aila.modules.sbd_nfr.db_models import (
    SbdNfrAnswerRecord,
    SbdNfrQuestionOptionRecord,
    SbdNfrQuestionRecord,
    SbdNfrSectionRecord,
    SbdNfrSessionRecord,
    SbdNfrSubgroupRecord,
)
from aila.modules.sbd_nfr.services.skip_logic import (
    QuestionSkipInfo,
    compute_section_progress,
    compute_visible_question_ids,
)
from aila.platform.uow import UnitOfWork

__all__ = [
    "bulk_upsert_answers",
    "validate_answer",
    "validate_completion",
    "compute_all_section_progress",
]

_log = logging.getLogger(__name__)

_DRAFT_EXPIRY_DAYS: int = 30


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _draft_expires_at() -> datetime:
    return _utc_now() + timedelta(days=_DRAFT_EXPIRY_DAYS)


async def validate_answer(
    question: SbdNfrQuestionRecord,
    answer_value: str,
    options: list[SbdNfrQuestionOptionRecord],
) -> str | None:
    """Validate an answer against question constraints (D-21, T-134-10).

    Args:
        question: The question record being answered.
        answer_value: The submitted answer value.
        options: All available option records for this question.

    Returns:
        None if valid. An error message string if invalid.
    """
    if question.is_required and not answer_value:
        return f"Question '{question.id}' is required but answer is empty"

    if question.answer_type in ("single_choice", "compliance"):
        valid_values = {o.value for o in options}
        if answer_value and answer_value not in valid_values:
            return (
                f"Answer '{answer_value}' is not a valid option for question '{question.id}'. "
                f"Valid options: {sorted(valid_values)}"
            )

    if question.max_length is not None and len(answer_value) > question.max_length:
        return (
            f"Answer for question '{question.id}' exceeds max length "
            f"({len(answer_value)} > {question.max_length})"
        )

    return None


async def _validate_completion(
    db: object,
    session_id: str,
) -> list[str]:
    """Return missing question IDs that would block completion (private helper).

    Accepts a db session for within-transaction use by session_service.complete_session.

    A question is "missing" if it is:
      - visible (skip-logic passes), AND
      - required (is_required=True), AND
      - unanswered (no SbdNfrAnswerRecord for this session_id + question_id).

    Hidden questions (skip-logic-invisible) are NEVER included in the missing
    list even if they have is_required=True (Pitfall 5).
    """
    from fastapi import HTTPException

    # Load session
    session = (await db.exec(
        select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
    )).first()
    if session is None or session.is_deleted:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")

    schema_version = session.schema_version_at_start

    # Load all answers
    answers_map: dict[str, str] = {
        r.question_id: r.answer_value
        for r in (await db.exec(
            select(SbdNfrAnswerRecord).where(SbdNfrAnswerRecord.session_id == session_id)
        )).all()
    }

    # Load all active questions for pinned schema version
    all_questions = list((await db.exec(
        select(SbdNfrQuestionRecord)
        .where(
            SbdNfrQuestionRecord.schema_version == schema_version,
            SbdNfrQuestionRecord.is_active == True,
        )
        .order_by(SbdNfrQuestionRecord.display_order)
    )).all())

    skip_infos = [
        QuestionSkipInfo(
            id=q.id,
            is_active=q.is_active,
            is_required=q.is_required,
            depends_on_question_id=q.depends_on_question_id,
            expected_when=q.expected_when,
        )
        for q in all_questions
    ]

    visible_ids = compute_visible_question_ids(skip_infos, answers_map)

    return [
        q.id
        for q in all_questions
        if q.id in visible_ids and q.is_required and q.id not in answers_map
    ]


async def bulk_upsert_answers(
    db: object,
    session_id: str,
    section_key: str,
    answers: list[AnswerInput],
    contributor_name: str,
    contributor_email: str,
    schema_version: int,
) -> SectionProgressResponse:
    """Upsert a section's answers in a single transaction (D-31).

    For each answer:
      - If an existing SbdNfrAnswerRecord exists for (session_id, question_id):
        update answer_value, note_text, answered_by_name/email, updated_at
        (last-write-wins per D-41).
      - If no record exists: insert a new one.

    Side effects:
      - Transitions session.status from 'draft' to 'in_progress' on first answer (D-20).
      - Resets session.expires_at to now + _DRAFT_EXPIRY_DAYS (D-62).
      - Updates session.updated_at.

    NOTE: This function accepts a db session directly because it is called from
    api_router handlers that open their own UnitOfWork for the inline session
    record query.  The caller owns the transaction.

    Args:
        db: Async database session (caller owns the transaction).
        session_id: Session primary key.
        section_key: Section identifier — used to compute section progress in return value.
        answers: List of AnswerInput objects from the bulk PATCH request.
        contributor_name: Identity of the answering person (for audit; D-25).
        contributor_email: Identity of the answering person (for audit; D-25).
        schema_version: Schema version at answer time.

    Returns:
        SectionProgressResponse for the section after saving.

    Raises:
        HTTPException(404): Session not found.
    """
    from fastapi import HTTPException
    from sqlalchemy import update as sa_update

    # Load session
    session = (await db.exec(
        select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
    )).first()
    if session is None or session.is_deleted:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")

    # Load existing answers for this session (for upsert dispatch)
    existing_by_qid: dict[str, SbdNfrAnswerRecord] = {
        r.question_id: r for r in (await db.exec(
            select(SbdNfrAnswerRecord).where(SbdNfrAnswerRecord.session_id == session_id)
        )).all()
    }

    now = _utc_now()

    for answer_input in answers:
        qid = answer_input.question_id
        if qid in existing_by_qid:
            # Update existing record (last-write-wins D-41)
            record = existing_by_qid[qid]
            record.answer_value = answer_input.answer_value
            record.note_text = answer_input.note_text
            record.answered_by_name = contributor_name
            record.answered_by_email = contributor_email
            record.schema_version = schema_version
            record.updated_at = now
            db.add(record)
        else:
            # Insert new record
            db.add(
                SbdNfrAnswerRecord(
                    id=str(uuid4()),
                    session_id=session_id,
                    question_id=qid,
                    answer_value=answer_input.answer_value,
                    note_text=answer_input.note_text,
                    answered_by_name=contributor_name,
                    answered_by_email=contributor_email,
                    schema_version=schema_version,
                    created_at=now,
                    updated_at=now,
                )
            )

    # Transition draft -> in_progress on first save (D-20)
    new_status = session.status
    if session.status == "draft":
        new_status = "in_progress"

    # Reset expiry and updated_at (D-62)
    await db.exec(
        sa_update(SbdNfrSessionRecord)
        .where(SbdNfrSessionRecord.id == session_id)
        .values(
            status=new_status,
            expires_at=_draft_expires_at(),
            updated_at=now,
        )
    )

    await db.commit()

    # Compute and return section progress for the target section
    return await _compute_section_progress_for_key(db, session_id, section_key, session.schema_version_at_start)


async def validate_completion(
    session_id: str,
) -> list[str]:
    """Return the list of missing question IDs that would block completion (D-34, Pitfall 5).

    A question is "missing" if it is visible, required, and unanswered.
    Hidden questions (skip-logic-invisible) are NEVER included (Pitfall 5).

    Args:
        session_id: Session primary key.

    Returns:
        List of question IDs that are visible, required, and unanswered.
        Empty list means all required visible questions are answered.

    Raises:
        HTTPException(404): Session not found.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        return await _validate_completion(db, session_id)


async def compute_all_section_progress(
    session_id: str,
) -> list[SectionProgressResponse]:
    """Compute progress for all sections of a session (used by get_session_detail).

    Loads questions grouped by section, computes visibility via skip logic,
    returns progress per section.

    Args:
        session_id: Session primary key.

    Returns:
        List of SectionProgressResponse for each active section.

    Raises:
        HTTPException(404): Session not found.
    """
    from fastapi import HTTPException

    async with UnitOfWork() as _uow:
        db = _uow.session
        session = (await db.exec(
            select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
        )).first()
        if session is None or session.is_deleted:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")

        schema_version = session.schema_version_at_start

        # Load all answers
        answers_map: dict[str, str] = {
            r.question_id: r.answer_value
            for r in (await db.exec(
                select(SbdNfrAnswerRecord).where(SbdNfrAnswerRecord.session_id == session_id)
            )).all()
        }

        # Load sections
        sections = list((await db.exec(
            select(SbdNfrSectionRecord)
            .where(
                SbdNfrSectionRecord.schema_version == schema_version,
                SbdNfrSectionRecord.is_active == True,
            )
            .order_by(SbdNfrSectionRecord.display_order)
        )).all())

        # Load subgroups
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

        # Load questions
        subgroup_ids = [sg.id for sg in all_subgroups]
        questions_by_subgroup: dict[str, list[SbdNfrQuestionRecord]] = {}
        all_question_records: list[SbdNfrQuestionRecord] = []
        if subgroup_ids:
            all_question_records = list((await db.exec(
                select(SbdNfrQuestionRecord)
                .where(
                    SbdNfrQuestionRecord.schema_version == schema_version,
                    SbdNfrQuestionRecord.is_active == True,
                    SbdNfrQuestionRecord.subgroup_id.in_(subgroup_ids),  # type: ignore[union-attr]
                )
                .order_by(SbdNfrQuestionRecord.display_order)
            )).all())
            for q in all_question_records:
                questions_by_subgroup.setdefault(q.subgroup_id, []).append(q)

        # Build global skip info for cross-section visibility
        all_skip_infos: list[QuestionSkipInfo] = [
            QuestionSkipInfo(
                id=q.id,
                is_active=q.is_active,
                is_required=q.is_required,
                depends_on_question_id=q.depends_on_question_id,
                expected_when=q.expected_when,
            )
            for q in all_question_records
        ]
        visible_ids = compute_visible_question_ids(all_skip_infos, answers_map)

        progress_list: list[SectionProgressResponse] = []
        for sec in sections:
            sec_questions: list[QuestionSkipInfo] = []
            for sg in subgroups_by_section.get(sec.id, []):
                for q in questions_by_subgroup.get(sg.id, []):
                    sec_questions.append(
                        QuestionSkipInfo(
                            id=q.id,
                            is_active=q.is_active,
                            is_required=q.is_required,
                            depends_on_question_id=q.depends_on_question_id,
                            expected_when=q.expected_when,
                        )
                    )
            prog = compute_section_progress(sec_questions, answers_map, visible_ids)
            progress_list.append(
                SectionProgressResponse(
                    section_key=sec.section_key,
                    visible_count=prog.visible_count,
                    answered_count=prog.answered_count,
                    total_count=prog.total_count,
                )
            )

        return progress_list


# ---------------------------------------------------------------------------
# Internal helper — section progress for a specific section_key
# ---------------------------------------------------------------------------


async def _compute_section_progress_for_key(
    db: object,
    session_id: str,
    section_key: str,
    schema_version: int,
) -> SectionProgressResponse:
    """Compute progress for a single section identified by section_key.

    Returns a zero-count SectionProgressResponse if the section_key is not
    found in this schema version (e.g., section was deactivated).
    """
    # Load answers (fresh after flush)
    answers_map: dict[str, str] = {
        r.question_id: r.answer_value
        for r in (await db.exec(
            select(SbdNfrAnswerRecord).where(SbdNfrAnswerRecord.session_id == session_id)
        )).all()
    }

    # Load target section
    section = (await db.exec(
        select(SbdNfrSectionRecord)
        .where(
            SbdNfrSectionRecord.schema_version == schema_version,
            SbdNfrSectionRecord.section_key == section_key,
            SbdNfrSectionRecord.is_active == True,
        )
        .limit(1)
    )).first()
    if section is None:
        return SectionProgressResponse(
            section_key=section_key,
            visible_count=0,
            answered_count=0,
            total_count=0,
        )

    # Load subgroups for this section
    subgroups = list((await db.exec(
        select(SbdNfrSubgroupRecord)
        .where(
            SbdNfrSubgroupRecord.schema_version == schema_version,
            SbdNfrSubgroupRecord.section_id == section.id,
            SbdNfrSubgroupRecord.is_active == True,
        )
        .order_by(SbdNfrSubgroupRecord.display_order)
    )).all())
    subgroup_ids = [sg.id for sg in subgroups]

    # Load questions for this section
    sec_questions: list[QuestionSkipInfo] = []
    all_questions_for_visibility: list[QuestionSkipInfo] = []

    if subgroup_ids:
        q_records = list((await db.exec(
            select(SbdNfrQuestionRecord)
            .where(
                SbdNfrQuestionRecord.schema_version == schema_version,
                SbdNfrQuestionRecord.is_active == True,
                SbdNfrQuestionRecord.subgroup_id.in_(subgroup_ids),  # type: ignore[union-attr]
            )
            .order_by(SbdNfrQuestionRecord.display_order)
        )).all())
        for q in q_records:
            info = QuestionSkipInfo(
                id=q.id,
                is_active=q.is_active,
                is_required=q.is_required,
                depends_on_question_id=q.depends_on_question_id,
                expected_when=q.expected_when,
            )
            sec_questions.append(info)
            all_questions_for_visibility.append(info)

    visible_ids = compute_visible_question_ids(all_questions_for_visibility, answers_map)
    prog = compute_section_progress(sec_questions, answers_map, visible_ids)

    return SectionProgressResponse(
        section_key=section_key,
        visible_count=prog.visible_count,
        answered_count=prog.answered_count,
        total_count=prog.total_count,
    )
