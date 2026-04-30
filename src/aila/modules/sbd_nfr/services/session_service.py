"""Session lifecycle service for the SbD NFR module.

Design references: D-05, D-06, D-20, D-26, D-27, D-30, D-32, D-33, D-34,
D-35a, D-36, D-51, D-53, D-55, D-60, D-62.

Each public function manages its own database session via UnitOfWork.
Private helpers (underscore-prefixed) accept a db session from the caller
for within-transaction atomicity.

Status state machine (D-20):
    draft -> in_progress -> completed -> resolving -> resolved | resolution_failed | expired
    resolution_failed -> resolving (retryable, D-24)
    expired -> draft (revivable, D-62)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Generic, TypeVar
from uuid import uuid4

import sqlalchemy.exc
from sqlmodel import select

from aila.platform.exceptions import AILAError
from aila.platform.uow import UnitOfWork

if TYPE_CHECKING:
    from aila.platform.contracts.platform import AsyncTaskQueue

from aila.modules.sbd_nfr.contracts.session import (
    AnswerResponse,
    SectionProgressResponse,
    SessionCreateRequest,
    SessionDetailResponse,
    SessionSummaryResponse,
)
from aila.modules.sbd_nfr.db_models import (
    SbdNfrActivityRecord,
    SbdNfrAnswerRecord,
    SbdNfrQuestionRecord,
    SbdNfrSectionRecord,
    SbdNfrSessionRecord,
    SbdNfrSessionSystemRecord,
    SbdNfrSubgroupRecord,
)
from aila.modules.sbd_nfr.services.schema_service import _get_current_schema_version
from aila.modules.sbd_nfr.services.scoring_service import (
    QuestionScoreInfo,
    compute_posture_index,
    compute_section_scores,
    derive_risk_tier,
)
from aila.modules.sbd_nfr.services.skip_logic import (
    QuestionSkipInfo,
    compute_section_progress,
    compute_visible_question_ids,
)
from aila.modules.sbd_nfr.services.triage_service import build_triage_context

__all__ = [
    "SessionListFilters",
    "PaginatedResponse",
    "create_session",
    "get_session_detail",
    "list_sessions",
    "clone_session",
    "complete_session",
    "soft_delete_session",
    "hard_delete_session",
    "export_session",
    "assign_architect",
    "update_session_status",
    "submit_for_review",
    "approve_session",
    "save_architect_notes",
]

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Status transition machine (D-20) — 7 states
# ---------------------------------------------------------------------------

_VALID_TRANSITIONS: dict[str, set[str]] = {
    "draft": {"in_progress"},
    "in_progress": {"completed"},
    "completed": {"resolving"},
    "resolving": {"resolved", "resolution_failed"},
    "resolved": {"in_review"},
    "in_review": {"approved"},
    "approved": {"report_generated"},
    "report_generated": set(),
    "resolution_failed": {"resolving"},  # retryable per D-24
    "expired": {"draft"},               # revivable per D-62
}

# Draft sessions expire after this many days unless renewed by activity (D-62).
_DRAFT_EXPIRY_DAYS: int = 30


# ---------------------------------------------------------------------------
# Helper types
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class SessionListFilters:
    """Filter parameters for list_sessions() (D-26)."""

    status: str | None = None
    owner_id: str | None = None
    business_unit: str | None = None
    tag: str | None = None       # matches if tag present in tags_json array
    search: str | None = None    # ILIKE on project_name
    is_template: bool | None = None  # Phase 145: filter by template flag (D-12)


T = TypeVar("T")


@dataclass(slots=True)
class PaginatedResponse(Generic[T]):
    """Generic paginated wrapper returned by list functions."""

    items: list[T] = field(default_factory=list)
    total: int = 0
    page: int = 1
    page_size: int = 20


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _draft_expires_at() -> datetime:
    return _utc_now() + timedelta(days=_DRAFT_EXPIRY_DAYS)


def _log_activity(
    db: object,
    *,
    session_id: str,
    event_type: str,
    actor_name: str | None,
    actor_email: str | None,
    detail: dict,
) -> None:
    """Append an immutable activity record for a session (D-65)."""
    try:
        detail_json = json.dumps(detail, sort_keys=True, default=str)
    except TypeError:
        detail_json = "{}"
    db.add(
        SbdNfrActivityRecord(
            id=str(uuid4()),
            session_id=session_id,
            event_type=event_type,
            actor_name=actor_name,
            actor_email=actor_email,
            detail_json=detail_json,
            created_at=_utc_now(),
        )
    )


def _session_to_summary(session: SbdNfrSessionRecord) -> SessionSummaryResponse:
    try:
        tags: list[str] = json.loads(session.tags_json) if session.tags_json else []
    except (json.JSONDecodeError, TypeError):
        tags = []
    return SessionSummaryResponse(
        id=session.id,
        status=session.status,
        project_name=session.project_name,
        description=session.description,
        business_unit=session.business_unit,
        requestor_name=session.requestor_name,
        requestor_email=session.requestor_email,
        target_date=session.target_date,
        is_template=session.is_template,
        template_name=session.template_name,
        tags=tags,
        assigned_architect_id=session.assigned_architect_id,
        architect_notes=session.architect_notes,
        created_at=session.created_at,
        updated_at=session.updated_at,
    )


async def _build_session_detail(
    db: object,
    session: SbdNfrSessionRecord,
) -> SessionDetailResponse:
    """Build the full state snapshot (D-32) for a session.

    Loads questions pinned to session.schema_version_at_start (Pitfall 1 / D-10).
    Computes section progress using skip-logic-aware helpers.
    Finds next unanswered required visible question.
    """
    schema_version = session.schema_version_at_start

    # --- Load all answers for this session ---
    answer_records = list((await db.exec(
        select(SbdNfrAnswerRecord).where(SbdNfrAnswerRecord.session_id == session.id)
    )).all())
    answers_map: dict[str, str] = {a.question_id: a.answer_value for a in answer_records}

    # --- Load sections for pinned schema version ---
    sections = list((await db.exec(
        select(SbdNfrSectionRecord)
        .where(
            SbdNfrSectionRecord.schema_version == schema_version,
            SbdNfrSectionRecord.is_active == True,
        )
        .order_by(SbdNfrSectionRecord.display_order)
    )).all())
    section_ids = [s.id for s in sections]

    # --- Load subgroups ---
    all_subgroups: list[SbdNfrSubgroupRecord] = []
    subgroups_by_section: dict[str, list[SbdNfrSubgroupRecord]] = {}
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

    # --- Load questions ---
    subgroup_ids = [sg.id for sg in all_subgroups]
    all_question_records: list[SbdNfrQuestionRecord] = []
    questions_by_subgroup: dict[str, list[SbdNfrQuestionRecord]] = {}
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

    # --- Build skip-logic DTOs ---
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

    # --- Compute per-section progress ---
    section_progress: list[SectionProgressResponse] = []
    for sec in sections:
        sec_subgroups = subgroups_by_section.get(sec.id, [])
        sec_questions: list[QuestionSkipInfo] = []
        for sg in sec_subgroups:
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
        section_progress.append(
            SectionProgressResponse(
                section_key=sec.section_key,
                visible_count=prog.visible_count,
                answered_count=prog.answered_count,
                total_count=prog.total_count,
            )
        )

    # --- Find next unanswered required visible question (ordered by display_order) ---
    next_unanswered: str | None = None
    for q in all_question_records:
        if q.is_required and q.id in visible_ids and q.id not in answers_map:
            next_unanswered = q.id
            break

    # --- Build answer responses ---
    answer_responses = [
        AnswerResponse(
            question_id=a.question_id,
            answer_value=a.answer_value,
            note_text=a.note_text,
            answered_by_name=a.answered_by_name,
            answered_by_email=a.answered_by_email,
            updated_at=a.updated_at,
        )
        for a in answer_records
    ]

    return SessionDetailResponse(
        session=_session_to_summary(session),
        schema_version=schema_version,
        share_token=session.share_token,
        answers=answer_responses,
        section_progress=section_progress,
        next_unanswered_question_id=next_unanswered,
    )


async def _update_session_status(
    db: object,
    session_id: str,
    new_status: str,
) -> None:
    """Validate and apply a status transition per the D-20 state machine (private helper).

    Accepts a db session so callers can include the transition in their transaction.

    Args:
        db: Async database session (caller owns the transaction).
        session_id: Primary key of the session.
        new_status: Target status string.

    Raises:
        ValueError: If the new_status is not a valid target from the current status.
        HTTPException(404): Session not found.
    """
    from fastapi import HTTPException
    from sqlalchemy import update as sa_update

    session = (await db.exec(
        select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
    )).first()
    if session is None:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")

    current_status = session.status
    valid_targets = _VALID_TRANSITIONS.get(current_status, set())
    if new_status not in valid_targets:
        raise ValueError(
            f"Invalid status transition from '{current_status}' to '{new_status}'. "
            f"Valid targets: {sorted(valid_targets) or 'none'}"
        )

    await db.exec(
        sa_update(SbdNfrSessionRecord)
        .where(SbdNfrSessionRecord.id == session_id)
        .values(status=new_status, updated_at=_utc_now())
    )


# ---------------------------------------------------------------------------
# Public service functions
# ---------------------------------------------------------------------------


async def create_session(
    data: SessionCreateRequest,
    owner_id: str,
) -> SessionDetailResponse:
    """Create a new NFR assessment session in 'draft' status (D-05, D-62).

    Pins schema_version_at_start to the current schema version so the session
    always renders the questions it was created with (Pitfall 1 / D-10).
    Generates a uuid4 share_token (T-134-08).
    Sets expires_at to now + DRAFT_EXPIRY_DAYS (D-62).

    Args:
        data: Validated session create payload.
        owner_id: ApiKeyRecord.id of the creating user.

    Returns:
        Full SessionDetailResponse for the new session.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        schema_version = await _get_current_schema_version(db)
        now = _utc_now()
        try:
            tags_json = json.dumps(data.tags, sort_keys=True)
        except TypeError:
            tags_json = "[]"

        session = SbdNfrSessionRecord(
            id=str(uuid4()),
            schema_version_at_start=schema_version,
            owner_id=owner_id,
            status="draft",
            project_name=data.project_name,
            description=data.description,
            business_unit=data.business_unit,
            requestor_name=data.requestor_name,
            requestor_email=data.requestor_email,
            target_date=data.target_date,
            share_token=str(uuid4()),
            is_template=False,
            is_deleted=False,
            tags_json=tags_json,
            expires_at=_draft_expires_at(),
            created_at=now,
            updated_at=now,
        )
        db.add(session)
        _log_activity(
            db,
            session_id=session.id,
            event_type="session_created",
            actor_name=data.requestor_name,
            actor_email=data.requestor_email,
            detail={"project_name": data.project_name, "schema_version": schema_version},
        )
        await db.commit()

        return await _build_session_detail(db, session)


async def get_session_detail(
    session_id: str,
) -> SessionDetailResponse:
    """Return the full state snapshot for a session (D-32).

    Args:
        session_id: Primary key of the session.

    Returns:
        SessionDetailResponse with all answers and section progress.

    Raises:
        HTTPException(404): If the session does not exist or is soft-deleted.
    """
    from fastapi import HTTPException

    async with UnitOfWork() as _uow:
        db = _uow.session
        session = (await db.exec(
            select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
        )).first()
        if session is None or session.is_deleted:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")

        return await _build_session_detail(db, session)


async def list_sessions(
    filters: SessionListFilters,
    *,
    page: int = 1,
    page_size: int = 20,
    include_deleted: bool = False,
) -> PaginatedResponse[SessionSummaryResponse]:
    """Paginated session listing with filtering (D-26).

    Args:
        filters: Optional filter parameters.
        page: 1-based page number.
        page_size: Records per page.
        include_deleted: If True, include soft-deleted sessions (admin only).

    Returns:
        PaginatedResponse[SessionSummaryResponse].
    """
    from sqlalchemy import func

    async with UnitOfWork() as _uow:
        db = _uow.session
        stmt = select(SbdNfrSessionRecord)

        if not include_deleted:
            stmt = stmt.where(SbdNfrSessionRecord.is_deleted == False)

        if filters.status:
            stmt = stmt.where(SbdNfrSessionRecord.status == filters.status)
        if filters.owner_id:
            stmt = stmt.where(SbdNfrSessionRecord.owner_id == filters.owner_id)
        if filters.business_unit:
            stmt = stmt.where(SbdNfrSessionRecord.business_unit == filters.business_unit)
        if filters.tag:
            # JSON contains check: tags_json stores a JSON array of strings.
            stmt = stmt.where(SbdNfrSessionRecord.tags_json.contains(filters.tag))  # type: ignore[union-attr]
        if filters.search:
            stmt = stmt.where(
                SbdNfrSessionRecord.project_name.ilike(f"%{filters.search}%")  # type: ignore[union-attr]
            )
        if filters.is_template is not None:
            stmt = stmt.where(SbdNfrSessionRecord.is_template == filters.is_template)

        # Count total for pagination
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = (await db.exec(count_stmt)).one()

        # Fetch page
        offset = (page - 1) * page_size
        records = list((await db.exec(
            stmt.order_by(SbdNfrSessionRecord.updated_at.desc())  # type: ignore[union-attr]
            .offset(offset)
            .limit(page_size)
        )).all())

        return PaginatedResponse(
            items=[_session_to_summary(r) for r in records],
            total=total,
            page=page,
            page_size=page_size,
        )


async def clone_session(
    session_id: str,
    owner_id: str,
) -> SessionDetailResponse:
    """Clone a session, copying all answers to a new session (D-33).

    The clone is created with status='draft', a new share_token, and
    cloned_from set to the original session_id (D-55).
    Activity is logged on both the original and cloned sessions.

    Args:
        session_id: Primary key of the session to clone.
        owner_id: Owner id for the new session.

    Returns:
        SessionDetailResponse for the new cloned session.

    Raises:
        HTTPException(404): If the source session does not exist.
    """
    from fastapi import HTTPException

    async with UnitOfWork() as _uow:
        db = _uow.session
        # Load source session
        source = (await db.exec(
            select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
        )).first()
        if source is None or source.is_deleted:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")

        # Load source answers
        source_answers = list((await db.exec(
            select(SbdNfrAnswerRecord).where(SbdNfrAnswerRecord.session_id == session_id)
        )).all())

        now = _utc_now()
        new_id = str(uuid4())

        cloned_session = SbdNfrSessionRecord(
            id=new_id,
            schema_version_at_start=source.schema_version_at_start,
            owner_id=owner_id,
            status="draft",
            project_name=source.project_name,
            description=source.description,
            business_unit=source.business_unit,
            requestor_name=source.requestor_name,
            requestor_email=source.requestor_email,
            target_date=source.target_date,
            share_token=str(uuid4()),
            cloned_from=session_id,
            is_template=False,
            tags_json=source.tags_json,
            expires_at=_draft_expires_at(),
            created_at=now,
            updated_at=now,
        )
        db.add(cloned_session)

        # Copy all answers
        for ans in source_answers:
            db.add(
                SbdNfrAnswerRecord(
                    id=str(uuid4()),
                    session_id=new_id,
                    question_id=ans.question_id,
                    answer_value=ans.answer_value,
                    note_text=ans.note_text,
                    answered_by_name=ans.answered_by_name,
                    answered_by_email=ans.answered_by_email,
                    schema_version=ans.schema_version,
                    created_at=now,
                    updated_at=now,
                )
            )

        _log_activity(
            db,
            session_id=session_id,
            event_type="session_cloned",
            actor_name=None,
            actor_email=None,
            detail={"cloned_to": new_id},
        )
        _log_activity(
            db,
            session_id=new_id,
            event_type="session_created_from_clone",
            actor_name=None,
            actor_email=None,
            detail={"cloned_from": session_id, "answers_copied": len(source_answers)},
        )
        await db.commit()

        return await _build_session_detail(db, cloned_session)


async def complete_session(
    session_id: str,
    actor_name: str | None = None,
    actor_email: str | None = None,
    task_queue: AsyncTaskQueue | None = None,  # Phase 135: auto-trigger resolution (D-01)
) -> SessionDetailResponse:
    """Validate and transition a session to 'completed' status (D-34).

    Validates that all visible required questions are answered.
    Raises HTTPException(400) with the list of missing question IDs if not.
    Transitions: in_progress -> completed -> resolving (when task_queue provided).

    Args:
        session_id: Primary key of the session.
        actor_name: Name of the actor performing completion (for audit log).
        actor_email: Email of the actor performing completion (for audit log).
        task_queue: Optional TaskQueue for auto-triggering resolution as a
            background task.  When provided, transitions the session to
            "resolving" and submits run_resolution().  Failure is non-blocking
            — the complete_session call succeeds even if auto-trigger fails.

    Returns:
        Updated SessionDetailResponse.

    Raises:
        HTTPException(400): Visible required questions are unanswered.
        HTTPException(409): Invalid status transition.
        HTTPException(404): Session not found.
    """
    from fastapi import HTTPException

    from aila.modules.sbd_nfr.services.answer_service import validate_completion

    async with UnitOfWork() as _uow:
        db = _uow.session
        session = (await db.exec(
            select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
        )).first()
        if session is None or session.is_deleted:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")

        missing_ids = await validate_completion(db, session_id)
        if missing_ids:
            raise HTTPException(
                status_code=400,
                detail={
                    "message": "Cannot complete: unanswered required questions",
                    "missing_question_ids": missing_ids,
                },
            )

        try:
            await _update_session_status(db, session_id, "completed")
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        # Reload session after status update
        updated = (await db.exec(
            select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
        )).first()
        if updated is None:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found after update")

        # Phase 154 (SCORE-01, SCORE-02): Compute maturity scores and risk tier.
        await _compute_and_store_scores(db, updated)

        _log_activity(
            db,
            session_id=session_id,
            event_type="session_completed",
            actor_name=actor_name,
            actor_email=actor_email,
            detail={},
        )
        await db.commit()

        # Phase 135 (D-01): Auto-trigger resolution as background task.
        # Non-blocking — resolution failure never fails the complete_session call.
        if task_queue is not None:
            try:
                await _trigger_resolution(db, session_id, updated.owner_id, task_queue)
            except (AILAError, ValueError, sqlalchemy.exc.SQLAlchemyError):
                _log.exception(
                    "Auto-trigger resolution failed for session %s — session is still completed",
                    session_id,
                )

        return await _build_session_detail(db, updated)


async def _compute_and_store_scores(
    db: object,
    session: SbdNfrSessionRecord,
) -> None:
    """Compute maturity section scores and risk tier, write to session record.

    Called from complete_session() after status transitions to "completed".
    Fetches answers and questions for the session's schema version, builds
    QuestionScoreInfo DTOs (with section_key resolved via subgroup → section),
    computes scores using pure functions from scoring_service, and writes
    risk_tier and posture_index back to the session record.

    The DB write is included in the caller's commit (no separate commit here).

    Phase 154: SCORE-01, SCORE-02.
    """
    schema_version = session.schema_version_at_start

    # --- Fetch all answers for this session ---
    answer_records = list((await db.exec(
        select(SbdNfrAnswerRecord).where(SbdNfrAnswerRecord.session_id == session.id)
    )).all())
    answers_map: dict[str, str] = {a.question_id: a.answer_value for a in answer_records}

    # --- Fetch sections to build question_id → section_key mapping ---
    sections = list((await db.exec(
        select(SbdNfrSectionRecord).where(
            SbdNfrSectionRecord.schema_version == schema_version,
            SbdNfrSectionRecord.is_active == True,
        )
    )).all())
    section_key_by_id: dict[str, str] = {s.id: s.section_key for s in sections}
    section_ids = list(section_key_by_id.keys())

    if not section_ids:
        # No schema — store conservative defaults
        session.risk_tier = "MEDIUM"
        session.posture_index = 0.0
        db.add(session)
        return

    # --- Fetch subgroups to resolve subgroup_id → section_key ---
    subgroups = list((await db.exec(
        select(SbdNfrSubgroupRecord).where(
            SbdNfrSubgroupRecord.schema_version == schema_version,
            SbdNfrSubgroupRecord.is_active == True,
            SbdNfrSubgroupRecord.section_id.in_(section_ids),  # type: ignore[union-attr]
        )
    )).all())
    section_key_by_subgroup_id: dict[str, str] = {
        sg.id: section_key_by_id[sg.section_id]
        for sg in subgroups
        if sg.section_id in section_key_by_id
    }
    subgroup_ids = list(section_key_by_subgroup_id.keys())

    # --- Fetch questions and build QuestionScoreInfo DTOs ---
    all_score_infos: list[QuestionScoreInfo] = []
    all_skip_infos_for_scoring: list[QuestionSkipInfo] = []
    if subgroup_ids:
        question_records = list((await db.exec(
            select(SbdNfrQuestionRecord).where(
                SbdNfrQuestionRecord.schema_version == schema_version,
                SbdNfrQuestionRecord.is_active == True,
                SbdNfrQuestionRecord.subgroup_id.in_(subgroup_ids),  # type: ignore[union-attr]
            )
        )).all())
        for q in question_records:
            sec_key = section_key_by_subgroup_id.get(q.subgroup_id, "unknown")
            answer_type = q.answer_type
            if answer_type == "single_choice":
                answer_type = "scope"
            all_score_infos.append(
                QuestionScoreInfo(
                    id=q.id,
                    answer_type=answer_type,
                    section_key=sec_key,
                )
            )
            all_skip_infos_for_scoring.append(
                QuestionSkipInfo(
                    id=q.id,
                    is_active=q.is_active,
                    is_required=q.is_required,
                    depends_on_question_id=q.depends_on_question_id,
                    expected_when=q.expected_when,
                    condition_expr_json=q.condition_expr_json,
                )
            )

    # --- Compute visible question IDs using skip logic ---
    visible_ids = compute_visible_question_ids(all_skip_infos_for_scoring, answers_map)

    # --- Compute section scores and posture index ---
    section_scores = compute_section_scores(all_score_infos, answers_map, visible_ids)
    posture_index = compute_posture_index(section_scores)

    # --- Derive risk tier from SCOPE-* answers only ---
    scope_answers = {qid: val for qid, val in answers_map.items() if qid.startswith("SCOPE-")}
    risk_tier = derive_risk_tier(scope_answers)

    # --- Write results back to session record ---
    session.risk_tier = risk_tier
    session.posture_index = posture_index
    db.add(session)

    # --- Build pre-triage context and write to all linked systems (TRIAGE-01, TRIAGE-02) ---
    triage_ctx = build_triage_context(scope_answers, risk_tier)
    triage_json = json.dumps(triage_ctx.to_dict())

    system_links = (await db.exec(
        select(SbdNfrSessionSystemRecord).where(
            SbdNfrSessionSystemRecord.session_id == session.id
        )
    )).all()
    for link in system_links:
        link.pre_triage_context_json = triage_json
        link.updated_at = _utc_now()
        db.add(link)


async def _trigger_resolution(
    db: object,
    session_id: str,
    owner_id: str,
    task_queue: AsyncTaskQueue,
) -> None:
    """Fire resolution as a background task (D-01).

    Transitions the session to "resolving" and submits run_resolution() to the
    platform task queue.  Called from complete_session() when a task_queue is
    provided.

    Args:
        db: Async database session (same session as complete_session caller).
        session_id: Primary key of the session to resolve.
        owner_id: Session owner_id, used as user_id on the submitted task.
        task_queue: Platform AsyncTaskQueue instance bound to the sbd_nfr module.
    """
    from aila.modules.sbd_nfr.services import resolution_service

    await _update_session_status(db, session_id, "resolving")
    await db.commit()  # Commit status change before submitting background task

    await task_queue.submit(
        track="sbd_nfr",
        fn=resolution_service.run_resolution,
        kwargs={"session_id": session_id},
        user_id=owner_id,
    )


async def soft_delete_session(
    session_id: str,
    actor_name: str | None = None,
    actor_email: str | None = None,
) -> None:
    """Soft-delete a session by setting is_deleted=True (D-35a, owner action).

    Args:
        session_id: Primary key of the session.

    Raises:
        HTTPException(404): Session not found.
    """
    from fastapi import HTTPException
    from sqlalchemy import update as sa_update

    async with UnitOfWork() as _uow:
        db = _uow.session
        if (await db.exec(
            select(SbdNfrSessionRecord.id).where(SbdNfrSessionRecord.id == session_id)
        )).first() is None:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")

        await db.exec(
            sa_update(SbdNfrSessionRecord)
            .where(SbdNfrSessionRecord.id == session_id)
            .values(is_deleted=True, updated_at=_utc_now())
        )
        _log_activity(
            db,
            session_id=session_id,
            event_type="session_soft_deleted",
            actor_name=actor_name,
            actor_email=actor_email,
            detail={},
        )
        await db.commit()


async def hard_delete_session(
    session_id: str,
) -> None:
    """Hard-delete a session and all related records (D-35a, admin only action).

    Permanently removes: answers, activity records, and the session record.

    Args:
        session_id: Primary key of the session.

    Raises:
        HTTPException(404): Session not found.
    """
    from fastapi import HTTPException
    from sqlalchemy import delete as sa_delete

    async with UnitOfWork() as _uow:
        db = _uow.session
        if (await db.exec(
            select(SbdNfrSessionRecord.id).where(SbdNfrSessionRecord.id == session_id)
        )).first() is None:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")

        await db.exec(
            sa_delete(SbdNfrAnswerRecord).where(SbdNfrAnswerRecord.session_id == session_id)
        )
        await db.exec(
            sa_delete(SbdNfrActivityRecord).where(SbdNfrActivityRecord.session_id == session_id)
        )
        await db.exec(
            sa_delete(SbdNfrSessionSystemRecord).where(SbdNfrSessionSystemRecord.session_id == session_id)
        )
        await db.exec(
            sa_delete(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
        )
        await db.commit()


async def export_session(
    session_id: str,
) -> dict:
    """Export a full session snapshot as a plain dict (D-27).

    Args:
        session_id: Primary key of the session.

    Returns:
        dict with session metadata, all answers, and section progress.

    Raises:
        HTTPException(404): Session not found.
    """
    detail = await get_session_detail(session_id)
    return detail.model_dump(mode="json")


async def assign_architect(
    session_id: str,
    architect_id: str,
    actor_name: str | None = None,
    actor_email: str | None = None,
) -> SessionSummaryResponse:
    """Assign an architect to a session (D-53, D-54).

    Args:
        session_id: Primary key of the session.
        architect_id: ApiKeyRecord.id of the architect to assign.

    Returns:
        Updated SessionSummaryResponse.

    Raises:
        HTTPException(404): Session not found.
    """
    from fastapi import HTTPException
    from sqlalchemy import update as sa_update

    async with UnitOfWork() as _uow:
        db = _uow.session
        session = (await db.exec(
            select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
        )).first()
        if session is None or session.is_deleted:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")

        await db.exec(
            sa_update(SbdNfrSessionRecord)
            .where(SbdNfrSessionRecord.id == session_id)
            .values(assigned_architect_id=architect_id, updated_at=_utc_now())
        )

        _log_activity(
            db,
            session_id=session_id,
            event_type="architect_assigned",
            actor_name=actor_name,
            actor_email=actor_email,
            detail={"architect_id": architect_id},
        )
        await db.commit()

        # Reload after update
        updated = (await db.exec(
            select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
        )).first()
        if updated is None:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found after update")

        return _session_to_summary(updated)


async def update_session_status(
    session_id: str,
    new_status: str,
) -> None:
    """Validate and apply a status transition per the D-20 state machine.

    Args:
        session_id: Primary key of the session.
        new_status: Target status string.

    Raises:
        ValueError: If the new_status is not a valid target from the current status.
        HTTPException(404): Session not found.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        await _update_session_status(db, session_id, new_status)
        await db.commit()


async def submit_for_review(
    session_id: str,
    notes: str | None = None,
    actor_name: str | None = None,
    actor_email: str | None = None,
) -> SessionSummaryResponse:
    """Transition a resolved session to in_review (Phase 145 D-01, D-02).

    Args:
        session_id: Primary key of the session.
        notes: Optional free-text notes from the submitter, captured in the
            activity log so the reviewing architect can see the submission context.
        actor_name: Name of the actor submitting (for audit log).
        actor_email: Email of the actor submitting (for audit log).

    Returns:
        Updated SessionSummaryResponse.

    Raises:
        HTTPException(409): Invalid status transition.
        HTTPException(404): Session not found.
    """
    from fastapi import HTTPException

    async with UnitOfWork() as _uow:
        db = _uow.session
        try:
            await _update_session_status(db, session_id, "in_review")
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        activity_detail: dict[str, object] = {"has_notes": notes is not None}
        if notes is not None:
            activity_detail["notes"] = notes
        _log_activity(
            db,
            session_id=session_id,
            event_type="session_submitted_for_review",
            actor_name=actor_name,
            actor_email=actor_email,
            detail=activity_detail,
        )
        await db.commit()

        updated = (await db.exec(
            select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
        )).first()
        if updated is None:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found after update")
        return _session_to_summary(updated)


async def approve_session(
    session_id: str,
    notes: str | None = None,
    actor_name: str | None = None,
    actor_email: str | None = None,
) -> SessionSummaryResponse:
    """Approve a session under architect review (Phase 145 D-01, D-02).

    Transitions the session from in_review to approved and persists
    optional architect notes.

    Args:
        session_id: Primary key of the session.
        notes: Optional architect notes to persist on the session.
        actor_name: Name of the approving architect (for audit log).
        actor_email: Email of the approving architect (for audit log).

    Returns:
        Updated SessionSummaryResponse.

    Raises:
        HTTPException(409): Invalid status transition.
        HTTPException(404): Session not found.
    """
    from fastapi import HTTPException
    from sqlalchemy import update as sa_update

    async with UnitOfWork() as _uow:
        db = _uow.session
        try:
            await _update_session_status(db, session_id, "approved")
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        if notes is not None:
            await db.exec(
                sa_update(SbdNfrSessionRecord)
                .where(SbdNfrSessionRecord.id == session_id)
                .values(architect_notes=notes, updated_at=_utc_now())
            )

        _log_activity(
            db,
            session_id=session_id,
            event_type="session_approved",
            actor_name=actor_name,
            actor_email=actor_email,
            detail={"has_notes": notes is not None},
        )
        await db.commit()

        updated = (await db.exec(
            select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
        )).first()
        if updated is None:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found after update")
        return _session_to_summary(updated)


async def save_architect_notes(
    session_id: str,
    notes: str,
    actor_name: str | None = None,
    actor_email: str | None = None,
) -> SessionSummaryResponse:
    """Persist architect notes on a session without changing status (Phase 145 D-13).

    Args:
        session_id: Primary key of the session.
        notes: Notes text to store.
        actor_name: Name of the architect (for audit log).
        actor_email: Email of the architect (for audit log).

    Returns:
        Updated SessionSummaryResponse.

    Raises:
        HTTPException(404): Session not found or soft-deleted.
    """
    from fastapi import HTTPException
    from sqlalchemy import update as sa_update

    async with UnitOfWork() as _uow:
        db = _uow.session
        session = (await db.exec(
            select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
        )).first()
        if session is None or session.is_deleted:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")

        await db.exec(
            sa_update(SbdNfrSessionRecord)
            .where(SbdNfrSessionRecord.id == session_id)
            .values(architect_notes=notes, updated_at=_utc_now())
        )

        _log_activity(
            db,
            session_id=session_id,
            event_type="architect_notes_saved",
            actor_name=actor_name,
            actor_email=actor_email,
            detail={"notes_length": len(notes)},
        )
        await db.commit()

        updated = (await db.exec(
            select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
        )).first()
        if updated is None:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found after update")
        return _session_to_summary(updated)
