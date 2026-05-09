"""Core LLM resolution orchestration for the SbD NFR module.

Design references: D-01 through D-12.

Classifies 25 SbD sub-task components based on completed NFR questionnaire
answers.  The classification is LLM-driven — no deterministic keyword fallback
per the v2.2 architecture decision.

Entry point:
    run_resolution(session_id)  — async function submitted to TaskQueue.

Threat mitigations:
  T-135-01: Resolution only runs for sessions in "resolving" status — verified
            at the start of run_resolution().
  T-135-02: Pydantic model_validate_json() enforces typed schema; Literal type
            on ComponentClassification.classification prevents arbitrary strings.
  T-135-04: 120-second hard timeout (D-04); AilaLLMClient pipeline enforces
            budget limits via CostTracker.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime

from sqlalchemy import delete
from sqlmodel import select

from aila.api.metrics import SILENT_FAILURE_TOTAL
from aila.modules.sbd_nfr.contracts.resolution import (
    ComponentClassification,
    ResolutionResponse,
)
from aila.modules.sbd_nfr.db_models import (
    SbdNfrAnswerRecord,
    SbdNfrQuestionRecord,
    SbdNfrQuestionSubtaskMapRecord,
    SbdNfrResolutionResultRecord,
    SbdNfrSessionRecord,
    SbdNfrSubtaskComponentRecord,
)
from aila.modules.sbd_nfr.services.activity_service import (
    EVENT_RESOLUTION_COMPLETED,
    EVENT_RESOLUTION_FAILED,
    EVENT_RESOLUTION_STARTED,
    log_activity,
)
from aila.modules.sbd_nfr.services.event_stream import SessionEventStream
from aila.modules.sbd_nfr.services.session_service import _update_session_status
from aila.platform.services.factory import ServiceFactory
from aila.platform.uow import UnitOfWork

__all__ = ["run_resolution", "get_resolution_results", "CONFIDENCE_THRESHOLD"]

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants (D-03, D-04, D-06)
# ---------------------------------------------------------------------------

CONFIDENCE_THRESHOLD: float = 0.7
LLM_TIMEOUT_SECONDS: int = 120
MAX_RETRIES: int = 1
RESOLUTION_TASK_TYPE: str = "resolution"


# ---------------------------------------------------------------------------
# Public async entry point (Pitfall 5 — sync wrapper for TaskQueue)
# ---------------------------------------------------------------------------


async def run_resolution(session_id: str) -> None:
    """Async resolution pipeline — submitted to TaskQueue as an async ARQ job.

    ARQ workers call this coroutine natively in the event loop — no sync
    wrapper or asyncio.run() bridge needed (Part 8 threading rule).

    Steps:
    1. Load session (verify status == "resolving") (T-135-01)
    2. Load answers, subtask definitions, mapping records, question labels
    3. Build LLM prompts (system + user)
    4. Call chat_structured() with retry and timeout (D-03, D-04)
    5. Apply confidence threshold — reclassify below-threshold as uncertain (D-06)
    6. Persist results in single transaction (delete + insert 25 rows) (D-10, D-12)
    7. Cache full LLM response JSON on session record (D-10)
    8. Transition session to "resolved" or "resolution_failed"
    9. Log activity event
    10. Emit SSE events (best-effort)

    Args:
        session_id: The SbdNfrSessionRecord.id to resolve.
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        # --- Step 1: Load and verify session ---
        session = (await db.exec(
            select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
        )).first()
        if session is None:
            _log.error("_run_resolution_async: session %r not found", session_id)
            return
        if session.status != "resolving":
            _log.warning(
                "_run_resolution_async: session %r has status %r, expected 'resolving' — aborting",
                session_id,
                session.status,
            )
            return

        # --- Step 2a: Load all answered questions for this session ---
        answers = list((await db.exec(
            select(SbdNfrAnswerRecord).where(SbdNfrAnswerRecord.session_id == session_id)
        )).all())

        # --- Step 2b: Load all 25 subtask component definitions ---
        subtasks = list((await db.exec(
            select(SbdNfrSubtaskComponentRecord).order_by(SbdNfrSubtaskComponentRecord.display_order)
        )).all())

        # --- Step 2c: Load question-subtask mapping records ---
        map_records = list((await db.exec(select(SbdNfrQuestionSubtaskMapRecord))).all())

        # Build mapping grouped by subtask_key (Pitfall 2 — not flat 751 rows)
        mapping_by_subtask: dict[str, list[str]] = {}
        for record in map_records:
            mapping_by_subtask.setdefault(record.subtask_key, []).append(record.question_id)

        # --- Step 2d: Load question labels for answered question IDs ---
        answered_question_ids = [a.question_id for a in answers]
        questions: list[SbdNfrQuestionRecord] = []
        if answered_question_ids:
            questions = list((await db.exec(
                select(SbdNfrQuestionRecord).where(
                    SbdNfrQuestionRecord.id.in_(answered_question_ids)  # type: ignore[union-attr]
                )
            )).all())

        question_label_map = {q.id: q.label for q in questions}

        # Build answered questions list for prompt
        answered_for_prompt: list[tuple[str, str, str]] = [
            (question_label_map.get(a.question_id, a.question_id), a.question_id, a.answer_value)
            for a in answers
        ]

        # Identify scope answers for executive summary context
        scope_answer_ids = {
            a.question_id for a in answers
            if question_label_map.get(a.question_id, "").lower().startswith("scope")
            or a.question_id.startswith("SCOPE")
        }
        scope_answers = [t for t in answered_for_prompt if t[1] in scope_answer_ids]

        # --- Step 3: Build LLM prompts ---
        system_prompt = _build_system_prompt(subtasks, mapping_by_subtask, session, scope_answers)
        user_message = _build_user_message(answered_for_prompt)

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]

        # --- Step 4: Log resolution started, emit SSE ---
        await log_activity(
            db,
            session_id=session_id,
            event_type=EVENT_RESOLUTION_STARTED,
            detail={"answer_count": len(answers)},
        )
        asyncio.create_task(_emit_session_event(session_id, "resolution_started", {"answer_count": len(answers)}))

        # --- Step 5: Call LLM with retry and timeout ---
        llm_client = ServiceFactory().llm_client
        resolution_data: ResolutionResponse | None = None
        last_error: str = ""

        for attempt in range(MAX_RETRIES + 1):
            try:
                llm_response = await asyncio.wait_for(
                    llm_client.chat_structured(
                        task_type=RESOLUTION_TASK_TYPE,
                        messages=messages,
                        model_class=ResolutionResponse,
                    ),
                    timeout=LLM_TIMEOUT_SECONDS,
                )
                if llm_response.disabled:
                    last_error = "LLM disabled by operator"
                    _log.warning(
                        "_run_resolution_async: LLM disabled for session %r", session_id
                    )
                    break

                # Per Pitfall 3: parse via model_validate_json, not direct dict access
                resolution_data = ResolutionResponse.model_validate_json(llm_response.content)
                break  # success
            except TimeoutError:
                last_error = f"LLM call timed out after {LLM_TIMEOUT_SECONDS}s"
                _log.error(
                    "_run_resolution_async: timeout (attempt %d/%d) for session %r",
                    attempt + 1,
                    MAX_RETRIES + 1,
                    session_id,
                )
                if attempt < MAX_RETRIES:
                    _log.info("_run_resolution_async: retrying (attempt %d)", attempt + 2)
            except (RuntimeError, ValueError, OSError) as exc:
                last_error = str(exc)
                _log.error(
                    "_run_resolution_async: LLM error (attempt %d/%d) for session %r: %s",
                    attempt + 1,
                    MAX_RETRIES + 1,
                    session_id,
                    exc,
                )
                if attempt < MAX_RETRIES:
                    _log.info("_run_resolution_async: retrying (attempt %d)", attempt + 2)

        if resolution_data is None:
            # --- Permanent failure path ---
            _log.error(
                "_run_resolution_async: resolution failed permanently for session %r: %s",
                session_id,
                last_error,
            )
            from sqlalchemy import update as sa_update

            await db.exec(
                sa_update(SbdNfrSessionRecord)
                .where(SbdNfrSessionRecord.id == session_id)
                .values(resolution_error=last_error[:2000])
            )
            await _update_session_status(db, session_id, "resolution_failed")
            await log_activity(
                db,
                session_id=session_id,
                event_type=EVENT_RESOLUTION_FAILED,
                detail={"error": last_error[:500]},
            )
            await db.commit()
            asyncio.create_task(_emit_session_event(session_id, "resolution_failed", {"error": last_error[:500]}))
            return

        # --- Step 6: Apply confidence threshold (RESOLVE-03) ---
        classified_components = _apply_confidence_threshold(
            resolution_data.components, CONFIDENCE_THRESHOLD
        )

        # --- Step 7: Persist results (D-10, D-12 replace-in-place) ---
        resolved_at = datetime.now(UTC)

        # Delete all existing rows for this session in one statement
        await db.exec(
            delete(SbdNfrResolutionResultRecord).where(
                SbdNfrResolutionResultRecord.session_id == session_id
            )
        )

        # Insert one row per classified component
        for component in classified_components:
            cited_json = json.dumps(component.cited_question_ids or [])
            db.add(
                SbdNfrResolutionResultRecord(
                    session_id=session_id,
                    subtask_key=component.subtask_key,
                    classification=component.classification,
                    confidence=component.confidence,
                    reasoning=component.reasoning or "",
                    cited_question_ids_json=cited_json,
                    resolved_at=resolved_at,
                )
            )

        # Cache full LLM JSON on session record for audit/debug (D-10)
        raw_json = resolution_data.model_dump_json()
        from sqlalchemy import update as sa_update

        await db.exec(
            sa_update(SbdNfrSessionRecord)
            .where(SbdNfrSessionRecord.id == session_id)
            .values(resolution_json=raw_json, resolution_error=None)
        )

        # --- Step 8: Transition to "resolved" ---
        await _update_session_status(db, session_id, "resolved")

        # --- Step 9: Log activity ---
        await log_activity(
            db,
            session_id=session_id,
            event_type=EVENT_RESOLUTION_COMPLETED,
            detail={"component_count": len(classified_components)},
        )
        await db.commit()

        # --- Step 10: Emit SSE event (best-effort, fire-and-forget) ---
        asyncio.create_task(_emit_session_event(
            session_id,
            "resolution_completed",
            {"component_count": len(classified_components)},
        ))

        # Plan 146-02 (RT-01): emit platform-wide sbd_complete event + NotificationRecord
        await _emit_platform_sbd_complete(
            owner_id=session.owner_id,
            session_id=session_id,
            component_count=len(classified_components),
        )

        _log.info(
            "_run_resolution_async: resolved session %r with %d components",
            session_id,
            len(classified_components),
        )


# ---------------------------------------------------------------------------
# Public async query function
# ---------------------------------------------------------------------------


async def get_resolution_results(
    session_id: str,
) -> list[SbdNfrResolutionResultRecord]:
    """Load all resolution result rows for a session, ordered by subtask_key.

    Args:
        session_id: The session whose resolution results to load.

    Returns:
        Ordered list of SbdNfrResolutionResultRecord rows (empty if not resolved).
    """
    async with UnitOfWork() as _uow:
        db = _uow.session
        return list((await db.exec(
            select(SbdNfrResolutionResultRecord)
            .where(SbdNfrResolutionResultRecord.session_id == session_id)
            .order_by(SbdNfrResolutionResultRecord.subtask_key)
        )).all())


# ---------------------------------------------------------------------------
# Confidence threshold helper (extracted for testability)
# ---------------------------------------------------------------------------


def _apply_confidence_threshold(
    components: list[ComponentClassification],
    threshold: float,
) -> list[ComponentClassification]:
    """Reclassify components with confidence below threshold as 'uncertain'.

    Per RESOLVE-03: any component whose confidence is below CONFIDENCE_THRESHOLD
    and whose current classification is not already 'uncertain' gets overridden
    to 'uncertain'.

    Returns a new list — does not mutate the input list.
    """
    result: list[ComponentClassification] = []
    for component in components:
        if component.classification != "uncertain" and component.confidence < threshold:
            result.append(
                ComponentClassification(
                    subtask_key=component.subtask_key,
                    classification="uncertain",
                    confidence=component.confidence,
                    reasoning=component.reasoning,
                    cited_question_ids=component.cited_question_ids,
                )
            )
        else:
            result.append(component)
    return result


# ---------------------------------------------------------------------------
# Prompt building helpers
# ---------------------------------------------------------------------------


def _build_system_prompt(
    subtasks: list[SbdNfrSubtaskComponentRecord],
    mapping_by_subtask: dict[str, list[str]],
    session: SbdNfrSessionRecord,
    scope_answers: list[tuple[str, str, str]],
) -> str:
    """Build the system prompt for the resolution LLM call."""
    lines = [
        "You are an expert Security by Design (SbD) architect performing an NFR "
        "(Non-Functional Requirements) assessment.",
        "",
        "Your task is to analyze the requester's answers to the NFR questionnaire "
        "and classify each of the 25 SbD sub-task components as 'triggered', "
        "'not_triggered', or 'uncertain'.",
        "",
        "Classification rules:",
        "  - 'triggered': The component is clearly relevant based on the answers.",
        "  - 'not_triggered': The component is clearly not relevant.",
        "  - 'uncertain': Insufficient evidence or conflicting signals.",
        "",
        "For each component, provide:",
        "  - subtask_key: The component's key (exactly as listed below)",
        "  - classification: One of 'triggered', 'not_triggered', 'uncertain'",
        "  - confidence: A float from 0.0 to 1.0 indicating your certainty",
        "  - reasoning: A concise explanation citing specific answer values",
        "  - cited_question_ids: List of question IDs that drove your classification",
        "",
        "You MUST return a classification for ALL 25 components, even if evidence is absent.",
        "",
        "=== PROJECT CONTEXT ===",
        f"Project: {session.project_name}",
    ]

    if session.description:
        lines.append(f"Description: {session.description}")
    if session.business_unit:
        lines.append(f"Business Unit: {session.business_unit}")

    if scope_answers:
        lines.append("")
        lines.append("Scope answers:")
        for label, qid, value in scope_answers[:10]:
            lines.append(f"  [{qid}] {label}: {value}")

    lines.append("")
    lines.append("=== 25 SBD SUB-TASK COMPONENTS ===")
    for subtask in subtasks:
        lines.append(f"Key: {subtask.key}")
        lines.append(f"Label: {subtask.label}")
        if subtask.description:
            lines.append(f"Description: {subtask.description}")
        mapped_questions = mapping_by_subtask.get(subtask.key, [])
        if mapped_questions:
            lines.append(f"Mapped questions: {', '.join(mapped_questions)}")
        lines.append("")

    return "\n".join(lines)


def _build_user_message(answered_questions: list[tuple[str, str, str]]) -> str:
    """Build the user message containing all answered NFR questions."""
    if not answered_questions:
        return "No answers have been submitted for this session."

    lines = [
        f"The requester has answered {len(answered_questions)} NFR questions.",
        "Analyze these answers to classify the 25 SbD components:",
        "",
    ]
    for label, qid, value in answered_questions:
        lines.append(f"{qid} ({label}): {value}")

    lines.append(
        "\nReturn a classification for ALL 25 components listed in the system prompt."
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Platform-wide SSE emission (best-effort — fails silently)
# ---------------------------------------------------------------------------


async def _emit_platform_sbd_complete(
    owner_id: str,
    session_id: str,
    component_count: int,
) -> None:
    """Emit sbd_complete to the platform event bus and persist a NotificationRecord."""
    try:
        from aila.api.events import emit_platform_event
        from aila.storage.db_models import NotificationRecord

        await emit_platform_event(
            user_id=owner_id,
            event_type="sbd_complete",
            data={
                "session_id": session_id,
                "component_count": component_count,
                "status": "complete",
            },
        )

        # Persist notification — deduplicate by source_entity_id
        from aila.platform.services.factory import ServiceFactory

        svc = ServiceFactory()
        existing = await svc.storage.fetch_one(
            NotificationRecord,
            NotificationRecord.source_entity_id == session_id,
            NotificationRecord.user_id == owner_id,
            NotificationRecord.source_module == "sbd_nfr",
        )

        if existing is None:
            await svc.storage.save(
                NotificationRecord(
                    user_id=owner_id,
                    title="SbD resolution complete",
                    body=(
                        f"Security by Design analysis for session "
                        f"{session_id[:8]} classified {component_count} components."
                    ),
                    category="info",
                    source_module="sbd_nfr",
                    source_entity_id=session_id,
                )
            )

    except Exception:
        SILENT_FAILURE_TOTAL.labels(component="sse_emission").inc()
        _log.warning(
            "_emit_platform_sbd_complete: failed for session %r (user=%s) — non-fatal",
            session_id,
            owner_id,
            exc_info=True,
        )


# ---------------------------------------------------------------------------
# SSE event emission (best-effort — fails silently)
# ---------------------------------------------------------------------------


async def _emit_session_event(
    session_id: str,
    event: str,
    data: dict | None = None,
) -> None:
    stream = SessionEventStream()
    try:
        await stream.emit(session_id, event, **(data or {}))
    except Exception as exc:
        SILENT_FAILURE_TOTAL.labels(component="sse_emission").inc()
        _log.warning(
            "_emit_session_event: failed to emit %r for session %r: %s",
            event,
            session_id,
            exc,
        )
        SILENT_FAILURE_TOTAL.labels(component="sse_emission").inc()
        _log.warning(
            "_emit_session_event: failed to emit %r for session %r: %s",
            event,
            session_id,
            exc,
        )
