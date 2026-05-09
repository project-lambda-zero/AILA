"""LLM-powered smart search service for the SbD NFR module.

Design references: D-44, D-45, D-46, D-47.
Security: T-134-16 (cross-user session leaking prevention).
Threat mitigations:
  T-134-15: User query is placed in the user message only, never in the
            system prompt.  System prompt is a static constant.
  T-134-16: Reader role sees only own sessions; operator/admin see all.
            Filtering is applied BEFORE data is sent to the LLM.
  T-134-19: Candidate session loading is capped at 20; max_results <= 50.

Each public function manages its own database session via UnitOfWork.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from sqlmodel import select

from aila.modules.sbd_nfr.contracts.search import (
    SearchMatchedAnswer,
    SearchResultItem,
    SmartSearchRequest,
    SmartSearchResponse,
    _LLMSearchResult,
)
from aila.modules.sbd_nfr.db_models import (
    SbdNfrAnswerRecord,
    SbdNfrQuestionRecord,
    SbdNfrSessionRecord,
)
from aila.platform.uow import UnitOfWork

if TYPE_CHECKING:
    from aila.platform.llm import AilaLLMClient

__all__ = ["smart_search"]

_log = logging.getLogger(__name__)

# Maximum candidates sent to the LLM (D-44/D-47 cost cap, T-134-19).
_MAX_CANDIDATES = 20

# Static system prompt — user query MUST NOT be concatenated here (T-134-15).
_SYSTEM_PROMPT = (
    "You are a search assistant for an NFR (Non-Functional Requirements) assessment "
    "platform. Each session represents a security and compliance assessment for a "
    "software project. Each session has answers to questions about scope, availability, "
    "identity management, data classification, and other security topics. "
    "Your job is to rank the provided sessions by relevance to the user's natural "
    "language query. For each session you include, provide a concise explanation "
    "citing specific answer values that make it relevant. "
    "Return ONLY sessions that are genuinely relevant. If none are relevant, return "
    "empty lists. Scores must be between 0.0 (not relevant) and 1.0 (perfectly "
    "relevant). Return them in descending score order (most relevant first)."
)


def _build_session_summary(
    session: SbdNfrSessionRecord,
    answers: list[tuple[str, str, str]],  # (question_label, question_id, answer_value)
) -> str:
    """Build a compact text summary of one session for the LLM context."""
    lines = [
        f"SESSION_ID: {session.id}",
        f"PROJECT: {session.project_name}",
        f"STATUS: {session.status}",
        f"BUSINESS_UNIT: {session.business_unit or 'N/A'}",
        f"REQUESTOR: {session.requestor_name}",
        f"ANSWERS ({len(answers)} captured):",
    ]
    # Include up to 30 answers per session to keep prompt size manageable.
    for label, qid, value in answers[:30]:
        lines.append(f"  [{qid}] {label}: {value}")
    return "\n".join(lines)


async def smart_search(
    request: SmartSearchRequest,
    user_id: str,
    user_role: str,
    llm_client: AilaLLMClient,
) -> SmartSearchResponse:
    """LLM-powered semantic search over NFR assessment sessions.

    Security (T-134-16): role-based filtering is applied before any data is
    sent to the LLM.
      - "reader" role: only sessions owned by user_id are candidates.
      - "operator" and "admin" roles: all non-deleted sessions are candidates.

    Args:
        request: Validated search request with query, filters, max_results.
        user_id: ApiKeyRecord.id of the authenticated caller.
        user_role: Role string from the JWT ("admin" | "operator" | "reader").
        llm_client: Injected AilaLLMClient instance from the platform runtime.

    Returns:
        SmartSearchResponse with ranked results and LLM query interpretation.
        On LLM failure: returns SmartSearchResponse with empty results and
        query_interpretation = "Search unavailable".
    """
    async with UnitOfWork() as _uow:
        db = _uow.session

        # --- Step 1: Load candidate sessions (T-134-16 role filter) ---
        stmt = (
            select(SbdNfrSessionRecord)
            .where(SbdNfrSessionRecord.is_deleted == False)
        )

        # Security: restrict reader role to their own sessions only (T-134-16).
        if user_role not in ("operator", "admin"):
            stmt = stmt.where(SbdNfrSessionRecord.owner_id == user_id)

        # Apply typed filters from the request.
        if request.status is not None:
            stmt = stmt.where(SbdNfrSessionRecord.status == request.status)
        if request.business_unit is not None:
            stmt = stmt.where(SbdNfrSessionRecord.business_unit == request.business_unit)
        if request.tag is not None:
            stmt = stmt.where(
                SbdNfrSessionRecord.tags_json.contains(json.dumps(request.tag))  # type: ignore[union-attr]
            )

        # Cap at _MAX_CANDIDATES for LLM cost control (T-134-19).
        stmt = stmt.order_by(SbdNfrSessionRecord.created_at.desc()).limit(_MAX_CANDIDATES)  # type: ignore[union-attr]

        candidates: list[SbdNfrSessionRecord] = list((await db.exec(stmt)).all())
        total_searched = len(candidates)

        if not candidates:
            return SmartSearchResponse(
                query=request.query,
                query_interpretation="No sessions found matching your filters.",
                results=[],
                total_searched=0,
            )

        # --- Step 2: Load answers with question labels for each candidate ---
        candidate_ids = [s.id for s in candidates]

        all_answers = list((await db.exec(
            select(SbdNfrAnswerRecord).where(
                SbdNfrAnswerRecord.session_id.in_(candidate_ids)  # type: ignore[union-attr]
            )
        )).all())

        # Load question labels for all answered question IDs.
        answered_question_ids = {a.question_id for a in all_answers}
        question_labels: dict[str, str] = {}
        if answered_question_ids:
            q_result = (await db.exec(
                select(SbdNfrQuestionRecord.id, SbdNfrQuestionRecord.label).where(
                    SbdNfrQuestionRecord.id.in_(answered_question_ids)  # type: ignore[union-attr]
                )
            )).all()
            for row in q_result:
                question_labels[row[0]] = row[1]

        # Group answers by session_id.
        answers_by_session: dict[str, list[tuple[str, str, str]]] = {}
        for answer in all_answers:
            label = question_labels.get(answer.question_id, answer.question_id)
            answers_by_session.setdefault(answer.session_id, []).append(
                (label, answer.question_id, answer.answer_value)
            )

        # Build a lookup map for quick session retrieval during result assembly.
        session_by_id = {s.id: s for s in candidates}

    # --- Step 3: Build prompts (outside UoW — pure computation) ---
    session_summaries = "\n\n---\n\n".join(
        _build_session_summary(s, answers_by_session.get(s.id, []))
        for s in candidates
    )

    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"Search query: {request.query}\n\n"
                f"Sessions to rank ({len(candidates)} total):\n\n"
                f"{session_summaries}"
            ),
        },
    ]

    # --- Step 4: Call LLM ---
    try:
        llm_response = await llm_client.chat_structured(
            task_type="search",
            messages=messages,
            model_class=_LLMSearchResult,
        )
        if llm_response.disabled:
            _log.warning("smart_search: LLM is disabled, returning empty results")
            return SmartSearchResponse(
                query=request.query,
                query_interpretation="Search unavailable",
                results=[],
                total_searched=total_searched,
            )
        llm_data = _LLMSearchResult.model_validate_json(llm_response.content)
    except (RuntimeError, ValueError, OSError, TimeoutError) as exc:
        _log.error("smart_search: LLM call failed: %s", exc)
        return SmartSearchResponse(
            query=request.query,
            query_interpretation="Search unavailable",
            results=[],
            total_searched=total_searched,
        )

    # --- Step 5: Map LLM results back to SearchResultItem objects ---
    result_items: list[SearchResultItem] = []
    for idx, session_id in enumerate(llm_data.session_ids):
        session = session_by_id.get(session_id)
        if session is None:
            # LLM hallucinated a session_id — skip it.
            _log.warning("smart_search: LLM returned unknown session_id %r", session_id)
            continue

        score = llm_data.scores[idx] if idx < len(llm_data.scores) else 0.0
        reasoning = llm_data.reasonings[idx] if idx < len(llm_data.reasonings) else ""

        # Clamp score to [0.0, 1.0].
        score = max(0.0, min(1.0, float(score)))

        # Build matched answer citations from session's answers.
        session_answers = answers_by_session.get(session_id, [])
        matched: list[SearchMatchedAnswer] = [
            SearchMatchedAnswer(
                question_id=qid,
                question_label=qlabel,
                answer_value=aval,
            )
            for qlabel, qid, aval in session_answers[:5]  # cite up to 5 per result
        ]

        result_items.append(
            SearchResultItem(
                session_id=session.id,
                project_name=session.project_name,
                status=session.status,
                business_unit=session.business_unit,
                requestor_name=session.requestor_name,
                relevance_score=score,
                reasoning=reasoning,
                matching_answers=matched,
                created_at=session.created_at,
            )
        )

    # Sort by relevance descending and cap at max_results.
    result_items.sort(key=lambda r: r.relevance_score, reverse=True)
    result_items = result_items[: request.max_results]

    return SmartSearchResponse(
        query=request.query,
        query_interpretation=llm_data.query_interpretation or request.query,
        results=result_items,
        total_searched=total_searched,
    )
