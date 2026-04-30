"""Pure-function skip logic engine for the SbD NFR questionnaire.

Design references: D-07, D-08, D-57, Pitfall 5.

All three functions are pure — they have no DB access, no side effects, and no
imports from aila.storage.  Callers build the lightweight DTO inputs from DB
records and pass answers as a plain dict.

Skip logic rule (D-07, D-08):
    An item (question or section) is visible when:
    1. It is active (is_active=True), AND
    2a. condition_expr_json is set → evaluate AND/OR multi-condition expression, OR
    2b. Either it has no dependency (depends_on_question_id is None),
        OR answers[depends_on_question_id] == expected_when.

    condition_expr_json takes precedence over depends_on_question_id + expected_when
    when both are set.  Format:
        {"op": "and"|"or", "conditions": [{"question_id": str, "expected": str}, ...]}

Progress denominator rule (Pitfall 5):
    Section completion % denominator = visible REQUIRED questions only.
    Hidden questions never count toward progress, whether answered or not.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

__all__ = [
    "QuestionSkipInfo",
    "SectionSkipInfo",
    "SectionProgressResult",
    "compute_visible_question_ids",
    "compute_visible_section_ids",
    "compute_section_progress",
]


# ---------------------------------------------------------------------------
# Lightweight, immutable DTOs — NOT SQLModel records
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class QuestionSkipInfo:
    """Minimal question data needed to evaluate skip logic and progress."""

    id: str
    is_active: bool
    is_required: bool
    depends_on_question_id: str | None
    expected_when: str | None
    condition_expr_json: str | None = field(default=None)


@dataclass(frozen=True, slots=True)
class SectionSkipInfo:
    """Minimal section data needed to evaluate skip logic."""

    id: str
    is_active: bool
    depends_on_question_id: str | None
    expected_when: str | None
    condition_expr_json: str | None = field(default=None)


@dataclass(frozen=True, slots=True)
class SectionProgressResult:
    """Aggregated progress counters for one section.

    visible_count: required questions visible given current answers.
    answered_count: visible required questions with an answer recorded.
    total_count: all questions in the section (visible and hidden).
    """

    visible_count: int
    answered_count: int
    total_count: int


# ---------------------------------------------------------------------------
# Pure engine functions
# ---------------------------------------------------------------------------


def _evaluate_condition_expr(
    condition_expr_json: str | None,
    answers: dict[str, str],
) -> bool | None:
    """Evaluate a condition_expr_json expression against current answers.

    Returns:
        True  — all/any conditions satisfied (AND/OR semantics).
        False — conditions not satisfied.
        None  — condition_expr_json is None; caller falls back to legacy logic.

    Malformed JSON returns False (fail-safe: hide rather than crash — T-151-04).
    Empty conditions list returns True (no constraints → visible).
    """
    if condition_expr_json is None:
        return None
    try:
        expr = json.loads(condition_expr_json)
    except (json.JSONDecodeError, ValueError):
        return False  # fail-safe: malformed expression hides the item
    op = expr.get("op", "and")
    conditions: list[dict[str, str]] = expr.get("conditions", [])
    if not conditions:
        return True  # no constraints → always visible
    results = [
        answers.get(c["question_id"]) == c["expected"]
        for c in conditions
    ]
    if op == "or":
        return any(results)
    return all(results)  # default to AND


def _is_item_visible(
    is_active: bool,
    depends_on_question_id: str | None,
    expected_when: str | None,
    answers: dict[str, str],
    condition_expr_json: str | None = None,
) -> bool:
    """Evaluate a single item's visibility against the current answer set.

    condition_expr_json takes precedence over depends_on_question_id + expected_when
    when set.  When condition_expr_json is None the legacy single-condition path
    is used unchanged.
    """
    if not is_active:
        return False
    expr_result = _evaluate_condition_expr(condition_expr_json, answers)
    if expr_result is not None:
        return expr_result
    # Legacy single-condition fallback
    if depends_on_question_id is None:
        return True
    return answers.get(depends_on_question_id) == expected_when


def compute_visible_question_ids(
    all_questions: list[QuestionSkipInfo],
    answers: dict[str, str],
) -> set[str]:
    """Return the set of question IDs visible given the current answers.

    A question is visible when:
    - is_active is True, AND
    - condition_expr_json is set → evaluated with AND/OR logic, OR
    - depends_on_question_id is None, OR answers[depends_on_question_id] == expected_when.

    Inactive questions (is_active=False) are never visible regardless of answers.

    Args:
        all_questions: All questions in scope (may span multiple sections).
        answers: Mapping of question_id → answer_value for all answered questions.

    Returns:
        Set of question IDs that should be rendered to the user.
    """
    return {
        q.id
        for q in all_questions
        if _is_item_visible(
            q.is_active,
            q.depends_on_question_id,
            q.expected_when,
            answers,
            q.condition_expr_json,
        )
    }


def compute_visible_section_ids(
    all_sections: list[SectionSkipInfo],
    answers: dict[str, str],
) -> set[str]:
    """Return the set of section IDs visible given the current answers.

    Uses the identical condition_expr_json / depends_on / expected_when logic
    as questions.

    Args:
        all_sections: All sections in the schema.
        answers: Mapping of question_id → answer_value.

    Returns:
        Set of section IDs that should be rendered in the navigation.
    """
    return {
        s.id
        for s in all_sections
        if _is_item_visible(
            s.is_active,
            s.depends_on_question_id,
            s.expected_when,
            answers,
            s.condition_expr_json,
        )
    }


def compute_section_progress(
    section_questions: list[QuestionSkipInfo],
    answers: dict[str, str],
    visible_question_ids: set[str],
) -> SectionProgressResult:
    """Compute completion progress for one section.

    Per Pitfall 5: the denominator is visible REQUIRED questions only.
    Hidden questions are never counted in visible_count or answered_count,
    even if they happen to have an answer stored.

    Args:
        section_questions: All questions belonging to this section.
        answers: Mapping of question_id → answer_value.
        visible_question_ids: Pre-computed set from compute_visible_question_ids().

    Returns:
        SectionProgressResult with visible_count, answered_count, total_count.
    """
    total_count = len(section_questions)
    visible_required = [
        q
        for q in section_questions
        if q.id in visible_question_ids and q.is_required
    ]
    visible_count = len(visible_required)
    answered_count = sum(1 for q in visible_required if q.id in answers)
    return SectionProgressResult(
        visible_count=visible_count,
        answered_count=answered_count,
        total_count=total_count,
    )
