"""Unit tests for the skip logic engine (pure functions, no DB).

All 7 required behaviors per PLAN 134-02, Task 1:
  1. compute_visible_question_ids() with no answers returns only unconditional questions
  2. compute_visible_question_ids() with SCOPE-05=YES makes data_protection questions visible
  3. compute_visible_question_ids() with SCOPE-05=NO hides conditional questions
  4. compute_visible_section_ids() with SCOPE-06=YES makes supplier_third_party section visible
  5. compute_visible_section_ids() with no answers hides conditional sections, shows mandatory ones
  6. compute_section_progress() correctly excludes hidden questions from denominator (Pitfall 5)
  7. Inactive questions (is_active=False) are never visible regardless of answers
"""

from __future__ import annotations

import pytest

from aila.modules.sbd_nfr.services.skip_logic import (
    QuestionSkipInfo,
    SectionSkipInfo,
    SectionProgressResult,
    compute_visible_question_ids,
    compute_visible_section_ids,
    compute_section_progress,
)


# ---------------------------------------------------------------------------
# Helpers — build minimal skip-info objects
# ---------------------------------------------------------------------------


def _q(
    id: str,
    *,
    is_active: bool = True,
    is_required: bool = True,
    depends_on: str | None = None,
    expected_when: str | None = None,
) -> QuestionSkipInfo:
    return QuestionSkipInfo(
        id=id,
        is_active=is_active,
        is_required=is_required,
        depends_on_question_id=depends_on,
        expected_when=expected_when,
    )


def _s(
    id: str,
    *,
    is_active: bool = True,
    depends_on: str | None = None,
    expected_when: str | None = None,
) -> SectionSkipInfo:
    return SectionSkipInfo(
        id=id,
        is_active=is_active,
        depends_on_question_id=depends_on,
        expected_when=expected_when,
    )


# ---------------------------------------------------------------------------
# Test 1: no answers → only unconditional questions visible
# ---------------------------------------------------------------------------


def test_no_answers_returns_only_unconditional_questions():
    """compute_visible_question_ids with empty answers only returns questions
    that have no depends_on_question_id constraint."""
    questions = [
        _q("SCOPE-01"),                              # unconditional → visible
        _q("SCOPE-05"),                              # unconditional → visible
        _q("DP-01", depends_on="SCOPE-05", expected_when="YES"),  # conditional → hidden
        _q("DP-02", depends_on="SCOPE-05", expected_when="YES"),  # conditional → hidden
    ]
    visible = compute_visible_question_ids(questions, answers={})
    assert "SCOPE-01" in visible
    assert "SCOPE-05" in visible
    assert "DP-01" not in visible
    assert "DP-02" not in visible


# ---------------------------------------------------------------------------
# Test 2: SCOPE-05=YES makes data_protection questions visible
# ---------------------------------------------------------------------------


def test_scope05_yes_makes_dependent_questions_visible():
    """When SCOPE-05 is answered YES, questions that depend on it with
    expected_when=YES become visible."""
    questions = [
        _q("SCOPE-05"),
        _q("DP-01", depends_on="SCOPE-05", expected_when="YES"),
        _q("DP-02", depends_on="SCOPE-05", expected_when="YES"),
        _q("TP-01", depends_on="SCOPE-06", expected_when="YES"),  # different gate — hidden
    ]
    answers = {"SCOPE-05": "YES"}
    visible = compute_visible_question_ids(questions, answers=answers)
    assert "SCOPE-05" in visible
    assert "DP-01" in visible
    assert "DP-02" in visible
    assert "TP-01" not in visible


# ---------------------------------------------------------------------------
# Test 3: SCOPE-05=NO hides data_protection questions
# ---------------------------------------------------------------------------


def test_scope05_no_hides_dependent_questions():
    """When SCOPE-05 is answered NO, questions with expected_when=YES remain
    hidden because the condition is not satisfied."""
    questions = [
        _q("SCOPE-05"),
        _q("DP-01", depends_on="SCOPE-05", expected_when="YES"),
    ]
    answers = {"SCOPE-05": "NO"}
    visible = compute_visible_question_ids(questions, answers=answers)
    assert "SCOPE-05" in visible
    assert "DP-01" not in visible


# ---------------------------------------------------------------------------
# Test 4: SCOPE-06=YES makes supplier_third_party section visible
# ---------------------------------------------------------------------------


def test_scope06_yes_makes_supplier_section_visible():
    """compute_visible_section_ids with SCOPE-06=YES includes the
    supplier_third_party section (which depends on SCOPE-06 expected YES)."""
    sections = [
        _s("scope"),                                                    # mandatory
        _s("hygiene_essentials"),                                       # mandatory
        _s("supplier_third_party", depends_on="SCOPE-06", expected_when="YES"),
    ]
    answers = {"SCOPE-06": "YES"}
    visible = compute_visible_section_ids(sections, answers=answers)
    assert "scope" in visible
    assert "hygiene_essentials" in visible
    assert "supplier_third_party" in visible


# ---------------------------------------------------------------------------
# Test 5: no answers → conditional sections hidden, mandatory sections visible
# ---------------------------------------------------------------------------


def test_no_answers_hides_conditional_sections_shows_mandatory():
    """With no answers, sections with depends_on constraints are hidden;
    unconditional sections are always shown."""
    sections = [
        _s("scope"),
        _s("hygiene_essentials"),
        _s("data_protection", depends_on="SCOPE-05", expected_when="YES"),
        _s("supplier_third_party", depends_on="SCOPE-06", expected_when="YES"),
        _s("apis", depends_on="SCOPE-02", expected_when="YES"),
    ]
    visible = compute_visible_section_ids(sections, answers={})
    assert "scope" in visible
    assert "hygiene_essentials" in visible
    assert "data_protection" not in visible
    assert "supplier_third_party" not in visible
    assert "apis" not in visible


# ---------------------------------------------------------------------------
# Test 6: compute_section_progress excludes hidden questions from denominator
# (Pitfall 5: denominator = visible required questions, not all questions)
# ---------------------------------------------------------------------------


def test_section_progress_excludes_hidden_questions():
    """compute_section_progress denominator must be visible required questions
    only, not all questions in the section."""
    # 3 questions total: 2 visible required, 1 hidden required
    q_visible_1 = _q("Q-01", is_required=True)
    q_visible_2 = _q("Q-02", is_required=True)
    q_hidden = _q("Q-03", is_required=True, depends_on="SCOPE-05", expected_when="YES")

    all_questions = [q_visible_1, q_visible_2, q_hidden]

    # Only Q-01 and Q-02 are visible
    visible_ids = {"Q-01", "Q-02"}

    # Q-01 is answered, Q-02 is not
    answers = {"Q-01": "YES"}

    result = compute_section_progress(all_questions, answers, visible_ids)

    # visible_count = 2 (Q-01 and Q-02 are visible and required)
    assert isinstance(result, SectionProgressResult)
    assert result.visible_count == 2
    # answered_count = 1 (only Q-01 answered, and it is visible)
    assert result.answered_count == 1
    # total_count = 3 (all questions in section, regardless of visibility)
    assert result.total_count == 3


# ---------------------------------------------------------------------------
# Test 7: inactive questions are never visible regardless of answers
# ---------------------------------------------------------------------------


def test_inactive_questions_never_visible():
    """is_active=False questions must never appear in compute_visible_question_ids
    output, even when their dependency condition is satisfied."""
    questions = [
        _q("SCOPE-05"),
        _q("DP-01", is_active=False),                           # inactive, unconditional
        _q("DP-02", is_active=False, depends_on="SCOPE-05", expected_when="YES"),  # inactive + conditional
        _q("DP-03", depends_on="SCOPE-05", expected_when="YES"),   # active + conditional → visible
    ]
    answers = {"SCOPE-05": "YES"}
    visible = compute_visible_question_ids(questions, answers=answers)
    assert "DP-01" not in visible, "Inactive unconditional question must not be visible"
    assert "DP-02" not in visible, "Inactive conditional question must not be visible even if condition met"
    assert "DP-03" in visible, "Active conditional question with condition met must be visible"


# ---------------------------------------------------------------------------
# New tests for condition_expr_json multi-condition gating (TOOL-04)
# ---------------------------------------------------------------------------


def _q_expr(
    id: str,
    *,
    is_active: bool = True,
    is_required: bool = True,
    depends_on: str | None = None,
    expected_when: str | None = None,
    condition_expr_json: str | None = None,
) -> QuestionSkipInfo:
    """Build a QuestionSkipInfo with optional condition_expr_json."""
    return QuestionSkipInfo(
        id=id,
        is_active=is_active,
        is_required=is_required,
        depends_on_question_id=depends_on,
        expected_when=expected_when,
        condition_expr_json=condition_expr_json,
    )


def _s_expr(
    id: str,
    *,
    is_active: bool = True,
    depends_on: str | None = None,
    expected_when: str | None = None,
    condition_expr_json: str | None = None,
) -> SectionSkipInfo:
    """Build a SectionSkipInfo with optional condition_expr_json."""
    return SectionSkipInfo(
        id=id,
        is_active=is_active,
        depends_on_question_id=depends_on,
        expected_when=expected_when,
        condition_expr_json=condition_expr_json,
    )


import json


# Test 8a: AND gating — visible only when ALL conditions match
def test_condition_expr_and_visible_when_all_match():
    """Question with AND condition_expr_json is visible only when ALL conditions satisfied."""
    expr = json.dumps({
        "op": "and",
        "conditions": [
            {"question_id": "SCOPE-01", "expected": "web"},
            {"question_id": "SCOPE-03", "expected": "internet"},
        ],
    })
    questions = [
        _q_expr("Q-AND", condition_expr_json=expr),
        _q_expr("Q-UNCON"),  # unconditional baseline
    ]
    # Both conditions met → visible
    answers = {"SCOPE-01": "web", "SCOPE-03": "internet"}
    visible = compute_visible_question_ids(questions, answers=answers)
    assert "Q-AND" in visible
    assert "Q-UNCON" in visible


# Test 8b: AND gating — hidden when ONE condition fails
def test_condition_expr_and_hidden_when_one_fails():
    """Question with AND condition_expr_json is hidden when any condition is not satisfied."""
    expr = json.dumps({
        "op": "and",
        "conditions": [
            {"question_id": "SCOPE-01", "expected": "web"},
            {"question_id": "SCOPE-03", "expected": "internet"},
        ],
    })
    questions = [_q_expr("Q-AND", condition_expr_json=expr)]
    # Only first condition met → hidden
    answers = {"SCOPE-01": "web", "SCOPE-03": "cloud"}
    visible = compute_visible_question_ids(questions, answers=answers)
    assert "Q-AND" not in visible


# Test 8c: OR gating — visible when ANY condition matches
def test_condition_expr_or_visible_when_any_matches():
    """Question with OR condition_expr_json is visible when any condition is satisfied."""
    expr = json.dumps({
        "op": "or",
        "conditions": [
            {"question_id": "SCOPE-01", "expected": "web_application"},
            {"question_id": "SCOPE-01", "expected": "mobile_application"},
        ],
    })
    questions = [_q_expr("Q-OR", condition_expr_json=expr)]
    # Only second option matches
    answers = {"SCOPE-01": "mobile_application"}
    visible = compute_visible_question_ids(questions, answers=answers)
    assert "Q-OR" in visible


# Test 8d: OR gating — hidden when no conditions match
def test_condition_expr_or_hidden_when_none_match():
    """Question with OR condition_expr_json is hidden when no conditions are satisfied."""
    expr = json.dumps({
        "op": "or",
        "conditions": [
            {"question_id": "SCOPE-01", "expected": "web_application"},
            {"question_id": "SCOPE-01", "expected": "mobile_application"},
        ],
    })
    questions = [_q_expr("Q-OR", condition_expr_json=expr)]
    answers = {"SCOPE-01": "api_service"}
    visible = compute_visible_question_ids(questions, answers=answers)
    assert "Q-OR" not in visible


# Test 8e: condition_expr_json=None → legacy depends_on/expected_when fallback
def test_condition_expr_none_falls_back_to_legacy():
    """condition_expr_json=None uses legacy depends_on/expected_when logic unchanged."""
    questions = [
        _q_expr(
            "Q-LEGACY",
            depends_on="SCOPE-05",
            expected_when="YES",
            condition_expr_json=None,
        ),
        _q_expr("Q-UNCON"),
    ]
    # Legacy condition met → visible
    answers = {"SCOPE-05": "YES"}
    visible = compute_visible_question_ids(questions, answers=answers)
    assert "Q-LEGACY" in visible
    assert "Q-UNCON" in visible

    # Legacy condition not met → hidden
    visible_no = compute_visible_question_ids(questions, answers={"SCOPE-05": "NO"})
    assert "Q-LEGACY" not in visible_no


# Test 8f: empty conditions list → always visible (no constraints)
def test_condition_expr_empty_conditions_always_visible():
    """condition_expr_json with empty conditions list means no constraints → item visible."""
    expr = json.dumps({"op": "and", "conditions": []})
    questions = [_q_expr("Q-EMPTY", condition_expr_json=expr)]
    visible = compute_visible_question_ids(questions, answers={})
    assert "Q-EMPTY" in visible


# Test 8g: Section-level condition_expr_json AND gating works identically
def test_section_condition_expr_and_gating():
    """Sections also support condition_expr_json with AND logic."""
    expr = json.dumps({
        "op": "and",
        "conditions": [
            {"question_id": "SCOPE-01", "expected": "web"},
            {"question_id": "SCOPE-03", "expected": "internet"},
        ],
    })
    sections = [
        _s_expr("scope"),  # unconditional
        _s_expr("conditional_section", condition_expr_json=expr),
    ]
    # Both conditions met
    answers = {"SCOPE-01": "web", "SCOPE-03": "internet"}
    visible = compute_visible_section_ids(sections, answers=answers)
    assert "scope" in visible
    assert "conditional_section" in visible

    # One condition fails
    visible_fail = compute_visible_section_ids(sections, answers={"SCOPE-01": "web", "SCOPE-03": "cloud"})
    assert "conditional_section" not in visible_fail


# Test 8h: Section-level condition_expr_json OR gating works identically
def test_section_condition_expr_or_gating():
    """Sections also support condition_expr_json with OR logic."""
    expr = json.dumps({
        "op": "or",
        "conditions": [
            {"question_id": "SCOPE-01", "expected": "web"},
            {"question_id": "SCOPE-01", "expected": "mobile"},
        ],
    })
    sections = [_s_expr("or_section", condition_expr_json=expr)]

    visible = compute_visible_section_ids(sections, answers={"SCOPE-01": "mobile"})
    assert "or_section" in visible

    visible_fail = compute_visible_section_ids(sections, answers={"SCOPE-01": "api"})
    assert "or_section" not in visible_fail
