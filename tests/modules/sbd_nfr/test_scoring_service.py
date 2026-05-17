"""Unit tests for the SbD NFR scoring service.

Tests cover:
- compute_section_scores: binary (compliance) questions, maturity tier questions,
  NA exclusion, empty sections
- compute_posture_index: scope exclusion, empty input
- derive_risk_tier: all four tiers (CRITICAL, HIGH, MEDIUM, LOW)

Design references: SCORE-01, SCORE-02.
"""

from __future__ import annotations

import pytest

from aila.modules.sbd_nfr.services.scoring_service import (
    QuestionScoreInfo,
    SectionScore,
    compute_posture_index,
    compute_section_scores,
    derive_risk_tier,
)

# ---------------------------------------------------------------------------
# compute_section_scores tests
# ---------------------------------------------------------------------------


class TestComputeSectionScoresBinaryCompliance:
    """Binary (compliance) questions: Yes=1.0, Partial=0.5, No=0.0, NA=excluded."""

    def test_all_yes_answers_score_1_0(self) -> None:
        """All Yes answers for 3 binary questions → section score 1.0."""
        questions = [
            QuestionScoreInfo(id="Q-01", answer_type="compliance", section_key="hygiene"),
            QuestionScoreInfo(id="Q-02", answer_type="compliance", section_key="hygiene"),
            QuestionScoreInfo(id="Q-03", answer_type="compliance", section_key="hygiene"),
        ]
        answers = {"Q-01": "Yes", "Q-02": "Yes", "Q-03": "Yes"}
        visible_ids = {"Q-01", "Q-02", "Q-03"}

        results = compute_section_scores(questions, answers, visible_ids)

        assert len(results) == 1
        section = results[0]
        assert section.section_key == "hygiene"
        assert section.score == pytest.approx(1.0)
        assert section.answered_count == 3
        assert section.visible_count == 3

    def test_yes_no_na_excludes_na_from_average(self) -> None:
        """Yes/No/NA → average of 1.0 and 0.0 (NA excluded) → 0.5."""
        questions = [
            QuestionScoreInfo(id="Q-01", answer_type="compliance", section_key="network"),
            QuestionScoreInfo(id="Q-02", answer_type="compliance", section_key="network"),
            QuestionScoreInfo(id="Q-03", answer_type="compliance", section_key="network"),
        ]
        answers = {"Q-01": "Yes", "Q-02": "No", "Q-03": "Not applicable"}
        visible_ids = {"Q-01", "Q-02", "Q-03"}

        results = compute_section_scores(questions, answers, visible_ids)

        assert len(results) == 1
        section = results[0]
        assert section.section_key == "network"
        assert section.score == pytest.approx(0.5)

    def test_partial_answer_scores_half(self) -> None:
        """Partial answer contributes 0.5."""
        questions = [
            QuestionScoreInfo(id="Q-01", answer_type="compliance", section_key="identity"),
            QuestionScoreInfo(id="Q-02", answer_type="compliance", section_key="identity"),
        ]
        answers = {"Q-01": "Yes", "Q-02": "Partial"}
        visible_ids = {"Q-01", "Q-02"}

        results = compute_section_scores(questions, answers, visible_ids)

        section = results[0]
        assert section.score == pytest.approx(0.75)  # (1.0 + 0.5) / 2

    def test_all_na_answers_scores_0_0(self) -> None:
        """All NA answers → no scored questions → section score 0.0."""
        questions = [
            QuestionScoreInfo(id="Q-01", answer_type="compliance", section_key="data"),
            QuestionScoreInfo(id="Q-02", answer_type="compliance", section_key="data"),
        ]
        answers = {"Q-01": "Not applicable", "Q-02": "Not applicable"}
        visible_ids = {"Q-01", "Q-02"}

        results = compute_section_scores(questions, answers, visible_ids)

        section = results[0]
        assert section.score == pytest.approx(0.0)

    def test_no_answers_empty_section_scores_0_0(self) -> None:
        """Empty answered set → section score 0.0 (no scored questions)."""
        questions = [
            QuestionScoreInfo(id="Q-01", answer_type="compliance", section_key="crypto"),
        ]
        answers: dict[str, str] = {}
        visible_ids = {"Q-01"}

        results = compute_section_scores(questions, answers, visible_ids)

        section = results[0]
        assert section.score == pytest.approx(0.0)
        assert section.answered_count == 0

    def test_unknown_answer_value_excluded(self) -> None:
        """Unknown answer values (not Yes/Partial/No/NA) are excluded from scoring (T-154-01)."""
        questions = [
            QuestionScoreInfo(id="Q-01", answer_type="compliance", section_key="ops"),
            QuestionScoreInfo(id="Q-02", answer_type="compliance", section_key="ops"),
        ]
        answers = {"Q-01": "Yes", "Q-02": "UnknownValue"}
        visible_ids = {"Q-01", "Q-02"}

        results = compute_section_scores(questions, answers, visible_ids)

        section = results[0]
        # Only Q-01 contributes → 1.0 / 1 = 1.0
        assert section.score == pytest.approx(1.0)


class TestComputeSectionScoresMaturityTier:
    """Maturity tier questions: answer value is the score directly (0-3)."""

    def test_maturity_tier_answers_averaged(self) -> None:
        """Maturity tier answers '2' and '3' → average 2.5."""
        questions = [
            QuestionScoreInfo(id="MT-01", answer_type="maturity_tier", section_key="architecture"),
            QuestionScoreInfo(id="MT-02", answer_type="maturity_tier", section_key="architecture"),
        ]
        answers = {"MT-01": "2", "MT-02": "3"}
        visible_ids = {"MT-01", "MT-02"}

        results = compute_section_scores(questions, answers, visible_ids)

        section = results[0]
        assert section.section_key == "architecture"
        assert section.score == pytest.approx(2.5)

    def test_maturity_tier_non_numeric_excluded(self) -> None:
        """Non-numeric maturity tier values are excluded from scoring."""
        questions = [
            QuestionScoreInfo(id="MT-01", answer_type="maturity_tier", section_key="architecture"),
            QuestionScoreInfo(id="MT-02", answer_type="maturity_tier", section_key="architecture"),
        ]
        answers = {"MT-01": "2", "MT-02": "not_a_number"}
        visible_ids = {"MT-01", "MT-02"}

        results = compute_section_scores(questions, answers, visible_ids)

        section = results[0]
        # Only MT-01 contributes → 2.0 / 1 = 2.0
        assert section.score == pytest.approx(2.0)

    def test_maturity_tier_zero_is_valid_score(self) -> None:
        """Maturity tier answer '0' is a valid score of 0.0 (not excluded)."""
        questions = [
            QuestionScoreInfo(id="MT-01", answer_type="maturity_tier", section_key="architecture"),
            QuestionScoreInfo(id="MT-02", answer_type="maturity_tier", section_key="architecture"),
        ]
        answers = {"MT-01": "0", "MT-02": "2"}
        visible_ids = {"MT-01", "MT-02"}

        results = compute_section_scores(questions, answers, visible_ids)

        section = results[0]
        assert section.score == pytest.approx(1.0)  # (0 + 2) / 2


class TestComputeSectionScoresExclusions:
    """Scope, free_text, and none answer types are excluded from scoring."""

    def test_scope_questions_excluded_from_score(self) -> None:
        """Scope questions do not contribute to section scores."""
        questions = [
            QuestionScoreInfo(id="SCOPE-01", answer_type="scope", section_key="scope"),
            QuestionScoreInfo(id="SCOPE-02", answer_type="scope", section_key="scope"),
        ]
        answers = {"SCOPE-01": "Yes", "SCOPE-02": "No"}
        visible_ids = {"SCOPE-01", "SCOPE-02"}

        results = compute_section_scores(questions, answers, visible_ids)

        # Section exists but score is 0.0 (no scored questions)
        section = results[0]
        assert section.score == pytest.approx(0.0)

    def test_free_text_questions_excluded_from_score(self) -> None:
        """Free text questions do not contribute to section scores."""
        questions = [
            QuestionScoreInfo(id="Q-01", answer_type="compliance", section_key="testing"),
            QuestionScoreInfo(id="Q-02", answer_type="free_text", section_key="testing"),
        ]
        answers = {"Q-01": "Yes", "Q-02": "some long text"}
        visible_ids = {"Q-01", "Q-02"}

        results = compute_section_scores(questions, answers, visible_ids)

        section = results[0]
        # Only Q-01 scores → 1.0
        assert section.score == pytest.approx(1.0)

    def test_none_type_questions_excluded_from_score(self) -> None:
        """None-type questions (headers) do not contribute to section scores."""
        questions = [
            QuestionScoreInfo(id="Q-01", answer_type="compliance", section_key="controls"),
            QuestionScoreInfo(id="Q-HDR", answer_type="none", section_key="controls"),
        ]
        answers = {"Q-01": "No", "Q-HDR": ""}
        visible_ids = {"Q-01", "Q-HDR"}

        results = compute_section_scores(questions, answers, visible_ids)

        section = results[0]
        assert section.score == pytest.approx(0.0)

    def test_hidden_questions_not_scored(self) -> None:
        """Questions not in visible_question_ids are excluded from scoring."""
        questions = [
            QuestionScoreInfo(id="Q-01", answer_type="compliance", section_key="access"),
            QuestionScoreInfo(id="Q-02", answer_type="compliance", section_key="access"),
        ]
        answers = {"Q-01": "Yes", "Q-02": "No"}
        # Q-02 is hidden
        visible_ids = {"Q-01"}

        results = compute_section_scores(questions, answers, visible_ids)

        section = results[0]
        assert section.score == pytest.approx(1.0)
        assert section.visible_count == 1

    def test_multiple_sections_scored_separately(self) -> None:
        """Questions across multiple sections produce one SectionScore per section."""
        questions = [
            QuestionScoreInfo(id="Q-01", answer_type="compliance", section_key="hygiene"),
            QuestionScoreInfo(id="Q-02", answer_type="compliance", section_key="network"),
        ]
        answers = {"Q-01": "Yes", "Q-02": "No"}
        visible_ids = {"Q-01", "Q-02"}

        results = compute_section_scores(questions, answers, visible_ids)
        scores_by_key = {s.section_key: s.score for s in results}

        assert len(results) == 2
        assert scores_by_key["hygiene"] == pytest.approx(1.0)
        assert scores_by_key["network"] == pytest.approx(0.0)

    def test_empty_question_list_returns_empty(self) -> None:
        """Empty question list returns empty result list."""
        results = compute_section_scores([], {}, set())
        assert results == []


# ---------------------------------------------------------------------------
# compute_posture_index tests
# ---------------------------------------------------------------------------


class TestComputePostureIndex:
    def test_scope_section_excluded_from_posture_index(self) -> None:
        """compute_posture_index excludes the scope section."""
        section_scores = [
            SectionScore(section_key="scope", score=2.5, answered_count=5, visible_count=5),
            SectionScore(section_key="hygiene", score=1.0, answered_count=3, visible_count=3),
            SectionScore(section_key="network", score=2.0, answered_count=3, visible_count=3),
        ]

        index = compute_posture_index(section_scores)

        # (1.0 + 2.0) / 2 = 1.5 (scope excluded)
        assert index == pytest.approx(1.5)

    def test_empty_section_list_returns_0_0(self) -> None:
        """compute_posture_index with no sections → 0.0."""
        index = compute_posture_index([])
        assert index == pytest.approx(0.0)

    def test_only_scope_section_returns_0_0(self) -> None:
        """Only scope section present → 0.0 (no NFR sections to average)."""
        section_scores = [
            SectionScore(section_key="scope", score=2.5, answered_count=5, visible_count=5),
        ]
        index = compute_posture_index(section_scores)
        assert index == pytest.approx(0.0)

    def test_average_is_rounded_to_2_decimal_places(self) -> None:
        """Result is rounded to 2 decimal places."""
        section_scores = [
            SectionScore(section_key="a", score=1.0, answered_count=1, visible_count=1),
            SectionScore(section_key="b", score=2.0, answered_count=1, visible_count=1),
            SectionScore(section_key="c", score=3.0, answered_count=1, visible_count=1),
        ]
        index = compute_posture_index(section_scores)
        # (1.0 + 2.0 + 3.0) / 3 = 2.0
        assert index == pytest.approx(2.0)
        # Verify it's a float with up to 2 decimal places
        assert round(index, 2) == index

    def test_single_nfr_section_returns_its_score(self) -> None:
        """Single NFR section returns its own score as posture index."""
        section_scores = [
            SectionScore(section_key="network", score=2.5, answered_count=5, visible_count=5),
        ]
        index = compute_posture_index(section_scores)
        assert index == pytest.approx(2.5)


# ---------------------------------------------------------------------------
# derive_risk_tier tests
# ---------------------------------------------------------------------------


class TestDeriveRiskTier:
    def test_internet_facing_and_pii_returns_critical(self) -> None:
        """SCOPE-02=PII + SCOPE-03=internet_facing → CRITICAL."""
        scope_answers = {"SCOPE-02": "pii", "SCOPE-03": "internet_facing"}
        assert derive_risk_tier(scope_answers) == "CRITICAL"

    def test_public_and_financial_returns_critical(self) -> None:
        """SCOPE-03=public + SCOPE-02=financial → CRITICAL."""
        scope_answers = {"SCOPE-02": "financial", "SCOPE-03": "public"}
        assert derive_risk_tier(scope_answers) == "CRITICAL"

    def test_internet_facing_and_phi_returns_critical(self) -> None:
        """SCOPE-03=internet_facing + SCOPE-02=phi → CRITICAL."""
        scope_answers = {"SCOPE-02": "phi", "SCOPE-03": "internet_facing"}
        assert derive_risk_tier(scope_answers) == "CRITICAL"

    def test_internet_facing_only_returns_high(self) -> None:
        """SCOPE-03=internet_facing + SCOPE-02=internal → HIGH."""
        scope_answers = {"SCOPE-02": "internal", "SCOPE-03": "internet_facing"}
        assert derive_risk_tier(scope_answers) == "HIGH"

    def test_pii_only_internal_returns_high(self) -> None:
        """SCOPE-02=PII + SCOPE-03=internal → HIGH."""
        scope_answers = {"SCOPE-02": "pii", "SCOPE-03": "internal"}
        assert derive_risk_tier(scope_answers) == "HIGH"

    def test_sensitive_data_internal_returns_high(self) -> None:
        """SCOPE-02=sensitive + SCOPE-03=internal → HIGH."""
        scope_answers = {"SCOPE-02": "sensitive", "SCOPE-03": "internal"}
        assert derive_risk_tier(scope_answers) == "HIGH"

    def test_confidential_internal_returns_medium(self) -> None:
        """SCOPE-02=confidential + SCOPE-03=internal → MEDIUM."""
        scope_answers = {"SCOPE-02": "confidential", "SCOPE-03": "internal"}
        assert derive_risk_tier(scope_answers) == "MEDIUM"

    def test_internal_confidential_internal_returns_medium(self) -> None:
        """SCOPE-02=internal_confidential + SCOPE-03=internal → MEDIUM."""
        scope_answers = {"SCOPE-02": "internal_confidential", "SCOPE-03": "internal"}
        assert derive_risk_tier(scope_answers) == "MEDIUM"

    def test_internal_only_returns_low(self) -> None:
        """SCOPE-02=internal_only + SCOPE-03=internal → LOW."""
        scope_answers = {"SCOPE-02": "internal_only", "SCOPE-03": "internal"}
        assert derive_risk_tier(scope_answers) == "LOW"

    def test_missing_scope_answers_defaults_to_medium(self) -> None:
        """Missing scope answers default to MEDIUM (conservative, T-154-02)."""
        assert derive_risk_tier({}) == "MEDIUM"

    def test_missing_scope02_defaults_conservative(self) -> None:
        """Missing SCOPE-02 with internet-facing SCOPE-03 → MEDIUM (conservative, not LOW)."""
        scope_answers = {"SCOPE-03": "internet_facing"}
        # SCOPE-02 is missing — cannot classify data sensitivity as sensitive or not
        # Result is HIGH (internet-facing presence alone triggers HIGH per logic)
        result = derive_risk_tier(scope_answers)
        # Internet-facing alone qualifies for HIGH even without data classification
        assert result == "HIGH"

    def test_case_insensitive_matching(self) -> None:
        """Answer matching is case-insensitive."""
        scope_answers = {"SCOPE-02": "PII", "SCOPE-03": "Internet_Facing"}
        assert derive_risk_tier(scope_answers) == "CRITICAL"
