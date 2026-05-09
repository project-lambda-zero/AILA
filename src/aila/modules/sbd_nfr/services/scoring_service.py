"""Pure-function SAMM maturity scoring engine for the SbD NFR questionnaire.

Design references: SCORE-01, SCORE-02.

All functions are pure — they have no DB access, no side effects, and no
imports from aila.storage.  Callers build the lightweight DTO inputs from DB
records and pass answers as a plain dict.

Scoring rules (SCORE-01):
    compliance (binary) questions:
        "Yes" → 1.0, "Partial" → 0.5, "No" → 0.0, "Not applicable" → excluded
    maturity_tier questions:
        answer value is the numeric score directly (e.g., "0", "1", "2", "3")
        non-numeric or unanswered → excluded
    scope, free_text, none → excluded from scoring entirely
    Section score = sum(scored answers) / count(scored answers); 0.0 if empty

Risk tier derivation (SCORE-02):
    CRITICAL: internet-facing + PII/PHI/financial/sensitive data
    HIGH:     internet-facing OR PII/PHI/financial/sensitive data
    MEDIUM:   confidential/internal-confidential data (internal only)
    LOW:      internal + public/internal data
    Default:  MEDIUM when scope answers are missing (T-154-02 conservative)

Threat model mitigations applied:
    T-154-01: Unknown answer values are excluded (not 0) — no crash, no score inflation.
    T-154-02: Missing scope answers default to MEDIUM — fail conservative, not LOW.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "QuestionScoreInfo",
    "SectionScore",
    "PostureResult",
    "compute_section_scores",
    "compute_posture_index",
    "derive_risk_tier",
]


# ---------------------------------------------------------------------------
# Lightweight, immutable DTOs — NOT SQLModel records
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class QuestionScoreInfo:
    """Minimal question data needed to compute a maturity score."""

    id: str
    answer_type: str  # "compliance" | "maturity_tier" | "scope" | "free_text" | "none"
    section_key: str


@dataclass(frozen=True, slots=True)
class SectionScore:
    """Aggregated maturity score for one questionnaire section.

    score:         0.0-3.0 average of scored questions.
    answered_count: number of visible questions with a recorded answer (any type).
    visible_count:  number of visible questions in this section.
    """

    section_key: str
    score: float
    answered_count: int
    visible_count: int


@dataclass(frozen=True, slots=True)
class PostureResult:
    """Overall posture assessment result for a completed session.

    section_scores: one SectionScore per section (including scope).
    posture_index:  0.0-3.0 average of non-scope section scores.
    risk_tier:      "LOW"|"MEDIUM"|"HIGH"|"CRITICAL".
    """

    section_scores: tuple[SectionScore, ...]
    posture_index: float
    risk_tier: str


# ---------------------------------------------------------------------------
# Answer value mappings
# ---------------------------------------------------------------------------

# Binary (compliance) answer value → numeric score.
# Values not in this map are excluded from scoring (T-154-01).
_COMPLIANCE_SCORES: dict[str, float] = {
    "yes": 1.0,
    "partial": 0.5,
    "no": 0.0,
}

# Normalised answer values that mark NA and are excluded from scoring.
_NA_VALUES: frozenset[str] = frozenset({"not applicable", "n/a", "na"})

# Data sensitivity answer values that trigger HIGH or CRITICAL tier.
# Case-insensitive matching applied at call site.
_SENSITIVE_DATA_VALUES: frozenset[str] = frozenset(
    {"pii", "phi", "financial", "sensitive"}
)

# Confidential (but not sensitive) data values → MEDIUM tier.
_CONFIDENTIAL_DATA_VALUES: frozenset[str] = frozenset(
    {"confidential", "internal_confidential"}
)

# Internet-facing exposure values.
_INTERNET_FACING_VALUES: frozenset[str] = frozenset({"internet_facing", "public"})


# ---------------------------------------------------------------------------
# Pure engine functions
# ---------------------------------------------------------------------------


def _score_compliance_answer(answer_value: str) -> float | None:
    """Return numeric score for a compliance answer, or None if excluded.

    None means the answer is excluded from the section average (NA, or unknown).
    This implements T-154-01: unknown values produce no score contribution.
    """
    normalised = answer_value.strip().lower()
    if normalised in _NA_VALUES:
        return None
    return _COMPLIANCE_SCORES.get(normalised)  # None for unknown values


def _score_maturity_tier_answer(answer_value: str) -> float | None:
    """Return numeric score for a maturity tier answer, or None if excluded.

    Numeric string values ("0", "1", "2", "3") are converted to float.
    Non-numeric or empty values are excluded (None).
    """
    stripped = answer_value.strip()
    if not stripped:
        return None
    try:
        return float(stripped)
    except ValueError:
        return None  # non-numeric excluded (T-154-01)


def compute_section_scores(
    questions: list[QuestionScoreInfo],
    answers: dict[str, str],
    visible_question_ids: set[str],
) -> list[SectionScore]:
    """Compute per-section maturity scores from question answers.

    Scoring rules:
    - Only questions in visible_question_ids are scored.
    - compliance/binary: Yes=1.0, Partial=0.5, No=0.0, NA=excluded.
    - maturity_tier: numeric string value → float; non-numeric → excluded.
    - scope, free_text, none: always excluded from section average.
    - Section score = sum(scores) / count(scored questions); 0.0 if none scored.

    Args:
        questions: All questions for the session (may include hidden ones).
        answers: Mapping of question_id → answer_value.
        visible_question_ids: Pre-computed set of visible question IDs.

    Returns:
        One SectionScore per distinct section_key in questions.
        Order is deterministic (insertion order of first occurrence).
    """
    # Accumulate per-section data
    section_keys: list[str] = []
    section_score_sum: dict[str, float] = {}
    section_score_count: dict[str, int] = {}
    section_answered: dict[str, int] = {}
    section_visible: dict[str, int] = {}

    for q in questions:
        if q.id not in visible_question_ids:
            continue
        key = q.section_key

        # Track section keys in insertion order
        if key not in section_score_sum:
            section_keys.append(key)
            section_score_sum[key] = 0.0
            section_score_count[key] = 0
            section_answered[key] = 0
            section_visible[key] = 0

        section_visible[key] += 1

        raw_answer = answers.get(q.id)
        if raw_answer is not None:
            section_answered[key] += 1

        # Determine numeric contribution
        score: float | None = None
        if q.answer_type == "compliance":
            if raw_answer is not None:
                score = _score_compliance_answer(raw_answer)
        elif q.answer_type == "maturity_tier" and raw_answer is not None:
            score = _score_maturity_tier_answer(raw_answer)
        # scope, free_text, none → score remains None (excluded)

        if score is not None:
            section_score_sum[key] += score
            section_score_count[key] += 1

    results: list[SectionScore] = []
    for key in section_keys:
        count = section_score_count[key]
        avg_score = section_score_sum[key] / count if count > 0 else 0.0
        results.append(
            SectionScore(
                section_key=key,
                score=avg_score,
                answered_count=section_answered[key],
                visible_count=section_visible[key],
            )
        )
    return results


def compute_posture_index(section_scores: list[SectionScore]) -> float:
    """Compute the overall posture index from per-section scores.

    Excludes the scope section (section_key == "scope") from the average —
    the scope section captures system context, not NFR maturity.

    Args:
        section_scores: List of SectionScore objects (may include scope).

    Returns:
        Unweighted average of non-scope section scores, rounded to 2 decimal
        places.  Returns 0.0 if no NFR sections are present.
    """
    nfr_scores = [s.score for s in section_scores if s.section_key != "scope"]
    if not nfr_scores:
        return 0.0
    raw = sum(nfr_scores) / len(nfr_scores)
    return round(raw, 2)


def derive_risk_tier(scope_answers: dict[str, str]) -> str:
    """Derive the risk tier from scope question answers.

    Reads SCOPE-02 (data sensitivity) and SCOPE-03 (internet exposure).
    Matching is case-insensitive.

    Tier logic (SCORE-02, T-154-02):
        CRITICAL: SCOPE-03 is internet-facing AND SCOPE-02 is sensitive data
        HIGH:     SCOPE-03 is internet-facing OR SCOPE-02 is sensitive data
        MEDIUM:   SCOPE-02 is confidential/internal-confidential
        LOW:      everything else (internal + public/internal data)
        Default:  MEDIUM when scope answers are missing (conservative — T-154-02)

    Args:
        scope_answers: Mapping of question_id → answer_value for scope questions.
            Expected keys: "SCOPE-02", "SCOPE-03".

    Returns:
        One of "LOW", "MEDIUM", "HIGH", "CRITICAL".
    """
    raw_data = scope_answers.get("SCOPE-02", "")
    raw_exposure = scope_answers.get("SCOPE-03", "")

    data_sensitivity = raw_data.strip().lower()
    exposure = raw_exposure.strip().lower()

    is_internet_facing = exposure in _INTERNET_FACING_VALUES
    is_sensitive_data = data_sensitivity in _SENSITIVE_DATA_VALUES
    is_confidential_data = data_sensitivity in _CONFIDENTIAL_DATA_VALUES

    if is_internet_facing and is_sensitive_data:
        return "CRITICAL"
    if is_internet_facing or is_sensitive_data:
        return "HIGH"
    if is_confidential_data:
        return "MEDIUM"
    # Both answers missing → default MEDIUM (conservative, T-154-02)
    if not data_sensitivity and not exposure:
        return "MEDIUM"
    # Internal + public/internal data → LOW
    # Anything else that isn't confidential → LOW
    return "LOW"
