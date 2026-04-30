"""Search contract models for the SbD NFR module.

Design references: D-45, D-47.

SmartSearchRequest:  unified search accepting a natural language query plus
typed filters for status, business_unit, and tag.

SearchResultItem:    a single search hit with LLM-generated reasoning citing
specific answers (D-47).

SmartSearchResponse: the full response including LLM's interpretation of the
query and ranked result list.

_LLMSearchResult:   internal model fed to chat_structured().  All fields MUST
have explicit defaults and be non-Optional to satisfy OpenAI strict mode
validation (Pitfall 6 in 134-RESEARCH).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from aila.api.schemas.common import APIModel

__all__ = [
    "SmartSearchRequest",
    "SearchMatchedAnswer",
    "SearchResultItem",
    "SmartSearchResponse",
]


class SmartSearchRequest(APIModel):
    """Per D-45: unified search with natural language query + typed filters.

    query is the free-text natural language question (1–500 chars).
    Optional typed filters narrow the candidate set before LLM ranking.
    max_results caps the returned hits (1–50, default 10).
    """

    query: str = Field(min_length=1, max_length=500)
    status: str | None = None
    business_unit: str | None = None
    tag: str | None = None
    max_results: int = Field(default=10, ge=1, le=50)


class SearchMatchedAnswer(APIModel):
    """One question/answer pair cited by the LLM as evidence for a result hit."""

    question_id: str
    question_label: str
    answer_value: str


class SearchResultItem(APIModel):
    """Per D-47: one ranked session hit with LLM-generated reasoning.

    reasoning cites specific answer values from the session to justify the
    relevance_score (0.0–1.0).  matching_answers lists the key
    question/answer pairs that were cited.
    """

    session_id: str
    project_name: str
    status: str
    business_unit: str | None = None
    requestor_name: str
    relevance_score: float = Field(ge=0.0, le=1.0)
    reasoning: str
    matching_answers: list[SearchMatchedAnswer] = Field(default_factory=list)
    created_at: datetime


class SmartSearchResponse(APIModel):
    """Top-level response for POST /sessions/smart-search.

    query_interpretation is the LLM's plain-language restatement of what it
    understood the query to be asking for.  Useful for the UI to show the user
    "We searched for X" so they can correct any misinterpretation.
    """

    query: str
    query_interpretation: str
    results: list[SearchResultItem] = Field(default_factory=list)
    total_searched: int = 0


# ---------------------------------------------------------------------------
# Internal LLM response model (NOT part of the public API surface)
# ---------------------------------------------------------------------------


class _LLMSearchResult(APIModel):
    """Internal Pydantic model for chat_structured() response.

    All fields have explicit non-None defaults per Pitfall 6: OpenAI strict
    mode validation requires every field to be present in the JSON schema
    'required' array.  Fields with Optional type would be excluded from
    'required' and cause validation errors.

    session_ids, scores, and reasonings are parallel lists: index N in each
    list corresponds to the same session.  The LLM returns them in its
    preferred relevance order (most relevant first).
    """

    session_ids: list[str] = Field(default_factory=list)
    scores: list[float] = Field(default_factory=list)
    reasonings: list[str] = Field(default_factory=list)
    query_interpretation: str = ""
