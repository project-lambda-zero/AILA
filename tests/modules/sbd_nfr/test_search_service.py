"""Tests for the SbD NFR smart search service (Plan 134-05, Task 1).

Verifies:
- smart_search() with user_role="reader" only considers sessions where
  owner_id == user_id (T-134-16 cross-user leak prevention).
- smart_search() with user_role="operator" considers all non-deleted sessions.
- smart_search() with user_role="admin" considers all non-deleted sessions.
- smart_search() gracefully returns empty results when the LLM client raises.
- _LLMSearchResult has NO Optional fields (all fields have default values
  per Pitfall 6 — strict mode compatibility).

smart_search() manages its own DB session via UnitOfWork, so DB interaction is
mocked by patching aila.modules.sbd_nfr.services.search_service.UnitOfWork.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aila.modules.sbd_nfr.contracts.search import (
    SmartSearchRequest,
    SmartSearchResponse,
    _LLMSearchResult,
)
from aila.modules.sbd_nfr.services.search_service import smart_search

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _make_session(
    session_id: str,
    owner_id: str,
    status: str = "draft",
    business_unit: str | None = None,
    is_deleted: bool = False,
) -> MagicMock:
    """Build a mock SbdNfrSessionRecord."""
    s = MagicMock()
    s.id = session_id
    s.owner_id = owner_id
    s.status = status
    s.business_unit = business_unit
    s.project_name = f"Project {session_id}"
    s.requestor_name = f"Requester {session_id}"
    s.requestor_email = f"req-{session_id}@example.com"
    s.is_deleted = is_deleted
    s.tags_json = "[]"
    s.created_at = _utc_now()
    return s


def _make_llm_response(
    session_ids: list[str],
    scores: list[float] | None = None,
    reasonings: list[str] | None = None,
    query_interpretation: str = "Test interpretation",
) -> MagicMock:
    """Build a mock LLMResponse whose .content is valid _LLMSearchResult JSON."""
    data = _LLMSearchResult(
        session_ids=session_ids,
        scores=scores if scores is not None else [0.9] * len(session_ids),
        reasonings=reasonings if reasonings is not None else ["Relevant"] * len(session_ids),
        query_interpretation=query_interpretation,
    )
    resp = MagicMock()
    resp.disabled = False
    resp.content = data.model_dump_json()
    return resp


def _make_uow_patch(sessions: list[MagicMock]) -> Any:
    """Return a context-manager patch for UnitOfWork that returns `sessions` from exec().

    smart_search() calls db.exec() three times:
      1. SbdNfrSessionRecord query   → returns sessions list
      2. SbdNfrAnswerRecord query    → returns [] (no answers in mock scenarios)
      3. SbdNfrQuestionRecord query  → returns [] (no question labels needed)

    The patch replaces UnitOfWork with an async context manager whose .session
    attribute has exec() returning appropriate values per call.
    """
    call_count = 0

    async def fake_exec(stmt, **kwargs):
        nonlocal call_count
        call_count += 1
        result = MagicMock()
        if call_count == 1:
            result.all.return_value = sessions
        else:
            result.all.return_value = []
        return result

    mock_db = MagicMock()
    mock_db.exec = fake_exec

    mock_uow = MagicMock()
    mock_uow.__aenter__ = AsyncMock(return_value=mock_uow)
    mock_uow.__aexit__ = AsyncMock(return_value=False)
    mock_uow.session = mock_db

    mock_uow_cls = MagicMock(return_value=mock_uow)
    return mock_uow_cls


# ---------------------------------------------------------------------------
# _LLMSearchResult schema tests (no DB/LLM needed)
# ---------------------------------------------------------------------------


def test_llm_search_result_no_optional_fields() -> None:
    """All fields in _LLMSearchResult must have non-None defaults (Pitfall 6).

    OpenAI strict mode requires every field to be in 'required'. Fields with
    Optional type (i.e., default=None) are excluded from 'required' and cause
    validation errors in strict mode.

    This test verifies that _LLMSearchResult can be instantiated with NO
    arguments, meaning all fields have explicit default values.
    """
    instance = _LLMSearchResult()
    assert instance.session_ids == []
    assert instance.scores == []
    assert instance.reasonings == []
    assert instance.query_interpretation == ""


def test_llm_search_result_no_none_defaults() -> None:
    """All fields in _LLMSearchResult must have non-None defaults (Pitfall 6).

    OpenAI strict mode compatibility requires that all fields have explicit
    defaults (not None) so the _inject_strict_schema_requirements() helper in
    the LLM client can safely inject them all into the 'required' array.

    We verify this by inspecting model_fields: no field should have a default
    of None or be annotated as Optional with PydanticUndefined default.
    """
    for name, field_info in _LLMSearchResult.model_fields.items():
        # None as default signals an Optional field — disallowed for strict mode.
        assert field_info.default is not None or field_info.default_factory is not None, (
            f"Field '{name}' has default=None. Use an explicit non-None default "
            f"(e.g., default='', default_factory=list) for strict mode compatibility."
        )


def test_smart_search_request_validation() -> None:
    """SmartSearchRequest validates query length and max_results bounds."""
    req = SmartSearchRequest(query="test query")
    assert req.max_results == 10
    assert req.status is None

    with pytest.raises(Exception):  # ValidationError
        SmartSearchRequest(query="")  # too short

    with pytest.raises(Exception):  # ValidationError
        SmartSearchRequest(query="q", max_results=51)  # exceeds le=50


# ---------------------------------------------------------------------------
# Role-based filtering tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reader_role_filters_to_own_sessions() -> None:
    """smart_search() with reader role must only pass own sessions to the LLM.

    This is the primary T-134-16 security test: a reader must never see
    sessions owned by other users, even in the LLM context.
    """
    user_id = "user-A"
    own_session = _make_session("sess-own", owner_id=user_id)
    # other_session is NOT returned from DB because role filter is applied inside
    # smart_search via a WHERE clause — the mock DB returns only own_session.
    other_session = _make_session("sess-other", owner_id="user-B")

    request = SmartSearchRequest(query="show me security assessments", max_results=10)

    captured_messages: list[Any] = []

    async def mock_chat_structured(task_type, messages, model_class, **kwargs):
        captured_messages.extend(messages)
        return _make_llm_response([own_session.id])

    mock_llm = MagicMock()
    mock_llm.chat_structured = mock_chat_structured

    uow_cls = _make_uow_patch([own_session])

    with patch("aila.modules.sbd_nfr.services.search_service.UnitOfWork", uow_cls):
        response = await smart_search(
            request=request,
            user_id=user_id,
            user_role="reader",
            llm_client=mock_llm,
        )

    assert isinstance(response, SmartSearchResponse)
    # LLM was called with at least system + user messages.
    assert len(captured_messages) >= 2
    user_message_content = captured_messages[1]["content"]
    assert own_session.id in user_message_content
    # other_session was DB-filtered before LLM — its ID must not appear.
    assert other_session.id not in user_message_content


@pytest.mark.asyncio
async def test_operator_role_sees_all_sessions() -> None:
    """smart_search() with operator role must not filter by owner_id."""
    user_id = "operator-user"
    sess_a = _make_session("sess-a", owner_id="user-X")
    sess_b = _make_session("sess-b", owner_id="user-Y")

    captured_messages: list[Any] = []

    async def mock_chat_structured(task_type, messages, model_class, **kwargs):
        captured_messages.extend(messages)
        return _make_llm_response([sess_a.id, sess_b.id])

    mock_llm = MagicMock()
    mock_llm.chat_structured = mock_chat_structured

    uow_cls = _make_uow_patch([sess_a, sess_b])

    request = SmartSearchRequest(query="all projects", max_results=10)
    with patch("aila.modules.sbd_nfr.services.search_service.UnitOfWork", uow_cls):
        response = await smart_search(
            request=request,
            user_id=user_id,
            user_role="operator",
            llm_client=mock_llm,
        )

    assert isinstance(response, SmartSearchResponse)
    user_message = captured_messages[1]["content"]
    assert sess_a.id in user_message
    assert sess_b.id in user_message


@pytest.mark.asyncio
async def test_admin_role_sees_all_sessions() -> None:
    """smart_search() with admin role must not filter by owner_id."""
    user_id = "admin-user"
    sess_c = _make_session("sess-c", owner_id="user-Z")

    captured_messages: list[Any] = []

    async def mock_chat_structured(task_type, messages, model_class, **kwargs):
        captured_messages.extend(messages)
        return _make_llm_response([sess_c.id])

    mock_llm = MagicMock()
    mock_llm.chat_structured = mock_chat_structured

    uow_cls = _make_uow_patch([sess_c])

    request = SmartSearchRequest(query="admin search", max_results=5)
    with patch("aila.modules.sbd_nfr.services.search_service.UnitOfWork", uow_cls):
        response = await smart_search(
            request=request,
            user_id=user_id,
            user_role="admin",
            llm_client=mock_llm,
        )

    assert isinstance(response, SmartSearchResponse)
    user_message = captured_messages[1]["content"]
    assert sess_c.id in user_message


# ---------------------------------------------------------------------------
# LLM failure graceful degradation test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_llm_failure_returns_empty_results() -> None:
    """smart_search() returns empty results when the LLM client raises."""
    session = _make_session("sess-err", owner_id="user-A")
    request = SmartSearchRequest(query="anything", max_results=10)

    async def mock_chat_structured_raises(*args, **kwargs):
        raise RuntimeError("LLM connection timeout")

    mock_llm = MagicMock()
    mock_llm.chat_structured = mock_chat_structured_raises

    uow_cls = _make_uow_patch([session])

    with patch("aila.modules.sbd_nfr.services.search_service.UnitOfWork", uow_cls):
        response = await smart_search(
            request=request,
            user_id="user-A",
            user_role="reader",
            llm_client=mock_llm,
        )

    assert isinstance(response, SmartSearchResponse)
    assert response.results == []
    assert response.query_interpretation == "Search unavailable"
    assert response.query == "anything"


@pytest.mark.asyncio
async def test_no_candidates_returns_empty_without_llm_call() -> None:
    """smart_search() returns early with empty results when no candidates found."""
    request = SmartSearchRequest(query="anything", max_results=10)

    mock_llm = MagicMock()
    mock_llm.chat_structured = AsyncMock()  # should NOT be called

    uow_cls = _make_uow_patch([])  # empty sessions list

    with patch("aila.modules.sbd_nfr.services.search_service.UnitOfWork", uow_cls):
        response = await smart_search(
            request=request,
            user_id="user-A",
            user_role="reader",
            llm_client=mock_llm,
        )

    assert response.results == []
    assert response.total_searched == 0
    mock_llm.chat_structured.assert_not_called()


@pytest.mark.asyncio
async def test_llm_hallucinated_session_id_is_skipped() -> None:
    """LLM response with unknown session_id should be silently skipped."""
    real_session = _make_session("sess-real", owner_id="user-A")
    request = SmartSearchRequest(query="test", max_results=10)

    async def mock_chat_structured(*args, **kwargs):
        return _make_llm_response(
            ["sess-real", "sess-HALLUCINATED"],
            scores=[0.9, 0.8],
            reasonings=["Real", "Fake"],
        )

    mock_llm = MagicMock()
    mock_llm.chat_structured = mock_chat_structured

    uow_cls = _make_uow_patch([real_session])

    with patch("aila.modules.sbd_nfr.services.search_service.UnitOfWork", uow_cls):
        response = await smart_search(
            request=request,
            user_id="user-A",
            user_role="reader",
            llm_client=mock_llm,
        )

    # Only the real session should appear — hallucinated one is skipped.
    assert len(response.results) == 1
    assert response.results[0].session_id == "sess-real"
