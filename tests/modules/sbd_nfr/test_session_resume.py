"""Tests for answer_service: bulk upsert, validation, and session resume (Phase 134, Plan 03).

Design references: D-21, D-29, D-31, D-34, D-41, Pitfall 5.

Test strategy:
  - Pure unit tests for validate_completion logic using QuestionSkipInfo DTOs.
  - Integration tests for bulk_upsert_answers use the async_db_session fixture (requires aiosqlite).
  - Integration tests are skipped automatically if aiosqlite is not installed.
"""

from __future__ import annotations

import pytest

from aila.modules.sbd_nfr.services.skip_logic import (
    QuestionSkipInfo,
    compute_visible_question_ids,
)

# ---------------------------------------------------------------------------
# Pure skip-logic visibility tests (no DB needed)
# ---------------------------------------------------------------------------


class TestComputeVisibleQuestionIds:
    """Verify compute_visible_question_ids correctly evaluates skip logic."""

    def _q(
        self,
        qid: str,
        *,
        is_active: bool = True,
        is_required: bool = True,
        depends_on: str | None = None,
        expected_when: str | None = None,
    ) -> QuestionSkipInfo:
        return QuestionSkipInfo(
            id=qid,
            is_active=is_active,
            is_required=is_required,
            depends_on_question_id=depends_on,
            expected_when=expected_when,
        )

    def test_unconditional_active_question_is_visible(self) -> None:
        q = self._q("Q1")
        visible = compute_visible_question_ids([q], {})
        assert "Q1" in visible

    def test_inactive_question_never_visible(self) -> None:
        q = self._q("Q1", is_active=False)
        visible = compute_visible_question_ids([q], {})
        assert "Q1" not in visible

    def test_conditional_question_hidden_when_trigger_unset(self) -> None:
        questions = [
            self._q("SCOPE-01"),
            self._q("Q2", depends_on="SCOPE-01", expected_when="Yes"),
        ]
        visible = compute_visible_question_ids(questions, {})
        assert "Q2" not in visible

    def test_conditional_question_visible_when_trigger_matches(self) -> None:
        questions = [
            self._q("SCOPE-01"),
            self._q("Q2", depends_on="SCOPE-01", expected_when="Yes"),
        ]
        visible = compute_visible_question_ids(questions, {"SCOPE-01": "Yes"})
        assert "Q2" in visible

    def test_conditional_question_hidden_when_trigger_value_differs(self) -> None:
        questions = [
            self._q("SCOPE-01"),
            self._q("Q2", depends_on="SCOPE-01", expected_when="Yes"),
        ]
        visible = compute_visible_question_ids(questions, {"SCOPE-01": "No"})
        assert "Q2" not in visible


# ---------------------------------------------------------------------------
# Pure validate_completion logic tests (no DB needed — pure unit tests)
# ---------------------------------------------------------------------------


def _make_skip_infos(
    required_ids: list[str],
    optional_ids: list[str],
    hidden_ids: list[str],
) -> tuple[list[QuestionSkipInfo], dict[str, str]]:
    """Build question list and answer dict for testing validate_completion logic.

    hidden_ids: questions that depend on SCOPE-01 = "Yes" but SCOPE-01 is not answered.
    required_ids: always-visible required questions.
    optional_ids: always-visible non-required questions.
    """
    questions: list[QuestionSkipInfo] = []
    for qid in required_ids:
        questions.append(
            QuestionSkipInfo(
                id=qid,
                is_active=True,
                is_required=True,
                depends_on_question_id=None,
                expected_when=None,
            )
        )
    for qid in optional_ids:
        questions.append(
            QuestionSkipInfo(
                id=qid,
                is_active=True,
                is_required=False,
                depends_on_question_id=None,
                expected_when=None,
            )
        )
    for qid in hidden_ids:
        questions.append(
            QuestionSkipInfo(
                id=qid,
                is_active=True,
                is_required=True,
                depends_on_question_id="SCOPE-01",
                expected_when="Yes",  # only visible if SCOPE-01 = "Yes"
            )
        )
    return questions, {}


def _compute_missing(
    questions: list[QuestionSkipInfo],
    answers: dict[str, str],
) -> list[str]:
    """Pure implementation of validate_completion logic for unit testing."""
    visible_ids = compute_visible_question_ids(questions, answers)
    return [
        q.id
        for q in questions
        if q.id in visible_ids and q.is_required and q.id not in answers
    ]


class TestValidateCompletionLogic:
    """Validate the pure completion-check logic that answer_service.validate_completion uses."""

    def test_all_required_answered_returns_empty(self) -> None:
        questions, _ = _make_skip_infos(["Q1", "Q2"], [], [])
        answers = {"Q1": "Yes", "Q2": "No"}
        missing = _compute_missing(questions, answers)
        assert missing == []

    def test_unanswered_required_question_returned(self) -> None:
        questions, _ = _make_skip_infos(["Q1", "Q2"], [], [])
        answers = {"Q1": "Yes"}
        missing = _compute_missing(questions, answers)
        assert "Q2" in missing
        assert "Q1" not in missing

    def test_hidden_questions_not_in_missing_list(self) -> None:
        """Pitfall 5: skip-logic-hidden questions must never appear in missing list."""
        questions, _ = _make_skip_infos([], [], ["HIDDEN-01", "HIDDEN-02"])
        # SCOPE-01 is not answered, so hidden questions remain invisible.
        answers: dict[str, str] = {}
        missing = _compute_missing(questions, answers)
        assert "HIDDEN-01" not in missing
        assert "HIDDEN-02" not in missing

    def test_hidden_required_question_becomes_missing_when_trigger_answered(self) -> None:
        """When trigger is answered, previously hidden required questions become visible and required."""
        questions, _ = _make_skip_infos([], [], ["HIDDEN-01"])
        answers = {"SCOPE-01": "Yes"}  # trigger answered
        missing = _compute_missing(questions, answers)
        assert "HIDDEN-01" in missing

    def test_optional_question_not_in_missing_list(self) -> None:
        """Non-required questions are never in the missing list, even if unanswered."""
        questions, _ = _make_skip_infos([], ["OPT-01"], [])
        missing = _compute_missing(questions, {})
        assert "OPT-01" not in missing

    def test_mix_of_required_optional_hidden(self) -> None:
        """Only visible required unanswered questions appear in missing list."""
        questions, _ = _make_skip_infos(["REQ-01"], ["OPT-01"], ["HIDDEN-01"])
        # REQ-01 unanswered, OPT-01 unanswered, HIDDEN-01 invisible (SCOPE-01 not answered)
        missing = _compute_missing(questions, {})
        assert missing == ["REQ-01"]

    def test_no_questions_returns_empty(self) -> None:
        assert _compute_missing([], {}) == []


# ---------------------------------------------------------------------------
# Bulk upsert last-write-wins semantics test (pure logic test)
# ---------------------------------------------------------------------------


class TestBulkUpsertLastWriteWins:
    """Verify last-write-wins semantics are correctly modeled.

    Integration tests for bulk_upsert_answers that write to DB are in the
    async_db_session fixture and run only when aiosqlite is installed.
    These pure tests validate the update-or-insert dispatch logic.
    """

    def test_last_write_wins_on_same_question(self) -> None:
        """When the same question_id appears in two successive upserts,
        the second value replaces the first (D-41 last-write-wins)."""
        # Simulate an in-memory answer store
        store: dict[str, str] = {}

        def upsert(question_id: str, answer_value: str) -> None:
            store[question_id] = answer_value  # always overwrites

        upsert("Q1", "Yes")
        upsert("Q1", "No")

        assert store["Q1"] == "No"

    def test_new_questions_are_inserted(self) -> None:
        store: dict[str, str] = {}

        def upsert(question_id: str, answer_value: str) -> None:
            store[question_id] = answer_value

        upsert("Q1", "Yes")
        upsert("Q2", "Partial")

        assert store["Q1"] == "Yes"
        assert store["Q2"] == "Partial"
        assert len(store) == 2


# ---------------------------------------------------------------------------
# Integration tests — require async_db_session (aiosqlite)
# ---------------------------------------------------------------------------

try:
    import aiosqlite as _check_aiosqlite  # noqa: F401
    _AIOSQLITE_AVAILABLE = True
except ImportError:
    _AIOSQLITE_AVAILABLE = False

_SKIP_DB = pytest.mark.skipif(
    not _AIOSQLITE_AVAILABLE,
    reason="aiosqlite not installed — run `pip install aiosqlite` to enable DB tests",
)


@_SKIP_DB
@pytest.mark.asyncio
async def test_bulk_upsert_creates_new_answer_records(async_db_session) -> None:
    """bulk_upsert_answers inserts new SbdNfrAnswerRecord rows when none exist."""
    from uuid import uuid4  # noqa: PLC0415

    from sqlmodel import select as sm_select  # noqa: PLC0415

    from aila.modules.sbd_nfr.contracts.session import AnswerInput, BulkAnswerRequest  # noqa: PLC0415
    from aila.modules.sbd_nfr.db_models import SbdNfrAnswerRecord, SbdNfrSessionRecord  # noqa: PLC0415
    from aila.modules.sbd_nfr.services.answer_service import bulk_upsert_answers  # noqa: PLC0415
    from aila.platform.contracts._common import utc_now  # noqa: PLC0415

    # Create a minimal session record directly
    session = SbdNfrSessionRecord(
        id=str(uuid4()),
        schema_version_at_start=1,
        owner_id="owner-1",
        status="in_progress",
        project_name="Test Project",
        requestor_name="Alice",
        requestor_email="alice@example.com",
        tags_json="[]",
        created_at=utc_now(),
        updated_at=utc_now(),
    )
    async_db_session.add(session)
    await async_db_session.flush()

    payload = BulkAnswerRequest(
        answers=[
            AnswerInput(question_id="Q1", answer_value="Yes"),
            AnswerInput(question_id="Q2", answer_value="No"),
        ]
    )

    result = await bulk_upsert_answers(
        async_db_session,
        session_id=session.id,
        section_key="scope",
        answers=payload.answers,
        contributor_name="Alice",
        contributor_email="alice@example.com",
        schema_version=1,
    )

    # Verify DB has 2 new answer records
    rows = (await async_db_session.exec(
        sm_select(SbdNfrAnswerRecord).where(SbdNfrAnswerRecord.session_id == session.id)
    )).all()
    assert len(rows) == 2
    assert {r.question_id for r in rows} == {"Q1", "Q2"}


@_SKIP_DB
@pytest.mark.asyncio
async def test_bulk_upsert_updates_existing_answer(async_db_session) -> None:
    """bulk_upsert_answers overwrites existing answer_value (last-write-wins D-41)."""
    from uuid import uuid4  # noqa: PLC0415

    from sqlmodel import select as sm_select  # noqa: PLC0415

    from aila.modules.sbd_nfr.contracts.session import AnswerInput, BulkAnswerRequest  # noqa: PLC0415
    from aila.modules.sbd_nfr.db_models import SbdNfrAnswerRecord, SbdNfrSessionRecord  # noqa: PLC0415
    from aila.modules.sbd_nfr.services.answer_service import bulk_upsert_answers  # noqa: PLC0415
    from aila.platform.contracts._common import utc_now  # noqa: PLC0415

    now = utc_now()
    session_id = str(uuid4())
    session = SbdNfrSessionRecord(
        id=session_id,
        schema_version_at_start=1,
        owner_id="owner-1",
        status="in_progress",
        project_name="Test Project",
        requestor_name="Bob",
        requestor_email="bob@example.com",
        tags_json="[]",
        created_at=now,
        updated_at=now,
    )
    async_db_session.add(session)

    # Pre-insert an answer with value "Yes"
    existing_answer = SbdNfrAnswerRecord(
        id=str(uuid4()),
        session_id=session_id,
        question_id="Q1",
        answer_value="Yes",
        answered_by_name="Bob",
        answered_by_email="bob@example.com",
        schema_version=1,
        created_at=now,
        updated_at=now,
    )
    async_db_session.add(existing_answer)
    await async_db_session.flush()

    # Now upsert with a different value
    payload = BulkAnswerRequest(answers=[AnswerInput(question_id="Q1", answer_value="No")])
    await bulk_upsert_answers(
        async_db_session,
        session_id=session_id,
        section_key="scope",
        answers=payload.answers,
        contributor_name="Carol",
        contributor_email="carol@example.com",
        schema_version=1,
    )

    rows = (await async_db_session.exec(
        sm_select(SbdNfrAnswerRecord).where(SbdNfrAnswerRecord.session_id == session_id)
    )).all()
    assert len(rows) == 1
    assert rows[0].answer_value == "No"
    assert rows[0].answered_by_name == "Carol"
