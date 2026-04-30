"""Tests for the SbD NFR resolution service.

After plan 185-04, run_resolution() manages its own UnitOfWork internally.
Integration tests seed real PostgreSQL data and mock only AilaLLMClient.

No mocking of UnitOfWork, AsyncSession, or async_session_scope.
ConfigRegistry/SecretStore are mocked to avoid reading from prod config.
AilaLLMClient is mocked to avoid real LLM calls.

Pure model tests and prompt-builder tests require no DB.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from aila.modules.sbd_nfr.contracts.resolution import (
    AssistRequest,
    AssistResponse,
    ComponentClassification,
    ResolutionResponse,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _make_session(
    session_id: str = "sess-001",
    status: str = "resolving",
    project_name: str = "Test Project",
) -> MagicMock:
    s = MagicMock()
    s.id = session_id
    s.status = status
    s.project_name = project_name
    s.description = "A test project"
    s.business_unit = "Engineering"
    s.requestor_name = "Alice"
    s.requestor_email = "alice@example.com"
    s.resolution_error = None
    s.resolution_json = None
    return s


def _make_subtask(key: str, label: str, description: str = "") -> MagicMock:
    st = MagicMock()
    st.key = key
    st.label = label
    st.description = description
    return st


def _make_answer(question_id: str, answer_value: str) -> MagicMock:
    a = MagicMock()
    a.question_id = question_id
    a.answer_value = answer_value
    return a


def _make_question(question_id: str, label: str) -> MagicMock:
    q = MagicMock()
    q.id = question_id
    q.label = label
    q.answer_type = "compliance"
    q.help_text = "Helpful guidance"
    q.instruction = "Answer carefully"
    q.section_id = "sec-001"
    return q


def _make_map_record(question_id: str, subtask_key: str) -> MagicMock:
    m = MagicMock()
    m.question_id = question_id
    m.subtask_key = subtask_key
    return m


def _make_llm_response_with_components(
    subtask_keys: list[str],
    classification: str = "triggered",
    confidence: float = 0.9,
) -> MagicMock:
    """Build a mock LLMResponse whose .content is valid ResolutionResponse JSON."""
    components = [
        ComponentClassification(
            subtask_key=key,
            classification=classification,
            confidence=confidence,
            reasoning=f"Reasoning for {key}",
            cited_question_ids=["Q-01"],
        )
        for key in subtask_keys
    ]
    data = ResolutionResponse(
        components=components,
        executive_summary="Overall assessment complete.",
    )
    resp = MagicMock()
    resp.disabled = False
    resp.content = data.model_dump_json()
    return resp


# ---------------------------------------------------------------------------
# Tests: ComponentClassification model
# ---------------------------------------------------------------------------


class TestComponentClassification:
    def test_all_fields_have_defaults(self):
        """All fields must have non-None defaults for OpenAI strict mode."""
        cc = ComponentClassification()
        assert cc.subtask_key == ""
        assert cc.classification == "uncertain"
        assert cc.confidence == 0.0
        assert cc.reasoning == ""
        assert cc.cited_question_ids == []

    def test_literal_classification_values(self):
        """classification field accepts only the three Literal values."""
        for valid in ("triggered", "not_triggered", "uncertain"):
            cc = ComponentClassification(classification=valid)
            assert cc.classification == valid

    def test_invalid_classification_rejected(self):
        """classification field rejects values outside the Literal set."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            ComponentClassification(classification="maybe")

    def test_confidence_range(self):
        """confidence must be between 0.0 and 1.0."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            ComponentClassification(confidence=1.5)
        with pytest.raises(ValidationError):
            ComponentClassification(confidence=-0.1)


class TestResolutionResponse:
    def test_empty_defaults(self):
        r = ResolutionResponse()
        assert r.components == []
        assert r.executive_summary == ""

    def test_round_trip_json(self):
        """ResolutionResponse survives model_dump_json() -> model_validate_json()."""
        components = [
            ComponentClassification(
                subtask_key="network_security",
                classification="triggered",
                confidence=0.95,
                reasoning="Strong signals found",
                cited_question_ids=["SCOPE-01", "HYGN-03"],
            )
        ]
        original = ResolutionResponse(
            components=components,
            executive_summary="Test summary",
        )
        serialized = original.model_dump_json()
        restored = ResolutionResponse.model_validate_json(serialized)
        assert len(restored.components) == 1
        assert restored.components[0].subtask_key == "network_security"
        assert restored.components[0].confidence == 0.95
        assert restored.executive_summary == "Test summary"


# ---------------------------------------------------------------------------
# Tests: resolution_service module constants and imports
# ---------------------------------------------------------------------------


class TestResolutionServiceImports:
    def test_module_imports_cleanly(self):
        from aila.modules.sbd_nfr.services import resolution_service
        assert hasattr(resolution_service, "run_resolution")
        assert hasattr(resolution_service, "get_resolution_results")
        assert hasattr(resolution_service, "CONFIDENCE_THRESHOLD")

    def test_confidence_threshold_value(self):
        from aila.modules.sbd_nfr.services.resolution_service import CONFIDENCE_THRESHOLD
        assert CONFIDENCE_THRESHOLD == 0.7

    def test_run_resolution_is_async(self):
        """run_resolution must be an async coroutine function."""
        import inspect
        from aila.modules.sbd_nfr.services.resolution_service import run_resolution
        assert inspect.iscoroutinefunction(run_resolution), (
            "run_resolution must be async def so ARQ workers can call it directly"
        )

    def test_get_resolution_results_is_async(self):
        import inspect
        from aila.modules.sbd_nfr.services.resolution_service import get_resolution_results
        assert inspect.iscoroutinefunction(get_resolution_results)


# ---------------------------------------------------------------------------
# Tests: confidence threshold reclassification
# ---------------------------------------------------------------------------


class TestConfidenceThreshold:
    def test_below_threshold_reclassified_as_uncertain(self):
        """Confidence < 0.7 on a triggered classification must become uncertain."""
        from aila.modules.sbd_nfr.services.resolution_service import (
            CONFIDENCE_THRESHOLD,
            _apply_confidence_threshold,
        )
        components = [
            ComponentClassification(
                subtask_key="network_security",
                classification="triggered",
                confidence=0.5,
                reasoning="Weak signal",
                cited_question_ids=["Q-01"],
            )
        ]
        result = _apply_confidence_threshold(components, CONFIDENCE_THRESHOLD)
        assert result[0].classification == "uncertain"

    def test_above_threshold_unchanged(self):
        """Confidence >= 0.7 must not be changed."""
        from aila.modules.sbd_nfr.services.resolution_service import (
            CONFIDENCE_THRESHOLD,
            _apply_confidence_threshold,
        )
        components = [
            ComponentClassification(
                subtask_key="network_security",
                classification="triggered",
                confidence=0.8,
                reasoning="Strong signal",
                cited_question_ids=["Q-01"],
            )
        ]
        result = _apply_confidence_threshold(components, CONFIDENCE_THRESHOLD)
        assert result[0].classification == "triggered"

    def test_already_uncertain_stays_uncertain(self):
        """Already-uncertain classification is not changed by threshold."""
        from aila.modules.sbd_nfr.services.resolution_service import (
            CONFIDENCE_THRESHOLD,
            _apply_confidence_threshold,
        )
        components = [
            ComponentClassification(
                subtask_key="network_security",
                classification="uncertain",
                confidence=0.3,
                reasoning="No signal",
                cited_question_ids=[],
            )
        ]
        result = _apply_confidence_threshold(components, CONFIDENCE_THRESHOLD)
        assert result[0].classification == "uncertain"

    def test_not_triggered_below_threshold_reclassified(self):
        """not_triggered below threshold also becomes uncertain."""
        from aila.modules.sbd_nfr.services.resolution_service import (
            CONFIDENCE_THRESHOLD,
            _apply_confidence_threshold,
        )
        components = [
            ComponentClassification(
                subtask_key="network_security",
                classification="not_triggered",
                confidence=0.4,
                reasoning="Unclear",
                cited_question_ids=[],
            )
        ]
        result = _apply_confidence_threshold(components, CONFIDENCE_THRESHOLD)
        assert result[0].classification == "uncertain"


# ---------------------------------------------------------------------------
# Tests: prompt building helpers
# ---------------------------------------------------------------------------


class TestPromptBuilders:
    def test_build_system_prompt_contains_subtask_key(self):
        from aila.modules.sbd_nfr.services.resolution_service import _build_system_prompt
        subtasks = [_make_subtask("network_security", "Network Security", "Desc")]
        mapping_by_subtask = {"network_security": ["Q-01", "Q-02"]}
        session = _make_session()
        scope_answers = [("What is scope?", "Q-01", "New service")]
        prompt = _build_system_prompt(subtasks, mapping_by_subtask, session, scope_answers)
        assert "network_security" in prompt
        assert "Network Security" in prompt

    def test_build_user_message_format(self):
        from aila.modules.sbd_nfr.services.resolution_service import _build_user_message
        answered = [("Label A", "Q-01", "Yes"), ("Label B", "Q-02", "No")]
        msg = _build_user_message(answered)
        assert "Q-01" in msg
        assert "Q-02" in msg
        assert "Label A" in msg
        assert "Yes" in msg


# ---------------------------------------------------------------------------
# Real 25 subtask keys from seed_subtasks.json
# ---------------------------------------------------------------------------

_REAL_SUBTASK_KEYS: list[str] = [
    "access_point_integration",
    "application_logging",
    "archer_inventory_update",
    "arcsight_new_update_alert_request",
    "container_native_firewall",
    "container_security_scan",
    "cyberark_epm",
    "dast",
    "database_logging",
    "file_integrity_monitoring_integration",
    "network_segment_placement",
    "onetrust_supplier_security_assesment",
    "operating_system_logging_unix",
    "operating_system_logging_windows",
    "penetration_testing",
    "privileged_user_access_management_integrations_cyberark",
    "proxy_definition",
    "risk_assesment",
    "sast",
    "scs",
    "secure_by_design_assesment",
    "software_composition_analysis_sca",
    "vulnerability_scan_tenable",
    "waf_integration",
    "web_certificate_request",
]


# ---------------------------------------------------------------------------
# DB seed helpers for integration tests
# ---------------------------------------------------------------------------


async def _seed_resolution_data(
    db,
    session_id: str,
    subtask_keys: list[str] | None = None,
    answer_count: int = 3,
) -> None:
    """Seed a full set of records needed for run_resolution to proceed.

    Seeds:
    - SbdNfrSchemaVersionRecord (version 1)
    - SbdNfrSectionRecord
    - SbdNfrSubgroupRecord
    - SbdNfrQuestionRecord rows (answer_count questions)
    - SbdNfrAnswerRecord rows (one answer per question)
    - SbdNfrSubtaskComponentRecord rows (for all subtask_keys)
    - SbdNfrQuestionSubtaskMapRecord (maps Q-00 to first subtask key)
    - SbdNfrSessionRecord in "resolving" status
    """
    from aila.modules.sbd_nfr.db_models import (
        SbdNfrAnswerRecord,
        SbdNfrQuestionRecord,
        SbdNfrQuestionSubtaskMapRecord,
        SbdNfrSchemaVersionRecord,
        SbdNfrSectionRecord,
        SbdNfrSessionRecord,
        SbdNfrSubgroupRecord,
        SbdNfrSubtaskComponentRecord,
    )

    if subtask_keys is None:
        subtask_keys = _REAL_SUBTASK_KEYS

    # Schema version
    db.add(SbdNfrSchemaVersionRecord(
        id=str(uuid4()), version=1, change_summary="seed", changed_by="test",
    ))

    # Section
    section = SbdNfrSectionRecord(
        id=str(uuid4()),
        schema_version=1,
        section_key="scope",
        label="Project Scope",
        display_order=0,
        is_active=True,
    )
    db.add(section)

    # Subgroup
    sg = SbdNfrSubgroupRecord(
        id=str(uuid4()),
        schema_version=1,
        section_id=section.id,
        subgroup_key="deployment",
        label="Deployment",
        display_order=0,
        is_active=True,
    )
    db.add(sg)

    # Questions + answers
    question_ids = [f"Q-{i:02d}" for i in range(answer_count)]
    for q_id in question_ids:
        db.add(SbdNfrQuestionRecord(
            id=q_id,
            schema_version=1,
            subgroup_id=sg.id,
            section_id=section.id,
            question_type="scope",
            depth_level="standard",
            answer_type="compliance",
            label=f"Question {q_id}",
            is_required=True,
            is_active=True,
            display_order=0,
        ))

    # Session in "resolving" status
    db.add(SbdNfrSessionRecord(
        id=session_id,
        owner_id="test-user",
        status="resolving",
        project_name="Test Project",
        description="Integration test project",
        business_unit="Engineering",
        requestor_name="Test User",
        requestor_email="test@test.com",
        schema_version_at_start=1,
        share_token=f"share-{uuid4().hex[:8]}",
        tags_json="[]",
        created_at=_utc_now(),
        updated_at=_utc_now(),
    ))
    await db.flush()

    # Answers (inserted after session exists for FK integrity)
    for q_id in question_ids:
        db.add(SbdNfrAnswerRecord(
            id=str(uuid4()),
            session_id=session_id,
            question_id=q_id,
            answer_value="Yes",
            answered_by_name="Test User",
            answered_by_email="test@test.com",
            schema_version=1,
            updated_at=_utc_now(),
        ))

    # Subtask components
    for i, key in enumerate(subtask_keys):
        db.add(SbdNfrSubtaskComponentRecord(
            key=key,
            label=f"Label {key}",
            category="security",
            description=f"Description for {key}",
            display_order=i,
            is_active=True,
            created_at=_utc_now(),
            updated_at=_utc_now(),
        ))

    # Question-subtask mappings (map first question to first subtask key)
    if subtask_keys:
        db.add(SbdNfrQuestionSubtaskMapRecord(
            id=str(uuid4()),
            question_id=question_ids[0],
            subtask_key=subtask_keys[0],
            created_at=_utc_now(),
        ))

    await db.commit()


def _patch_llm_context(mock_llm_client: Any):
    """Return a context manager that patches AilaLLMClient only.

    All other dependencies (UnitOfWork, async_session_scope, ConfigRegistry,
    SecretStore) are NOT mocked — they use the real test DB.
    """
    import contextlib

    @contextlib.asynccontextmanager
    async def _ctx():
        with patch(
            "aila.modules.sbd_nfr.services.resolution_service.AilaLLMClient"
        ) as mock_cls:
            mock_cls.return_value = mock_llm_client
            yield

    return _ctx()


# ---------------------------------------------------------------------------
# Integration tests: run_resolution with real DB + mocked LLM
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_classify_all_subtasks(async_db_session):
    """RESOLVE-01: run_resolution classifies all 25 subtasks using mock LLM.

    Seeds real DB data. Calls run_resolution. Queries DB to verify 25 result
    rows were inserted.
    """
    from aila.modules.sbd_nfr.services import resolution_service
    from aila.modules.sbd_nfr.db_models import SbdNfrResolutionResultRecord
    from sqlmodel import select as sm_select

    session_id = f"sess-{uuid4().hex[:8]}"
    await _seed_resolution_data(async_db_session, session_id)

    llm_response = _make_llm_response_with_components(_REAL_SUBTASK_KEYS, confidence=0.9)
    mock_llm_client = AsyncMock()
    mock_llm_client.chat_structured = AsyncMock(return_value=llm_response)

    async with _patch_llm_context(mock_llm_client):
        await resolution_service.run_resolution(session_id)

    mock_llm_client.chat_structured.assert_called_once()

    # Verify 25 result rows in DB
    rows = (await async_db_session.exec(
        sm_select(SbdNfrResolutionResultRecord).where(
            SbdNfrResolutionResultRecord.session_id == session_id
        )
    )).all()
    assert len(rows) == 25


@pytest.mark.asyncio
async def test_cited_question_ids(async_db_session):
    """RESOLVE-02: resolved result records have non-empty cited_question_ids_json."""
    import json as _json
    from aila.modules.sbd_nfr.services import resolution_service
    from aila.modules.sbd_nfr.db_models import SbdNfrResolutionResultRecord
    from sqlmodel import select as sm_select

    session_id = f"sess-{uuid4().hex[:8]}"
    await _seed_resolution_data(async_db_session, session_id)

    llm_response = _make_llm_response_with_components(_REAL_SUBTASK_KEYS, confidence=0.9)
    mock_llm_client = AsyncMock()
    mock_llm_client.chat_structured = AsyncMock(return_value=llm_response)

    async with _patch_llm_context(mock_llm_client):
        await resolution_service.run_resolution(session_id)

    rows = (await async_db_session.exec(
        sm_select(SbdNfrResolutionResultRecord).where(
            SbdNfrResolutionResultRecord.session_id == session_id
        )
    )).all()
    assert len(rows) == 25
    for row in rows:
        cited = _json.loads(row.cited_question_ids_json)
        assert isinstance(cited, list)
        assert len(cited) >= 1


@pytest.mark.asyncio
async def test_uncertain_threshold(async_db_session):
    """RESOLVE-03: components with low confidence are reclassified to 'uncertain'.

    First subtask key has confidence=0.5 (below 0.7 threshold). Verifies the
    stored record for that key has classification='uncertain'.
    """
    from aila.modules.sbd_nfr.services import resolution_service
    from aila.modules.sbd_nfr.db_models import SbdNfrResolutionResultRecord
    from sqlmodel import select as sm_select

    session_id = f"sess-{uuid4().hex[:8]}"
    await _seed_resolution_data(async_db_session, session_id)

    # Build a response where the first key has low confidence
    components = [
        ComponentClassification(
            subtask_key=_REAL_SUBTASK_KEYS[0],
            classification="triggered",
            confidence=0.5,  # below 0.7 → should become uncertain
            reasoning="Weak signal",
            cited_question_ids=["Q-00"],
        )
    ] + [
        ComponentClassification(
            subtask_key=k,
            classification="triggered",
            confidence=0.9,
            reasoning=f"Strong signal for {k}",
            cited_question_ids=["Q-00"],
        )
        for k in _REAL_SUBTASK_KEYS[1:]
    ]
    resolution_data = ResolutionResponse(
        components=components,
        executive_summary="Test summary",
    )
    llm_response = MagicMock()
    llm_response.disabled = False
    llm_response.content = resolution_data.model_dump_json()

    mock_llm_client = AsyncMock()
    mock_llm_client.chat_structured = AsyncMock(return_value=llm_response)

    async with _patch_llm_context(mock_llm_client):
        await resolution_service.run_resolution(session_id)

    from sqlmodel import select as sm_select
    row = (await async_db_session.exec(
        sm_select(SbdNfrResolutionResultRecord).where(
            SbdNfrResolutionResultRecord.session_id == session_id,
            SbdNfrResolutionResultRecord.subtask_key == _REAL_SUBTASK_KEYS[0],
        )
    )).first()
    assert row is not None
    assert row.classification == "uncertain"


@pytest.mark.asyncio
async def test_uses_llm_client(async_db_session):
    """PLAT-02: run_resolution calls chat_structured with task_type='resolution'."""
    from aila.modules.sbd_nfr.services import resolution_service

    session_id = f"sess-{uuid4().hex[:8]}"
    await _seed_resolution_data(async_db_session, session_id)

    llm_response = _make_llm_response_with_components(_REAL_SUBTASK_KEYS, confidence=0.9)

    captured_calls: list = []

    async def capture_chat_structured(task_type, messages, model_class, **kwargs):
        captured_calls.append({
            "task_type": task_type,
            "model_class": model_class,
            "message_count": len(messages),
        })
        return llm_response

    mock_llm_client = AsyncMock()
    mock_llm_client.chat_structured = capture_chat_structured

    async with _patch_llm_context(mock_llm_client):
        await resolution_service.run_resolution(session_id)

    assert len(captured_calls) == 1
    assert captured_calls[0]["task_type"] == "resolution"
    assert captured_calls[0]["model_class"] == ResolutionResponse
    assert captured_calls[0]["message_count"] >= 2  # system + user


@pytest.mark.asyncio
async def test_retry_on_first_failure(async_db_session):
    """D-03: LLM raises on first call but succeeds on second (retry once).

    Verifies that a single transient LLM failure does not cause permanent
    resolution failure when MAX_RETRIES=1.
    """
    from aila.modules.sbd_nfr.services import resolution_service
    from aila.modules.sbd_nfr.db_models import SbdNfrSessionRecord
    from sqlmodel import select as sm_select

    session_id = f"sess-{uuid4().hex[:8]}"
    await _seed_resolution_data(async_db_session, session_id)

    llm_response = _make_llm_response_with_components(_REAL_SUBTASK_KEYS, confidence=0.9)
    call_count = [0]

    async def raise_then_succeed(*args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            raise RuntimeError("Transient LLM error")
        return llm_response

    mock_llm_client = AsyncMock()
    mock_llm_client.chat_structured = raise_then_succeed

    async with _patch_llm_context(mock_llm_client):
        await resolution_service.run_resolution(session_id)

    # Two calls: 1 initial fail + 1 retry success
    assert call_count[0] == 2

    # Session should be "resolved"
    session_row = (await async_db_session.exec(
        sm_select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id),
        execution_options={"populate_existing": True},
    )).first()
    assert session_row is not None
    assert session_row.status == "resolved"


@pytest.mark.asyncio
async def test_resolution_failed_on_double_failure(async_db_session):
    """D-03: Both LLM calls fail → session becomes resolution_failed."""
    from aila.modules.sbd_nfr.services import resolution_service
    from aila.modules.sbd_nfr.db_models import SbdNfrResolutionResultRecord, SbdNfrSessionRecord
    from sqlmodel import select as sm_select

    session_id = f"sess-{uuid4().hex[:8]}"
    await _seed_resolution_data(async_db_session, session_id)

    async def always_fail(*args, **kwargs):
        raise RuntimeError("Permanent LLM failure")

    mock_llm_client = AsyncMock()
    mock_llm_client.chat_structured = always_fail

    async with _patch_llm_context(mock_llm_client):
        await resolution_service.run_resolution(session_id)

    # No result rows added
    from sqlmodel import select as sm_select
    rows = (await async_db_session.exec(
        sm_select(SbdNfrResolutionResultRecord).where(
            SbdNfrResolutionResultRecord.session_id == session_id
        )
    )).all()
    assert len(rows) == 0

    # Session marked resolution_failed
    session_row = (await async_db_session.exec(
        sm_select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id),
        execution_options={"populate_existing": True},
    )).first()
    assert session_row is not None
    assert session_row.status == "resolution_failed"


@pytest.mark.asyncio
async def test_timeout_causes_failure(async_db_session):
    """D-04: LLM call that hangs causes TimeoutError → resolution_failed."""
    from aila.modules.sbd_nfr.services import resolution_service
    from aila.modules.sbd_nfr.db_models import SbdNfrSessionRecord
    from sqlmodel import select as sm_select

    session_id = f"sess-{uuid4().hex[:8]}"
    await _seed_resolution_data(async_db_session, session_id)

    async def slow_llm(*args, **kwargs):
        await asyncio.sleep(10)
        return _make_llm_response_with_components(_REAL_SUBTASK_KEYS)

    mock_llm_client = AsyncMock()
    mock_llm_client.chat_structured = slow_llm

    with patch(
        "aila.modules.sbd_nfr.services.resolution_service.LLM_TIMEOUT_SECONDS", 0.01
    ):
        async with _patch_llm_context(mock_llm_client):
            await resolution_service.run_resolution(session_id)

    from sqlmodel import select as sm_select
    session_row = (await async_db_session.exec(
        sm_select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id),
        execution_options={"populate_existing": True},
    )).first()
    assert session_row is not None
    assert session_row.status == "resolution_failed"


@pytest.mark.asyncio
async def test_replace_in_place(async_db_session):
    """D-12: Second resolution run replaces existing results (25 rows, not 50)."""
    from aila.modules.sbd_nfr.services import resolution_service
    from aila.modules.sbd_nfr.db_models import SbdNfrResolutionResultRecord, SbdNfrSessionRecord
    from sqlalchemy import update
    from sqlmodel import select as sm_select

    session_id = f"sess-{uuid4().hex[:8]}"
    await _seed_resolution_data(async_db_session, session_id)

    llm_response = _make_llm_response_with_components(_REAL_SUBTASK_KEYS, confidence=0.9)
    mock_llm_client = AsyncMock()
    mock_llm_client.chat_structured = AsyncMock(return_value=llm_response)

    # First resolution run
    async with _patch_llm_context(mock_llm_client):
        await resolution_service.run_resolution(session_id)

    # Reset to resolving for second run
    await async_db_session.exec(
        update(SbdNfrSessionRecord)
        .where(SbdNfrSessionRecord.id == session_id)
        .values(status="resolving")
    )
    await async_db_session.commit()

    # Second resolution run
    mock_llm_client.chat_structured = AsyncMock(return_value=llm_response)
    async with _patch_llm_context(mock_llm_client):
        await resolution_service.run_resolution(session_id)

    # Should still be exactly 25 rows (not 50)
    rows = (await async_db_session.exec(
        sm_select(SbdNfrResolutionResultRecord).where(
            SbdNfrResolutionResultRecord.session_id == session_id
        )
    )).all()
    assert len(rows) == 25


@pytest.mark.asyncio
async def test_golden_fixture_db_persistence(async_db_session):
    """D-22: Golden fixture JSON matches exactly what is stored in DB."""
    import json as _json
    from pathlib import Path
    from aila.modules.sbd_nfr.services import resolution_service
    from aila.modules.sbd_nfr.db_models import SbdNfrResolutionResultRecord
    from sqlmodel import select as sm_select

    # Load the golden fixture
    fixture_path = (
        Path(__file__).resolve().parent / "fixtures" / "golden_resolution_response.json"
    )
    fixture_data = _json.loads(fixture_path.read_text(encoding="utf-8"))
    assert len(fixture_data["components"]) == 25

    session_id = f"sess-{uuid4().hex[:8]}"
    await _seed_resolution_data(async_db_session, session_id)

    llm_response = MagicMock()
    llm_response.disabled = False
    llm_response.content = _json.dumps(fixture_data)

    mock_llm_client = AsyncMock()
    mock_llm_client.chat_structured = AsyncMock(return_value=llm_response)

    async with _patch_llm_context(mock_llm_client):
        await resolution_service.run_resolution(session_id)

    rows = (await async_db_session.exec(
        sm_select(SbdNfrResolutionResultRecord).where(
            SbdNfrResolutionResultRecord.session_id == session_id
        )
    )).all()
    assert len(rows) == 25

    fixture_by_key = {c["subtask_key"]: c for c in fixture_data["components"]}
    for row in rows:
        key = row.subtask_key
        assert key in fixture_by_key, f"Unexpected subtask_key in DB: {key}"
        expected = fixture_by_key[key]

        if expected["confidence"] >= 0.7:
            assert row.classification == expected["classification"], (
                f"Key {key}: classification mismatch"
            )

        assert abs(row.confidence - expected["confidence"]) < 0.001, (
            f"Key {key}: confidence mismatch"
        )
        assert row.reasoning == expected["reasoning"], (
            f"Key {key}: reasoning mismatch"
        )
        stored_ids = _json.loads(row.cited_question_ids_json)
        assert stored_ids == expected["cited_question_ids"], (
            f"Key {key}: cited_question_ids mismatch"
        )


# ---------------------------------------------------------------------------
# Tests: assist_service (import and async checks only — LLM mocked in separate file)
# ---------------------------------------------------------------------------


class TestAssistServiceImports:
    def test_module_imports_cleanly(self):
        from aila.modules.sbd_nfr.services import assist_service
        assert hasattr(assist_service, "handle_assist")

    def test_handle_assist_is_async(self):
        import inspect
        from aila.modules.sbd_nfr.services.assist_service import handle_assist
        assert inspect.iscoroutinefunction(handle_assist)


@pytest.mark.asyncio
async def test_auto_retry_fires_once_before_failure(async_db_session):
    """D-03: LLM call should be retried once (MAX_RETRIES=1) before giving up."""
    from aila.modules.sbd_nfr.services import resolution_service
    from aila.modules.sbd_nfr.services.resolution_service import MAX_RETRIES

    assert MAX_RETRIES == 1

    session_id = f"sess-{uuid4().hex[:8]}"
    await _seed_resolution_data(async_db_session, session_id)

    llm_call_count = [0]

    async def failing_chat_structured(*a, **kw):
        llm_call_count[0] += 1
        raise RuntimeError("Transient error")

    mock_llm_client = AsyncMock()
    mock_llm_client.chat_structured = failing_chat_structured

    async with _patch_llm_context(mock_llm_client):
        await resolution_service.run_resolution(session_id)

    # Should have been called 1 initial + 1 retry = 2 total
    assert llm_call_count[0] == 2
