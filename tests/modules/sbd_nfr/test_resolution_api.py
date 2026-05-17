"""Integration tests for SbD NFR resolution API handler functions.

After plan 185-04, all router handlers manage their own DB sessions via
UnitOfWork internally. Tests insert real DB records via async_db_session,
then call the handler functions directly with real AuthContext objects.

No mocking of UnitOfWork, AsyncSession, or async_session_scope.
TaskQueue.submit is mocked (external infrastructure, not business logic).
AilaLLMClient is mocked for resolution-involving tests.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from aila.modules.sbd_nfr.contracts.resolution import (
    AssistRequest,
    AssistResponse,
    ResolutionResultResponse,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _make_auth_context(
    user_id: str = "user-001",
    role: str = "operator",
) -> object:
    """Build a simple auth context object with user_id and role."""
    ctx = MagicMock()
    ctx.user_id = user_id
    ctx.role = role
    ctx.auth_type = "api_key"
    return ctx


def _make_request() -> object:
    """Build a lightweight request stub for direct handler calls."""
    request = MagicMock()
    request.app.state.platform = MagicMock()
    return request


async def _seed_session(
    db,
    session_id: str = "sess-001",
    owner_id: str = "user-001",
    status: str = "resolution_failed",
    is_deleted: bool = False,
    resolution_json: str | None = None,
) -> object:
    """Insert a real SbdNfrSessionRecord into the test DB."""
    from aila.modules.sbd_nfr.db_models import SbdNfrSessionRecord

    record = SbdNfrSessionRecord(
        id=session_id,
        owner_id=owner_id,
        status=status,
        is_deleted=is_deleted,
        project_name="Test Project",
        description="A test project",
        business_unit="Engineering",
        requestor_name="Alice",
        requestor_email="alice@example.com",
        schema_version_at_start=1,
        share_token=f"share-{uuid4().hex[:8]}",
        resolution_json=resolution_json,
        tags_json="[]",
        created_at=_utc_now(),
        updated_at=_utc_now(),
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    return record


# ---------------------------------------------------------------------------
# Tests: POST /sessions/{id}/complete (RESOLVE-04)
# ---------------------------------------------------------------------------


class TestCompleteSession:
    """Tests for the complete_session endpoint."""

    @pytest.mark.asyncio
    async def test_complete_returns_session_detail(self, async_db_session):
        """RESOLVE-04: complete_session returns a SessionDetailResponse.

        Seeds a real in_progress session. Mocks TaskQueue.submit (background).
        Mocks session_service.complete_session to return a stub detail response
        (avoids full validation logic in this unit test).
        """
        from aila.modules.sbd_nfr.api_router import complete_session
        from aila.modules.sbd_nfr.contracts.session import SessionDetailResponse

        session = await _seed_session(
            async_db_session,
            session_id=f"sess-{uuid4().hex[:8]}",
            owner_id="user-owner",
            status="in_progress",
        )
        auth_ctx = _make_auth_context(user_id="user-owner", role="operator")

        mock_detail = MagicMock(spec=SessionDetailResponse)
        mock_detail.id = session.id
        mock_detail.status = "completed"

        with patch("aila.modules.sbd_nfr.api_router.session_service") as mock_ss:
            mock_ss.complete_session = AsyncMock(return_value=mock_detail)
            with patch("aila.api.deps.get_task_queue") as mock_get_tq:
                mock_tq = MagicMock()
                mock_tq.submit = AsyncMock()
                mock_get_tq.return_value = mock_tq

                result = await complete_session(
                    request=_make_request(),
                    session_id=session.id,
                    auth=auth_ctx,
                )

        assert result is mock_detail

    @pytest.mark.asyncio
    async def test_complete_requires_ownership(self, async_db_session):
        """RESOLVE-04: Non-owner non-admin gets 403 on complete."""
        from fastapi import HTTPException

        from aila.modules.sbd_nfr.api_router import complete_session

        session = await _seed_session(
            async_db_session,
            session_id=f"sess-{uuid4().hex[:8]}",
            owner_id="user-owner",
            status="in_progress",
        )
        auth_ctx = _make_auth_context(user_id="user-other", role="reader")

        with pytest.raises(HTTPException) as exc_info:
            await complete_session(
                request=_make_request(),
                session_id=session.id,
                auth=auth_ctx,
            )

        assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# Tests: POST /sessions/{id}/resolve (D-02, D-18, T-135-10)
# ---------------------------------------------------------------------------


class TestTriggerResolution:
    """Tests for the trigger_resolution endpoint."""

    def setup_method(self):
        """Clear rate limit store before each test."""
        import aila.modules.sbd_nfr.api_router as _router
        _router._resolve_rate_limits.clear()

    @pytest.mark.asyncio
    async def test_manual_retry_from_failed(self, async_db_session):
        """D-02: trigger_resolution returns ResolutionTriggerResponse from resolution_failed.

        Seeds a real session in resolution_failed state. Mocks TaskQueue.submit.
        Verifies the endpoint returns the correct response dict.
        """
        from aila.modules.sbd_nfr.api_router import trigger_resolution

        session = await _seed_session(
            async_db_session,
            session_id=f"sess-{uuid4().hex[:8]}",
            owner_id="user-001",
            status="resolution_failed",
        )
        auth_ctx = _make_auth_context(user_id="user-001", role="operator")

        task_submitted: list = []

        async def mock_submit(**kwargs):
            task_submitted.append(kwargs)

        with patch("aila.modules.sbd_nfr.api_router.session_service") as mock_ss:
            mock_ss.update_session_status = AsyncMock()
            with patch("aila.api.deps.get_task_queue") as mock_get_tq:
                mock_tq = MagicMock()
                mock_tq.submit = mock_submit
                mock_get_tq.return_value = mock_tq

                result = await trigger_resolution(
                    request=_make_request(),
                    session_id=session.id,
                    auth=auth_ctx,
                )

        assert result.status == "resolving"
        assert result.session_id == session.id
        assert len(task_submitted) == 1

    @pytest.mark.asyncio
    async def test_manual_retry_wrong_status(self, async_db_session):
        """D-02: trigger_resolution returns 409 for non-resolution_failed sessions."""
        from fastapi import HTTPException

        from aila.modules.sbd_nfr.api_router import trigger_resolution

        session = await _seed_session(
            async_db_session,
            session_id=f"sess-{uuid4().hex[:8]}",
            owner_id="user-001",
            status="draft",
        )
        auth_ctx = _make_auth_context(user_id="user-001", role="operator")

        with pytest.raises(HTTPException) as exc_info:
            await trigger_resolution(
                request=_make_request(),
                session_id=session.id,
                auth=auth_ctx,
            )

        assert exc_info.value.status_code == 409
        assert "resolution_failed" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_resolve_rate_limit(self, async_db_session):
        """D-18: trigger_resolution returns 429 after exceeding rate limit.

        Pre-fills the rate limit store with 3 recent timestamps.
        The 4th call must be rejected with 429.
        """
        from fastapi import HTTPException

        from aila.modules.sbd_nfr.api_router import _resolve_rate_limits, trigger_resolution

        session = await _seed_session(
            async_db_session,
            session_id=f"sess-{uuid4().hex[:8]}",
            owner_id="user-001",
            status="resolution_failed",
        )
        auth_ctx = _make_auth_context(user_id="user-001", role="operator")

        # Pre-fill rate limit store with 3 recent timestamps
        now = time.time()
        _resolve_rate_limits[session.id] = [now - 1, now - 2, now - 3]

        with pytest.raises(HTTPException) as exc_info:
            await trigger_resolution(
                request=_make_request(),
                session_id=session.id,
                auth=auth_ctx,
            )

        assert exc_info.value.status_code == 429
        assert "Rate limit" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_resolution_rbac(self, async_db_session):
        """T-135-10: Non-owner non-admin cannot trigger resolution (403)."""
        from fastapi import HTTPException

        from aila.modules.sbd_nfr.api_router import trigger_resolution

        session = await _seed_session(
            async_db_session,
            session_id=f"sess-{uuid4().hex[:8]}",
            owner_id="user-owner",
            status="resolution_failed",
        )
        auth_ctx = _make_auth_context(user_id="user-other", role="reader")

        with pytest.raises(HTTPException) as exc_info:
            await trigger_resolution(
                request=_make_request(),
                session_id=session.id,
                auth=auth_ctx,
            )

        assert exc_info.value.status_code == 403
        assert "Only the session owner" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_resolution_async_flow(self, async_db_session):
        """RESOLVE-04: Full trigger flow submits task to TaskQueue.

        Verifies update_session_status is called with 'resolving' and
        task is submitted with correct session_id.
        """
        from aila.modules.sbd_nfr.api_router import trigger_resolution

        session = await _seed_session(
            async_db_session,
            session_id=f"sess-{uuid4().hex[:8]}",
            owner_id="user-001",
            status="resolution_failed",
        )
        auth_ctx = _make_auth_context(user_id="user-001", role="operator")

        status_updates: list = []
        task_submits: list = []

        async def mock_update_status(session_id, new_status):
            status_updates.append(new_status)

        async def mock_submit(**kwargs):
            task_submits.append(kwargs)

        with patch("aila.modules.sbd_nfr.api_router.session_service") as mock_ss:
            mock_ss.update_session_status = mock_update_status
            with patch("aila.api.deps.get_task_queue") as mock_get_tq:
                mock_tq = MagicMock()
                mock_tq.submit = mock_submit
                mock_get_tq.return_value = mock_tq

                result = await trigger_resolution(
                    request=_make_request(),
                    session_id=session.id,
                    auth=auth_ctx,
                )

        assert "resolving" in status_updates
        assert len(task_submits) == 1
        assert task_submits[0].get("kwargs", {}).get("session_id") == session.id


# ---------------------------------------------------------------------------
# Tests: GET /sessions/{id}/resolution (D-11)
# ---------------------------------------------------------------------------


class TestGetResolution:
    """Tests for the get_resolution endpoint."""

    @pytest.mark.asyncio
    async def test_get_resolution_results(self, async_db_session):
        """D-11: get_resolution returns ResolutionResultResponse with components.

        Seeds a real resolved session and 25 result records.
        """
        from aila.modules.sbd_nfr.api_router import get_resolution
        from aila.modules.sbd_nfr.db_models import (
            SbdNfrResolutionResultRecord,
            SbdNfrSubtaskComponentRecord,
        )

        subtask_keys = [
            "access_point_integration", "application_logging", "archer_inventory_update",
            "arcsight_new_update_alert_request", "container_native_firewall",
            "container_security_scan", "cyberark_epm", "dast", "database_logging",
            "file_integrity_monitoring_integration", "network_segment_placement",
            "onetrust_supplier_security_assesment", "operating_system_logging_unix",
            "operating_system_logging_windows", "penetration_testing",
            "privileged_user_access_management_integrations_cyberark", "proxy_definition",
            "risk_assesment", "sast", "scs", "secure_by_design_assesment",
            "software_composition_analysis_sca", "vulnerability_scan_tenable",
            "waf_integration", "web_certificate_request",
        ]

        resolution_json = json.dumps({
            "components": [],
            "executive_summary": "Test executive summary",
        })
        session_id = f"sess-{uuid4().hex[:8]}"
        session = await _seed_session(
            async_db_session,
            session_id=session_id,
            owner_id="user-001",
            status="resolved",
            resolution_json=resolution_json,
        )

        # Seed subtask component records
        for key in subtask_keys:
            async_db_session.add(SbdNfrSubtaskComponentRecord(
                id=str(uuid4()),
                key=key,
                label=f"Label {key}",
                category="security",
                display_order=0,
                is_active=True,
            ))

        # Seed resolution result records
        resolved_at = _utc_now()
        for key in subtask_keys:
            async_db_session.add(SbdNfrResolutionResultRecord(
                session_id=session_id,
                subtask_key=key,
                classification="triggered",
                confidence=0.9,
                reasoning=f"Reasoning for {key}",
                cited_question_ids_json='["Q-01", "Q-02"]',
                resolved_at=resolved_at,
            ))
        await async_db_session.commit()

        auth_ctx = _make_auth_context(user_id="user-001", role="operator")

        response = await get_resolution(
            session_id=session_id,
            auth=auth_ctx,
        )

        assert isinstance(response, ResolutionResultResponse)
        assert len(response.components) == 25
        assert response.status == "resolved"
        for comp in response.components:
            assert comp.classification in ("triggered", "not_triggered", "uncertain")
            assert isinstance(comp.cited_question_ids, list)
        assert response.executive_summary == "Test executive summary"

    @pytest.mark.asyncio
    async def test_get_resolution_not_resolved(self, async_db_session):
        """D-11: get_resolution returns empty components for in_progress sessions."""
        from aila.modules.sbd_nfr.api_router import get_resolution

        session_id = f"sess-{uuid4().hex[:8]}"
        await _seed_session(
            async_db_session,
            session_id=session_id,
            owner_id="user-001",
            status="in_progress",
        )
        auth_ctx = _make_auth_context(user_id="user-001", role="operator")

        response = await get_resolution(
            session_id=session_id,
            auth=auth_ctx,
        )

        assert isinstance(response, ResolutionResultResponse)
        assert response.components == []
        assert response.status == "in_progress"


# ---------------------------------------------------------------------------
# Tests: GET /sessions/{id}/events (PLAT-03, D-13)
# ---------------------------------------------------------------------------


class TestSseEvents:
    """Tests for the SSE events endpoint."""

    @pytest.mark.asyncio
    async def test_sse_events_requires_redis(self, async_db_session):
        """Session SSE returns 503 when Redis transport is unavailable."""
        from contextlib import asynccontextmanager

        from fastapi import HTTPException

        from aila.modules.sbd_nfr.api_router import stream_session_events

        session_id = f"sess-{uuid4().hex[:8]}"
        await _seed_session(
            async_db_session,
            session_id=session_id,
            owner_id="user-001",
            status="resolving",
        )
        auth_ctx = _make_auth_context(user_id="user-001", role="operator")

        @asynccontextmanager
        async def _broken_redis():
            raise RuntimeError("Redis pool not initialized")
            yield  # pragma: no cover

        with patch("aila.platform.services.redis_pool.get_redis", _broken_redis):
            with pytest.raises(HTTPException) as exc_info:
                await stream_session_events(
                    session_id=session_id,
                    last_id="0",
                    auth=auth_ctx,
                )

        assert exc_info.value.status_code == 503
        assert "Redis not configured" in exc_info.value.detail


# ---------------------------------------------------------------------------
# Tests: POST /questions/{id}/assist (D-14, D-18)
# ---------------------------------------------------------------------------


class TestAssistEndpoint:
    """Tests for the assist endpoint."""

    def setup_method(self):
        """Clear assist rate limit store before each test."""
        import aila.modules.sbd_nfr.api_router as _router
        _router._assist_rate_limits.clear()

    @pytest.mark.asyncio
    async def test_assist_endpoint(self):
        """D-14: assist_question passes through to assist_service and returns AssistResponse."""
        from aila.modules.sbd_nfr.api_router import assist_question

        auth_ctx = _make_auth_context(user_id="user-001", role="reader")
        request = AssistRequest(
            message="What does this question mean?",
            history=[],
            current_answer=None,
        )

        expected_reply = "This question asks about your deployment model."
        mock_assist_response = AssistResponse(reply=expected_reply)

        with patch(
            "aila.modules.sbd_nfr.api_router.assist_service.handle_assist",
            new=AsyncMock(return_value=mock_assist_response),
        ):
            result = await assist_question(
                question_id="Q-01",
                body=request,
                auth=auth_ctx,
            )

        assert isinstance(result, AssistResponse)
        assert result.reply == expected_reply

    @pytest.mark.asyncio
    async def test_assist_rate_limit(self):
        """D-18: assist_question returns 429 after exceeding rate limit.

        Pre-fills the rate limit store with 20 timestamps (at the limit).
        """
        from fastapi import HTTPException

        from aila.modules.sbd_nfr.api_router import _assist_rate_limits, assist_question

        auth_ctx = _make_auth_context(user_id="user-001", role="reader")
        request = AssistRequest(message="Help me", history=[])

        question_id = "Q-RATE-TEST"
        rate_key = f"{auth_ctx.user_id}:{question_id}"

        now = time.time()
        _assist_rate_limits[rate_key] = [now - i for i in range(20)]

        with pytest.raises(HTTPException) as exc_info:
            await assist_question(
                question_id=question_id,
                body=request,
                auth=auth_ctx,
            )

        assert exc_info.value.status_code == 429
        assert "Rate limit" in exc_info.value.detail
