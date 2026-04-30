"""Cross-cutting tests for Phase 98: Health state machine & error response consistency.

XCUT-08: DB up/down x module up/down -> correct aggregate status
XCUT-09: Every 4xx/5xx returns ErrorResponse with detail, code, errors fields
"""
from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from aila.api.schemas.health import HealthCheckResult
from aila.platform.modules.protocol import ModuleHealthResult

__all__: list[str] = []


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _make_stub_module(
    module_id: str,
    health_checks_return: dict[str, object] | None = None,
    health_checks_raises: BaseException | None = None,
    *,
    no_health_checks: bool = False,
) -> MagicMock:
    """Create a MagicMock module with controllable health_checks behavior."""
    mod = MagicMock()
    mod.module_id = module_id
    if no_health_checks:
        del mod.health_checks
    elif health_checks_raises is not None:
        mod.health_checks.side_effect = health_checks_raises
    elif health_checks_return is not None:
        mod.health_checks.return_value = health_checks_return
    else:
        mod.health_checks.return_value = {}
    return mod


def _db_up_result() -> HealthCheckResult:
    """Simulate a healthy database check result."""
    return HealthCheckResult(status="up", latency_ms=1.0)


def _db_down_result() -> HealthCheckResult:
    """Simulate a failed database check result."""
    return HealthCheckResult(status="down", message="connection refused")


def _assert_error_response_shape(body: dict) -> None:
    """Assert the response body conforms to ErrorResponse schema."""
    assert "detail" in body, f"Missing 'detail' field: {body}"
    assert isinstance(body["detail"], str), (
        f"detail must be str, got {type(body['detail']).__name__}"
    )
    assert "code" in body, f"Missing 'code' field: {body}"
    assert "errors" in body, f"Missing 'errors' field: {body}"


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture(scope="function")
async def health_client(test_db):
    """Async client with a stub platform whose module_registry has configurable modules."""
    from aila.api.app import create_app

    test_app = create_app()

    stub_registry = MagicMock()
    stub_registry.modules = []

    stub_runtime = MagicMock()
    stub_runtime.module_registry = stub_registry

    stub_platform = MagicMock()
    stub_platform.runtime = stub_runtime

    test_app.state.platform = stub_platform
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        client._stub_registry = stub_registry  # type: ignore[attr-defined]
        yield client


@pytest_asyncio.fixture(scope="function")
async def error_client(test_db):
    """Async client for error response shape testing."""
    from aila.api.app import create_app

    test_app = create_app()
    test_app.state.platform = None
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        yield client


# ─── XCUT-08: Health state machine ───────────────────────────────────────────


class TestHealthStateMachine:
    """Verify all DB x module combinations produce the correct aggregate status."""

    @pytest.mark.asyncio
    async def test_db_up_no_modules_healthy(self, health_client):
        """DB up + no modules -> healthy."""
        health_client._stub_registry.modules = []

        resp = await health_client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"
        assert body["checks"]["database"]["status"] == "up"

    @pytest.mark.asyncio
    async def test_db_up_all_modules_up_healthy(self, health_client):
        """DB up + all modules up -> healthy."""
        mod_a = _make_stub_module(
            "mod_a",
            health_checks_return={"ping": lambda: ModuleHealthResult(status="up")},
        )
        mod_b = _make_stub_module(
            "mod_b",
            health_checks_return={"ping": lambda: ModuleHealthResult(status="up")},
        )
        health_client._stub_registry.modules = [mod_a, mod_b]

        resp = await health_client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_db_up_one_module_down_degraded(self, health_client):
        """DB up + one module down -> degraded (NOT unhealthy)."""
        mod = _make_stub_module(
            "failing",
            health_checks_return={
                "svc": lambda: ModuleHealthResult(status="down", message="offline"),
            },
        )
        health_client._stub_registry.modules = [mod]

        resp = await health_client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "degraded", (
            f"Expected 'degraded' for DB up + module down, got '{body['status']}'"
        )

    @pytest.mark.asyncio
    async def test_db_up_one_module_degraded_degraded(self, health_client):
        """DB up + one module degraded -> degraded."""
        mod = _make_stub_module(
            "slow",
            health_checks_return={
                "cache": lambda: ModuleHealthResult(status="degraded", message="slow"),
            },
        )
        health_client._stub_registry.modules = [mod]

        resp = await health_client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "degraded"

    @pytest.mark.asyncio
    async def test_db_up_mixed_modules_degraded(self, health_client):
        """DB up + mixed (one up, one down) -> degraded."""
        mod_ok = _make_stub_module(
            "ok_mod",
            health_checks_return={"ping": lambda: ModuleHealthResult(status="up")},
        )
        mod_bad = _make_stub_module(
            "bad_mod",
            health_checks_return={
                "svc": lambda: ModuleHealthResult(status="down", message="dead"),
            },
        )
        health_client._stub_registry.modules = [mod_ok, mod_bad]

        resp = await health_client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "degraded"

    @pytest.mark.asyncio
    async def test_db_down_no_modules_unhealthy(self, health_client):
        """DB down + no modules -> unhealthy."""
        health_client._stub_registry.modules = []

        with patch(
            "aila.api.routers.health._check_database",
            return_value=_db_down_result(),
        ):
            resp = await health_client.get("/health")

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "unhealthy"
        assert body["checks"]["database"]["status"] == "down"

    @pytest.mark.asyncio
    async def test_db_down_all_modules_up_unhealthy(self, health_client):
        """DB down + all modules up -> unhealthy (DB is critical)."""
        mod = _make_stub_module(
            "ok_mod",
            health_checks_return={"ping": lambda: ModuleHealthResult(status="up")},
        )
        health_client._stub_registry.modules = [mod]

        with patch(
            "aila.api.routers.health._check_database",
            return_value=_db_down_result(),
        ):
            resp = await health_client.get("/health")

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "unhealthy"

    @pytest.mark.asyncio
    async def test_db_down_modules_down_unhealthy(self, health_client):
        """DB down + modules down -> unhealthy."""
        mod = _make_stub_module(
            "dead_mod",
            health_checks_return={
                "svc": lambda: ModuleHealthResult(status="down", message="gone"),
            },
        )
        health_client._stub_registry.modules = [mod]

        with patch(
            "aila.api.routers.health._check_database",
            return_value=_db_down_result(),
        ):
            resp = await health_client.get("/health")

        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "unhealthy"


# ─── XCUT-09: Error response consistency ────────────────────────────────────


class TestErrorResponseConsistency:
    """Every 4xx/5xx response conforms to ErrorResponse(detail, code, errors)."""

    @pytest.mark.asyncio
    async def test_401_no_auth_header(self, error_client):
        """Request with no Authorization header returns ErrorResponse shape."""
        resp = await error_client.get("/systems")
        assert resp.status_code == 401
        _assert_error_response_shape(resp.json())

    @pytest.mark.asyncio
    async def test_401_bad_token(self, error_client):
        """Invalid Bearer token returns ErrorResponse shape."""
        resp = await error_client.get(
            "/systems",
            headers={"Authorization": "Bearer totally-invalid-jwt"},
        )
        assert resp.status_code == 401
        _assert_error_response_shape(resp.json())

    @pytest.mark.asyncio
    async def test_403_forbidden_role(self, error_client, reader_token):
        """Reader token on admin-only endpoint returns 403 ErrorResponse."""
        resp = await error_client.post(
            "/auth/keys",
            headers={"Authorization": f"Bearer {reader_token}"},
            json={"role": "reader", "label": "test"},
        )
        assert resp.status_code == 403
        _assert_error_response_shape(resp.json())

    @pytest.mark.asyncio
    async def test_404_not_found(self, error_client, admin_token):
        """Non-existent resource returns 404 ErrorResponse shape."""
        resp = await error_client.get(
            "/systems/999999",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 404
        _assert_error_response_shape(resp.json())

    @pytest.mark.asyncio
    async def test_422_validation_error(self, error_client):
        """Validation error returns ErrorResponse with code=VALIDATION_ERROR."""
        resp = await error_client.post(
            "/auth/token",
            json={},  # missing required api_key field
        )
        assert resp.status_code == 422
        body = resp.json()
        _assert_error_response_shape(body)
        assert body["code"] == "VALIDATION_ERROR"
        assert isinstance(body["errors"], list)
        assert len(body["errors"]) > 0

    @pytest.mark.asyncio
    async def test_500_unhandled_exception_no_stack_trace(self, error_client):
        """Unhandled exception returns ErrorResponse, no stack trace leaked."""
        # Patch a well-known endpoint to raise an unhandled exception
        with patch(
            "aila.api.routers.health._check_database",
            side_effect=RuntimeError("kaboom"),
        ):
            resp = await error_client.get("/health")

        assert resp.status_code == 500
        body = resp.json()
        _assert_error_response_shape(body)
        assert body["detail"] == "Internal server error"
        # Must NOT contain stack trace information
        assert "Traceback" not in str(body)
        assert "kaboom" not in body["detail"]
        assert body["code"] is None
        assert body["errors"] is None
