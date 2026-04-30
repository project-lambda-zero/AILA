"""Coverage tests for health.py and scans.py router uncovered paths.

health.py targets: lines 48-49, 106-121, 126-138
scans.py targets: lines 170-172 (get_scan_status with data)

Uses mock platforms and modules to exercise health check collection
and single-check execution paths without requiring live infrastructure.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.storage.database import session_scope


# ---------------------------------------------------------------------------
# Fixtures: platform with modules that have health_checks()
# ---------------------------------------------------------------------------


@dataclass
class _FakeHealthResult:
    status: str = "up"
    latency_ms: float | None = 5.0
    message: str | None = None


class _FakeModule:
    """Module stub that exposes health_checks()."""

    def __init__(self, module_id: str, checks: dict[str, object] | None = None, raises: bool = False):
        self.module_id = module_id
        self._checks = checks or {}
        self._raises = raises

    def health_checks(self) -> dict[str, object]:
        if self._raises:
            raise RuntimeError("module health check explosion")
        return self._checks


class _FakeModuleRegistry:
    def __init__(self, modules: list[object]):
        self.modules = modules


@pytest_asyncio.fixture(scope="function")
async def async_client_with_modules(test_db):
    """Client with a platform that has modules exposing health_checks().

    Exercises _collect_module_health_checks (lines 106-121) and
    _run_single_health_check (lines 126-138).
    """
    from aila.api.app import create_app

    def good_check() -> _FakeHealthResult:
        return _FakeHealthResult(status="up", latency_ms=2.5)

    def bad_check() -> _FakeHealthResult:
        raise ConnectionError("redis down")

    def non_callable_check():
        pass

    modules = [
        _FakeModule(
            module_id="vuln",
            checks={
                "llm": good_check,
                "redis": bad_check,
            },
        ),
        _FakeModule(
            module_id="broken",
            raises=True,
        ),
    ]
    module_registry = _FakeModuleRegistry(modules)

    stub_runtime = MagicMock()
    stub_runtime.module_registry = module_registry

    stub_platform = MagicMock()
    stub_platform.runtime = stub_runtime

    test_app = create_app()
    test_app.state.platform = stub_platform
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        yield client


# ---------------------------------------------------------------------------
# health.py: _collect_module_health_checks (lines 106-121)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_module_checks_present(
    async_client_with_modules: AsyncClient,
) -> None:
    """GET /health with modules that have health_checks() includes module checks.

    Covers lines 106-121 (_collect_module_health_checks inner loop).
    """
    resp = await async_client_with_modules.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    checks = data["checks"]

    # vuln module's good check should be 'up'
    assert "vuln_llm" in checks
    assert checks["vuln_llm"]["status"] == "up"

    # vuln module's bad check should be 'down' (raises ConnectionError)
    assert "vuln_redis" in checks
    assert checks["vuln_redis"]["status"] == "down"
    assert "redis down" in checks["vuln_redis"]["message"]

    # broken module's health_checks() itself raises -> module-level 'down'
    assert "broken_health" in checks
    assert checks["broken_health"]["status"] == "down"
    assert "health_checks() raised" in checks["broken_health"]["message"]


@pytest.mark.asyncio
async def test_health_aggregation_degraded_with_module_down(
    async_client_with_modules: AsyncClient,
) -> None:
    """GET /health with module 'down' but DB up returns 'degraded'.

    Per Phase 98: only DB down = unhealthy; module down = degraded.
    """
    resp = await async_client_with_modules.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "degraded"


# ---------------------------------------------------------------------------
# health.py: _run_single_health_check with non-callable (lines 126-127)
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="function")
async def async_client_with_noncallable_check(test_db):
    """Client where a module returns a non-callable health check entry."""
    from aila.api.app import create_app

    class _ModuleWithBadCheck:
        module_id = "bad"

        def health_checks(self) -> dict[str, object]:
            return {"check_a": "not_callable"}  # Not a function!

    module_registry = _FakeModuleRegistry([_ModuleWithBadCheck()])
    stub_runtime = MagicMock()
    stub_runtime.module_registry = module_registry
    stub_platform = MagicMock()
    stub_platform.runtime = stub_runtime

    test_app = create_app()
    test_app.state.platform = stub_platform
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        yield client


@pytest.mark.asyncio
async def test_health_noncallable_check_returns_down(
    async_client_with_noncallable_check: AsyncClient,
) -> None:
    """Non-callable health check entry returns status='down'.

    Covers line 127 (not callable -> HealthCheckResult with message).
    """
    resp = await async_client_with_noncallable_check.get("/health")
    assert resp.status_code == 200
    checks = resp.json()["checks"]
    assert "bad_check_a" in checks
    assert checks["bad_check_a"]["status"] == "down"
    assert "not callable" in checks["bad_check_a"]["message"].lower()


# ---------------------------------------------------------------------------
# health.py: _check_database exception path (lines 48-49)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_database_down(
    async_client_with_modules: AsyncClient,
) -> None:
    """GET /health when session_scope raises returns database status='down'.

    Covers lines 48-49 (except branch in _check_database).
    """
    with patch("aila.api.routers.health.session_scope") as mock_scope:
        mock_scope.side_effect = RuntimeError("DB connection failed")
        resp = await async_client_with_modules.get("/health")

    assert resp.status_code == 200
    checks = resp.json()["checks"]
    assert "database" in checks
    assert checks["database"]["status"] == "down"
    assert "DB connection failed" in checks["database"]["message"]


# ---------------------------------------------------------------------------
# health.py: _run_single_health_check result without status attr (line 136)
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="function")
async def async_client_with_statusless_check(test_db):
    """Client where a module health check returns a value without .status."""
    from aila.api.app import create_app

    def plain_check() -> str:
        return "ok"  # No .status attribute

    class _ModulePlain:
        module_id = "plain"

        def health_checks(self) -> dict[str, object]:
            return {"simple": plain_check}

    module_registry = _FakeModuleRegistry([_ModulePlain()])
    stub_runtime = MagicMock()
    stub_runtime.module_registry = module_registry
    stub_platform = MagicMock()
    stub_platform.runtime = stub_runtime

    test_app = create_app()
    test_app.state.platform = stub_platform
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        yield client


@pytest.mark.asyncio
async def test_health_check_no_status_attr_returns_up(
    async_client_with_statusless_check: AsyncClient,
) -> None:
    """Health check returning value without .status defaults to 'up'.

    Covers line 136 (no hasattr(result, 'status') -> HealthCheckResult(status='up')).
    """
    resp = await async_client_with_statusless_check.get("/health")
    assert resp.status_code == 200
    checks = resp.json()["checks"]
    assert "plain_simple" in checks
    assert checks["plain_simple"]["status"] == "up"


# ---------------------------------------------------------------------------
# scans.py: GET /scans/{run_id} with data (lines 170-172)
# ---------------------------------------------------------------------------


def _seed_task(
    task_id: str = "scan-run-001",
    status: str = TaskStatus.DONE,
    group_id: str = "admin",
    track: str = "vulnerability",
) -> TaskRecord:
    """Seed a TaskRecord that doubles as a scan record."""
    record = TaskRecord(
        id=task_id,
        track=track,
        fn_path="aila.api.routers.scans.run_platform_handle",
        fn_module="__platform__",
        status=status,
        user_id="user-scan-001",
        group_id=group_id,
    )
    with session_scope() as session:
        session.add(record)
        session.commit()
        session.refresh(record)
    return record


@pytest.mark.asyncio
async def test_get_scan_status_found(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """GET /scans/{run_id} with existing task returns 200 with task details.

    Covers scans.py lines 170-172 (get_scan_status returning data dict).
    """
    task = _seed_task(task_id="scan-found-001", status=TaskStatus.DONE, group_id="admin")

    resp = await async_client.get(
        f"/scans/{task.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["run_id"] == task.id
    assert data["status"] == "done"
    assert data["track"] == "vulnerability"


@pytest.mark.asyncio
async def test_get_scan_status_not_found(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """GET /scans/{nonexistent} returns 404."""
    resp = await async_client.get(
        "/scans/nonexistent-run-id",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_get_scan_status_running(
    async_client: AsyncClient,
    admin_token: str,
    test_db,
) -> None:
    """GET /scans/{run_id} with RUNNING task returns status=running."""
    task = _seed_task(task_id="scan-running-001", status=TaskStatus.RUNNING, group_id="admin")

    resp = await async_client.get(
        f"/scans/{task.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "running"
    assert data["result_path"] is None  # Not done yet
