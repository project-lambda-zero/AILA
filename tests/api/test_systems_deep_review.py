"""Deep review tests for systems router (Phase 70).

Covers branches NOT tested by test_55_02_system_crud.py or test_negative_systems.py:
  - List pagination (multi-page, empty, page=2)
  - Get system detail with module delegation (summaries, exception swallowing, scan_count)
  - Get system findings with module delegation (delegation, platform=None, nonexistent)
  - Get system scans happy path (matching runs, empty)
  - Boundary compliance (no aila.modules imports in systems router)

FILE-07: every function read, every branch tested, zero dead code, no boundary violations.
"""
from __future__ import annotations

import ast
import time
from collections.abc import AsyncGenerator
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture(scope="function")
async def async_client_with_modules(test_db) -> AsyncGenerator[AsyncClient, None]:
    """Async client with a stub platform providing a mock module registry.

    The stub module exposes:
    - module_id: "stub"
    - system_summary(system_id, session) -> dict
    - system_findings(system_id, system_name, session, page, page_size) -> dict
    """
    from aila.api.app import create_app

    stub_module = MagicMock()
    stub_module.module_id = "stub"
    # systems.py awaits ``module.system_summary(...)`` and
    # ``module.system_findings(...)`` -- both must be AsyncMock so the returned
    # coroutine resolves to the payload, not a raw MagicMock (unawaitable).
    stub_module.system_summary = AsyncMock(return_value={"total_findings": 5, "critical": 2})
    stub_module.system_findings = AsyncMock(
        return_value={
            "items": [
                {
                    "run_id": "run-stub-001",
                    "cve_id": "CVE-2024-0001",
                    "package": "openssl",
                    "host": "web01",
                    "severity": "CRITICAL",
                    "kev": True,
                    "score": 9.8,
                    "status": "open",
                }
            ],
            "total": 1,
        }
    )

    stub_registry = MagicMock()
    stub_registry.modules = [stub_module]

    stub_runtime = MagicMock()
    stub_runtime.module_registry = stub_registry

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


def _seed_systems(count: int) -> list:
    """Seed N ManagedSystemRecord rows and return them."""
    from aila.platform.contracts._common import utc_now
    from aila.storage.database import session_scope
    from aila.storage.db_models import ManagedSystemRecord

    records = []
    with session_scope() as session:
        for i in range(count):
            record = ManagedSystemRecord(
                name=f"sys-{i:03d}",
                host=f"10.0.0.{i + 1}",
                username="root",
                port=22,
                distro="ubuntu",
                description=f"System {i}",
                created_at=utc_now(),
                updated_at=utc_now(),
            )
            session.add(record)
        session.commit()
        # Re-query to get IDs
        from sqlmodel import select

        stmt = select(ManagedSystemRecord).order_by(ManagedSystemRecord.name)
        records = list(session.exec(stmt).all())
    return records


# ─── Group 1: List pagination ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_systems_paginated_response(
    async_client: AsyncClient, admin_token: str
) -> None:
    """GET /systems returns paginated response with correct total, page, and pages."""
    _seed_systems(3)
    resp = await async_client.get(
        "/systems?page=1&page_size=2",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 3
    assert data["page"] == 1
    assert data["page_size"] == 2
    assert data["pages"] == 2  # ceil(3/2)
    assert len(data["items"]) == 2


@pytest.mark.asyncio
async def test_list_systems_page_two(
    async_client: AsyncClient, admin_token: str
) -> None:
    """GET /systems?page=2 returns the correct second-page slice."""
    _seed_systems(3)
    resp = await async_client.get(
        "/systems?page=2&page_size=2",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 3
    assert data["page"] == 2
    assert len(data["items"]) == 1  # 3 total, page_size=2, page=2 -> 1 remaining


@pytest.mark.asyncio
async def test_list_systems_empty(
    async_client: AsyncClient, admin_token: str
) -> None:
    """GET /systems with no systems returns total=0, pages=0, items=[]."""
    resp = await async_client.get(
        "/systems",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["pages"] == 0
    assert data["items"] == []


# ─── Group 2: Get system detail with module delegation ───────────────────────


@pytest.mark.asyncio
async def test_get_system_with_module_summaries(
    async_client_with_modules: AsyncClient, admin_token: str, seeded_system
) -> None:
    """GET /systems/{id} with stub platform returns module_summaries from system_summary()."""
    resp = await async_client_with_modules.get(
        f"/systems/{seeded_system.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "module_summaries" in data
    assert "stub" in data["module_summaries"]
    assert data["module_summaries"]["stub"]["total_findings"] == 5
    assert data["module_summaries"]["stub"]["critical"] == 2


@pytest.mark.asyncio
async def test_get_system_platform_none_returns_empty_summaries(
    async_client: AsyncClient, admin_token: str, seeded_system
) -> None:
    """GET /systems/{id} with platform=None returns empty module_summaries."""
    resp = await async_client.get(
        f"/systems/{seeded_system.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["module_summaries"] == {}


@pytest.mark.asyncio
async def test_get_system_module_exception_swallowed(
    test_db, admin_token: str, seeded_system
) -> None:
    """GET /systems/{id} with a module that raises in system_summary() still returns 200.

    Verifies the per-module exception swallowing in _collect_module_summaries.
    """
    from aila.api.app import create_app

    broken_module = MagicMock()
    broken_module.module_id = "broken"
    broken_module.system_summary.side_effect = RuntimeError("module crashed")

    stub_registry = MagicMock()
    stub_registry.modules = [broken_module]

    stub_runtime = MagicMock()
    stub_runtime.module_registry = stub_registry

    stub_platform = MagicMock()
    stub_platform.runtime = stub_runtime

    test_app = create_app()
    test_app.state.platform = stub_platform
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        resp = await client.get(
            f"/systems/{seeded_system.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
    assert resp.status_code == 200
    data = resp.json()
    # Broken module's summary is excluded, not an error
    assert "broken" not in data["module_summaries"]


@pytest.mark.asyncio
async def test_get_system_scan_count(
    async_client: AsyncClient, admin_token: str, seeded_system, seeded_run
) -> None:
    """GET /systems/{id} scan_count counts matching WorkflowRunRecords.

    seeded_run has route_json containing 'web01' which matches seeded_system.name.
    """
    resp = await async_client.get(
        f"/systems/{seeded_system.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["scan_count"] >= 1


# ─── Group 3: Get system findings with module delegation ─────────────────────


@pytest.mark.asyncio
async def test_get_system_findings_with_stub_module(
    async_client_with_modules: AsyncClient, admin_token: str, seeded_system
) -> None:
    """GET /systems/{id}/findings with stub module returns delegated findings."""
    resp = await async_client_with_modules.get(
        f"/systems/{seeded_system.id}/findings",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert len(data["items"]) == 1
    item = data["items"][0]
    assert item["cve_id"] == "CVE-2024-0001"
    assert item["package"] == "openssl"
    assert item["kev"] is True


@pytest.mark.asyncio
async def test_get_system_findings_platform_none(
    async_client: AsyncClient, admin_token: str, seeded_system
) -> None:
    """GET /systems/{id}/findings with platform=None returns empty list."""
    resp = await async_client.get(
        f"/systems/{seeded_system.id}/findings",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["items"] == []


@pytest.mark.asyncio
async def test_get_system_findings_nonexistent_system(
    async_client: AsyncClient, admin_token: str
) -> None:
    """GET /systems/99999/findings for nonexistent system returns total=0.

    Unlike /scans, the /findings endpoint does not 404 for missing systems --
    it returns an empty findings list with total=0.
    """
    resp = await async_client.get(
        "/systems/99999/findings",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["items"] == []


# ─── Group 4: Get system scans happy path ────────────────────────────────────


@pytest.mark.asyncio
async def test_get_system_scans_with_matching_run(
    async_client: AsyncClient, admin_token: str, seeded_system, seeded_run
) -> None:
    """GET /systems/{id}/scans with matching WorkflowRunRecord returns paginated items.

    seeded_run route_json contains 'web01' which matches seeded_system.name.
    """
    resp = await async_client.get(
        f"/systems/{seeded_system.id}/scans",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    assert len(data["items"]) >= 1
    assert data["page"] == 1
    assert "pages" in data


@pytest.mark.asyncio
async def test_get_system_scans_no_matching_runs(
    async_client: AsyncClient, admin_token: str, seeded_system
) -> None:
    """GET /systems/{id}/scans with no matching runs returns total=0, items=[]."""
    resp = await async_client.get(
        f"/systems/{seeded_system.id}/scans",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["items"] == []


# ─── Group 5: Boundary compliance (structural) ──────────────────────────────


def test_systems_router_has_no_module_imports() -> None:
    """Verify systems.py has zero imports from aila.modules.* (boundary compliance).

    Uses AST analysis to ensure no ImportFrom nodes reference aila.modules,
    preventing accidental boundary violations from being introduced.
    """
    systems_path = Path("src/aila/api/routers/systems.py")
    source = systems_path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    violations = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("aila.modules"):
            violations.append(f"line {node.lineno}: from {node.module} import ...")

    assert violations == [], (
        "Boundary violation: systems.py imports from aila.modules:\n"
        + "\n".join(violations)
    )
