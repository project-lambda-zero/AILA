"""Comprehensive config router tests -- FILE-03 deep review.

Covers: admin-only PUT enforcement (RBAC), namespace/key validation,
GET/PUT contract correctness, pagination edge cases.

Created by Phase 66 Plan 01 for exhaustive config router coverage.
"""
from __future__ import annotations

import time
from collections.abc import AsyncGenerator
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel

from aila.storage.registry import ConfigRegistry

# ---------------------------------------------------------------------------
# Local test schema for config registration
# ---------------------------------------------------------------------------


class TestModConfig(BaseModel):
    max_items: int = 100
    enabled: bool = True
    label: str = "default"


# ---------------------------------------------------------------------------
# Local fixture: config_client_with_schema
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="function")
async def config_client_with_schema(test_db) -> AsyncGenerator[AsyncClient, None]:
    """Async client with a ConfigRegistry that has a registered 'testmod' schema.

    Registers TestModConfig under namespace 'testmod', which seeds 3 DB rows:
      testmod/max_items=100 (int), testmod/enabled=True (bool), testmod/label=default (str)

    Provides a real ConfigRegistry for PUT validation and GET retrieval tests.
    """
    from aila.api.app import create_app
    from aila.platform.runtime.tools import ToolRegistry

    config_registry = ConfigRegistry()
    # ConfigRegistry.register is async (registry.py:114). Missing await -> the
    # coroutine is discarded, _schemas['testmod'] stays empty, no DB rows get
    # seeded, and every test that assumes the seeded schema fails: PUT hits the
    # 'No schema registered for namespace' branch (registry.py:255) instead of
    # writing (200) or the 'Key not found' branch (registry.py:258).
    await config_registry.register("testmod", TestModConfig)

    tool_registry = ToolRegistry()

    stub_runtime = MagicMock()
    stub_runtime.config_registry = config_registry
    stub_runtime.tool_registry = tool_registry

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


# ===========================================================================
# RBAC enforcement (admin-only PUT) -- Tests 1-4
# ===========================================================================


@pytest.mark.asyncio
async def test_put_admin_returns_200(
    config_client_with_schema: AsyncClient,
    admin_token: str,
) -> None:
    """Test 1: PUT /config/testmod/max_items with admin JWT returns 200."""
    resp = await config_client_with_schema.put(
        "/config/testmod/max_items",
        json={"value": "200"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["namespace"] == "testmod"
    assert data["key"] == "max_items"
    assert data["value"] == "200"


@pytest.mark.asyncio
async def test_put_operator_returns_403(
    config_client_with_schema: AsyncClient,
    operator_token: str,
) -> None:
    """Test 2: PUT /config/testmod/max_items with operator JWT returns 403."""
    resp = await config_client_with_schema.put(
        "/config/testmod/max_items",
        json={"value": "200"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_put_reader_returns_403(
    config_client_with_schema: AsyncClient,
    reader_token: str,
) -> None:
    """Test 3: PUT /config/testmod/max_items with reader JWT returns 403."""
    resp = await config_client_with_schema.put(
        "/config/testmod/max_items",
        json={"value": "200"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_put_no_token_returns_401(
    config_client_with_schema: AsyncClient,
) -> None:
    """Test 4: PUT /config/testmod/max_items without token returns 401."""
    resp = await config_client_with_schema.put(
        "/config/testmod/max_items",
        json={"value": "200"},
    )
    assert resp.status_code == 401


# ===========================================================================
# GET contract -- single key -- Tests 5-7
# ===========================================================================


@pytest.mark.asyncio
async def test_get_existing_key_returns_200(
    config_client_with_schema: AsyncClient,
    admin_token: str,
) -> None:
    """Test 5: GET /config/testmod/max_items for existing key returns 200 with correct fields."""
    resp = await config_client_with_schema.get(
        "/config/testmod/max_items",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["namespace"] == "testmod"
    assert data["key"] == "max_items"
    assert data["value"] == "100"
    assert data["value_type"] == "int"


@pytest.mark.asyncio
async def test_get_missing_key_returns_404(
    config_client_with_schema: AsyncClient,
    admin_token: str,
) -> None:
    """Test 6: GET /config/testmod/nonexistent for missing key returns 404 with descriptive detail."""
    resp = await config_client_with_schema.get(
        "/config/testmod/nonexistent",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404
    data = resp.json()
    assert "testmod" in data["detail"]
    assert "nonexistent" in data["detail"]


@pytest.mark.asyncio
async def test_get_missing_namespace_returns_404(
    config_client_with_schema: AsyncClient,
    admin_token: str,
) -> None:
    """Test 7: GET /config/bogus_ns/bogus_key for missing namespace returns 404."""
    resp = await config_client_with_schema.get(
        "/config/bogus_ns/bogus_key",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404


# ===========================================================================
# GET contract -- list endpoints -- Tests 8-12
# ===========================================================================


@pytest.mark.asyncio
async def test_get_all_config_returns_paginated_list(
    config_client_with_schema: AsyncClient,
    admin_token: str,
) -> None:
    """Test 8: GET /config with seeded entries returns paginated list with total=3."""
    resp = await config_client_with_schema.get(
        "/config",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 3
    assert len(data["items"]) == 3
    assert data["page"] == 1


@pytest.mark.asyncio
async def test_get_namespace_config_returns_namespace_only(
    config_client_with_schema: AsyncClient,
    admin_token: str,
) -> None:
    """Test 9: GET /config/testmod returns only entries for that namespace."""
    resp = await config_client_with_schema.get(
        "/config/testmod",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 3
    for item in data["items"]:
        assert item["namespace"] == "testmod"


@pytest.mark.asyncio
async def test_get_empty_namespace_returns_zero(
    config_client_with_schema: AsyncClient,
    admin_token: str,
) -> None:
    """Test 10: GET /config/nonexistent_ns returns total=0, items=[], pages=0."""
    resp = await config_client_with_schema.get(
        "/config/nonexistent_ns",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["items"] == []
    assert data["pages"] == 0


@pytest.mark.asyncio
async def test_get_config_pagination(
    config_client_with_schema: AsyncClient,
    admin_token: str,
) -> None:
    """Test 11: GET /config page=1, page_size=1 returns 1 item, correct total and pages."""
    resp = await config_client_with_schema.get(
        "/config",
        params={"page": 1, "page_size": 1},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 1
    assert data["total"] == 3
    assert data["pages"] == 3  # ceil(3/1) = 3


@pytest.mark.asyncio
async def test_get_config_page_beyond_last(
    config_client_with_schema: AsyncClient,
    admin_token: str,
) -> None:
    """Test 12: GET /config page beyond last returns items=[], total unchanged."""
    resp = await config_client_with_schema.get(
        "/config",
        params={"page": 100, "page_size": 50},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["total"] == 3
    assert data["pages"] == 1  # ceil(3/50) = 1


# ===========================================================================
# Namespace/key validation on PUT -- Tests 13-15
# (These will FAIL until Task 2 adds ValueError->422 handling)
# ===========================================================================


@pytest.mark.asyncio
async def test_put_unregistered_namespace_returns_422(
    config_client_with_schema: AsyncClient,
    admin_token: str,
) -> None:
    """Test 13: PUT /config/unregistered_ns/some_key with admin token returns 422."""
    resp = await config_client_with_schema.put(
        "/config/unregistered_ns/some_key",
        json={"value": "anything"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422
    assert "unregistered_ns" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_put_unknown_key_returns_422(
    config_client_with_schema: AsyncClient,
    admin_token: str,
) -> None:
    """Test 14: PUT /config/testmod/bogus_key with admin token returns 422."""
    resp = await config_client_with_schema.put(
        "/config/testmod/bogus_key",
        json={"value": "anything"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422
    assert "bogus_key" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_put_bad_type_cast_returns_422(
    config_client_with_schema: AsyncClient,
    admin_token: str,
) -> None:
    """Test 15: PUT /config/testmod/max_items with 'not_a_number' returns 422 (int field)."""
    resp = await config_client_with_schema.put(
        "/config/testmod/max_items",
        json={"value": "not_a_number"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422


# ===========================================================================
# Auth on read endpoints -- Tests 16-18
# ===========================================================================


@pytest.mark.asyncio
async def test_get_config_list_no_token_returns_401(
    config_client_with_schema: AsyncClient,
) -> None:
    """Test 16: GET /config without token returns 401."""
    resp = await config_client_with_schema.get("/config")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_config_key_no_token_returns_401(
    config_client_with_schema: AsyncClient,
) -> None:
    """Test 17: GET /config/testmod/max_items without token returns 401."""
    resp = await config_client_with_schema.get("/config/testmod/max_items")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_reader_can_get_config(
    config_client_with_schema: AsyncClient,
    reader_token: str,
) -> None:
    """Test 18: Reader can GET config values (read access for all authenticated roles)."""
    resp = await config_client_with_schema.get(
        "/config/testmod/max_items",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["namespace"] == "testmod"
    assert data["key"] == "max_items"
    assert data["value"] == "100"


# ===========================================================================
# Pagination validation -- Tests 19-20
# ===========================================================================


@pytest.mark.asyncio
async def test_get_config_page_size_zero_returns_422(
    config_client_with_schema: AsyncClient,
    admin_token: str,
) -> None:
    """Test 19: GET /config page_size=0 returns 422 (violates ge=1 constraint)."""
    resp = await config_client_with_schema.get(
        "/config",
        params={"page_size": 0},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_get_config_page_size_too_large_returns_422(
    config_client_with_schema: AsyncClient,
    admin_token: str,
) -> None:
    """Test 20: GET /config page_size=251 returns 422 (violates le=250 constraint)."""
    resp = await config_client_with_schema.get(
        "/config",
        params={"page_size": 251},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422
