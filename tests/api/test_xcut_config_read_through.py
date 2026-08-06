"""Phase 101 -- XCUT-14: Config read-through verification.

Proves the full configuration chain:
  PUT /config/platform/{key} -> ConfigRegistry.set() -> DB -> get_task_tuning() reads new value

Success criteria:
  1. PUT persists the value to database (ConfigEntryRecord row updated)
  2. get_task_tuning() reads the persisted value, not the constant default
  3. No cache -- a second PUT is picked up immediately by get_task_tuning()
  4. Invalid values rejected at API (422) before they can reach get_task_tuning()
"""
from __future__ import annotations

import time
from collections.abc import AsyncGenerator
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from aila.platform.config import PlatformConfigSchema
from aila.platform.tasks import get_task_tuning
from aila.platform.tasks.constants import (
    ARQ_MAX_TRIES,
    HEARTBEAT_INTERVAL_S,
)
from aila.storage.registry import ConfigRegistry

# ---------------------------------------------------------------------------
# Fixture: async client with PlatformConfigSchema registered
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="function")
async def platform_config_client(test_db) -> AsyncGenerator[AsyncClient, None]:
    """Async client with ConfigRegistry that has PlatformConfigSchema registered.

    Registers PlatformConfigSchema under namespace 'platform', which seeds all
    platform tuning fields (heartbeat_interval_s, arq_max_tries, etc.) into the
    test DB with their default values.
    """
    from aila.api.app import create_app
    from aila.platform.runtime.tools import ToolRegistry

    config_registry = ConfigRegistry()
    # ConfigRegistry.register is async (registry.py:108) -- seeds default rows
    # into ConfigEntryRecord via async_session_scope. A missing await here left
    # _schemas empty, so every PUT below rejected as 422 with 'No schema
    # registered for namespace platform.'
    await config_registry.register("platform", PlatformConfigSchema)

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
# XCUT-14 Test 1: API write propagates to get_task_tuning
# ===========================================================================


@pytest.mark.asyncio
async def test_put_config_propagates_to_get_task_tuning(
    platform_config_client: AsyncClient,
    admin_token: str,
) -> None:
    """PUT /config/platform/heartbeat_interval_s=99 -> get_task_tuning returns 99."""
    # Verify default is in place before the write
    before = get_task_tuning("heartbeat_interval_s", HEARTBEAT_INTERVAL_S)
    assert before == HEARTBEAT_INTERVAL_S, f"Expected default {HEARTBEAT_INTERVAL_S}, got {before}"

    # Write new value via API
    resp = await platform_config_client.put(
        "/config/platform/heartbeat_interval_s",
        json={"value": "99"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["value"] == "99"

    # Read via get_task_tuning -- must see the new value, not the default
    after = get_task_tuning("heartbeat_interval_s", HEARTBEAT_INTERVAL_S)
    assert after == 99, f"get_task_tuning should return 99 after PUT, got {after}"


# ===========================================================================
# XCUT-14 Test 2: No stale cache -- second write also picked up
# ===========================================================================


@pytest.mark.asyncio
async def test_second_config_change_picked_up_without_restart(
    platform_config_client: AsyncClient,
    admin_token: str,
) -> None:
    """Two sequential PUTs: both values are picked up by get_task_tuning immediately."""
    # First write
    resp1 = await platform_config_client.put(
        "/config/platform/heartbeat_interval_s",
        json={"value": "99"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp1.status_code == 200
    assert get_task_tuning("heartbeat_interval_s", HEARTBEAT_INTERVAL_S) == 99

    # Second write -- different value
    resp2 = await platform_config_client.put(
        "/config/platform/heartbeat_interval_s",
        json={"value": "55"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp2.status_code == 200
    assert get_task_tuning("heartbeat_interval_s", HEARTBEAT_INTERVAL_S) == 55


# ===========================================================================
# XCUT-14 Test 3: Invalid values rejected at API boundary
# ===========================================================================


@pytest.mark.asyncio
async def test_invalid_config_value_rejected_at_api(
    platform_config_client: AsyncClient,
    admin_token: str,
) -> None:
    """PUT /config/platform/heartbeat_interval_s with non-int returns 422."""
    resp = await platform_config_client.put(
        "/config/platform/heartbeat_interval_s",
        json={"value": "not_a_number"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422

    # get_task_tuning must still return the default (bad value never reached DB)
    current = get_task_tuning("heartbeat_interval_s", HEARTBEAT_INTERVAL_S)
    assert current == HEARTBEAT_INTERVAL_S, (
        f"Bad value should not persist -- expected {HEARTBEAT_INTERVAL_S}, got {current}"
    )


# ===========================================================================
# XCUT-14 Test 4: Multiple independent keys
# ===========================================================================


@pytest.mark.asyncio
async def test_multiple_config_keys_independent(
    platform_config_client: AsyncClient,
    admin_token: str,
) -> None:
    """PUT two different keys; get_task_tuning reads each independently."""
    # Set heartbeat to 99
    resp1 = await platform_config_client.put(
        "/config/platform/heartbeat_interval_s",
        json={"value": "99"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp1.status_code == 200

    # Set arq_max_tries to 7
    resp2 = await platform_config_client.put(
        "/config/platform/arq_max_tries",
        json={"value": "7"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp2.status_code == 200

    # Both reads return their respective new values
    assert get_task_tuning("heartbeat_interval_s", HEARTBEAT_INTERVAL_S) == 99
    assert get_task_tuning("arq_max_tries", ARQ_MAX_TRIES) == 7


# ===========================================================================
# XCUT-14 Test 5: get_task_tuning reads DB on every call (no in-memory cache)
# ===========================================================================


@pytest.mark.asyncio
async def test_get_task_tuning_reads_db_every_call(
    platform_config_client: AsyncClient,
    admin_token: str,
) -> None:
    """Interleave PUT and get_task_tuning calls to prove no stale in-memory cache."""
    values = [10, 20, 30, 40, 50]
    for val in values:
        resp = await platform_config_client.put(
            "/config/platform/heartbeat_interval_s",
            json={"value": str(val)},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        read_val = get_task_tuning("heartbeat_interval_s", HEARTBEAT_INTERVAL_S)
        assert read_val == val, f"After PUT {val}, get_task_tuning returned {read_val}"
