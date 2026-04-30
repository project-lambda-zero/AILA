"""Deep review tests for tools router (Phase 72).

Covers branches NOT tested by test_coverage_tools.py:
  - Auth still works after removing redundant endpoint-level Depends(require_api_key)
  - Unauthenticated requests still blocked by router-level dependency
  - Operator invoke RBAC (operator allowed, no-auth blocked, empty kwargs)
  - Multi-tool discovery with correct module_ids
  - Non-dict inputs edge case (isinstance false branch)
  - Invoke boundary 404 with tool name in error message
  - Platform unavailable 503 for GET and POST

FILE-09: every function read, every branch tested, zero dead code.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient


# ---------------------------------------------------------------------------
# Mock tool matching ToolProtocol
# ---------------------------------------------------------------------------


@dataclass
class _MockTool:
    name: str = "mock_tool"
    description: str = "A mock tool for testing"

    def forward(self, **kwargs: Any) -> Any:
        return {"echo": kwargs}


# ===========================================================================
# Group 1: Redundancy removal verification
# ===========================================================================


@pytest.mark.asyncio
async def test_list_tools_auth_via_router_dependency(
    async_client_with_registries: AsyncClient,
    admin_token: str,
) -> None:
    """GET /tools with admin token returns 200 after endpoint-level Depends removal.

    FILE-09: Proves router-level dependencies=[Depends(require_api_key)] covers
    the list_tools endpoint after removing redundant endpoint-level Depends.
    """
    client = async_client_with_registries
    app = client._transport.app  # type: ignore[attr-defined]
    registry = app.state.platform.runtime.tool_registry
    registry.register("test.probe", _MockTool(name="probe", description="Auth probe"))

    resp = await client.get(
        "/tools",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert any(t["tool_key"] == "test.probe" for t in data)


@pytest.mark.asyncio
async def test_get_tool_detail_auth_via_router_dependency(
    async_client_with_registries: AsyncClient,
    admin_token: str,
) -> None:
    """GET /tools/{key} with admin token returns 200 after endpoint-level Depends removal.

    FILE-09: Proves router-level dependency covers the get_tool detail endpoint.
    """
    client = async_client_with_registries
    app = client._transport.app  # type: ignore[attr-defined]
    registry = app.state.platform.runtime.tool_registry
    registry.register("test.detail_auth", _MockTool(name="detail_auth", description="Detail auth probe"))

    resp = await client.get(
        "/tools/test.detail_auth",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["tool_key"] == "test.detail_auth"


@pytest.mark.asyncio
async def test_list_tools_no_auth_returns_401(
    async_client_with_registries: AsyncClient,
) -> None:
    """GET /tools without auth returns 401.

    FILE-09: Proves router-level require_api_key still blocks unauthenticated
    requests after endpoint-level Depends removal.
    """
    resp = await async_client_with_registries.get("/tools")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_tool_detail_no_auth_returns_401(
    async_client_with_registries: AsyncClient,
) -> None:
    """GET /tools/{key} without auth returns 401.

    FILE-09: Proves router-level require_api_key blocks unauthenticated detail requests.
    """
    resp = await async_client_with_registries.get("/tools/any.tool")
    assert resp.status_code == 401


# ===========================================================================
# Group 2: Invoke RBAC (operator+ required)
# ===========================================================================


@pytest.mark.asyncio
async def test_invoke_tool_operator_allowed(
    async_client_with_registries: AsyncClient,
    operator_token: str,
) -> None:
    """POST /tools/{key} with operator token returns 200.

    FILE-09: Proves operator role satisfies require_role(ROLE_OPERATOR) on invoke.
    """
    client = async_client_with_registries
    app = client._transport.app  # type: ignore[attr-defined]
    registry = app.state.platform.runtime.tool_registry
    registry.register("test.op_invoke", _MockTool(name="op_tool", description="Operator invoke test"))

    resp = await client.post(
        "/tools/test.op_invoke",
        json={"kwargs": {"x": 42}},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["result"] == {"echo": {"x": 42}}
    assert data["error"] is None


@pytest.mark.asyncio
async def test_invoke_tool_no_auth_returns_401(
    async_client_with_registries: AsyncClient,
) -> None:
    """POST /tools/{key} without any auth returns 401.

    FILE-09: Proves unauthenticated invoke is blocked at the API key level
    (router-level dependency) before even reaching role check.
    """
    resp = await async_client_with_registries.post(
        "/tools/any.tool",
        json={"kwargs": {}},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_invoke_tool_empty_kwargs(
    async_client_with_registries: AsyncClient,
    admin_token: str,
) -> None:
    """POST /tools/{key} with empty kwargs returns 200 with echo of empty dict.

    FILE-09: Proves ToolInvokeRequest defaults kwargs to empty dict and forward()
    receives no arguments.
    """
    client = async_client_with_registries
    app = client._transport.app  # type: ignore[attr-defined]
    registry = app.state.platform.runtime.tool_registry
    registry.register("test.empty_kwargs", _MockTool(name="empty_tool", description="Empty kwargs test"))

    resp = await client.post(
        "/tools/test.empty_kwargs",
        json={"kwargs": {}},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["result"] == {"echo": {}}


# ===========================================================================
# Group 3: Tool discovery edge cases
# ===========================================================================


@pytest.mark.asyncio
async def test_list_tools_multiple_with_correct_module_ids(
    async_client_with_registries: AsyncClient,
    admin_token: str,
) -> None:
    """GET /tools with multiple registered tools returns all with correct module_ids.

    FILE-09: Proves _module_id_from_key correctly derives module_id for dotted keys
    and falls back to 'platform' for bare keys, across multiple tools in one response.
    """
    client = async_client_with_registries
    app = client._transport.app  # type: ignore[attr-defined]
    registry = app.state.platform.runtime.tool_registry
    registry.register("vuln.scanner", _MockTool(name="scanner", description="Vuln scanner"))
    registry.register("net.probe", _MockTool(name="probe", description="Net probe"))
    registry.register("standalone", _MockTool(name="standalone", description="No dot tool"))

    resp = await client.get(
        "/tools",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 3

    by_key = {t["tool_key"]: t for t in data}
    assert by_key["vuln.scanner"]["module_id"] == "vuln"
    assert by_key["net.probe"]["module_id"] == "net"
    assert by_key["standalone"]["module_id"] == "platform"


@pytest.mark.asyncio
async def test_get_tool_detail_non_dict_inputs(
    async_client_with_registries: AsyncClient,
    admin_token: str,
) -> None:
    """GET /tools/{key} with non-dict inputs attr returns inputs as empty dict.

    FILE-09: Exercises the isinstance(raw_inputs, dict) false branch -- tool has
    an inputs attribute but it is not a dict (e.g., a list), so response defaults
    to empty dict.
    """
    client = async_client_with_registries
    app = client._transport.app  # type: ignore[attr-defined]
    registry = app.state.platform.runtime.tool_registry

    # Create a tool-like mock with inputs set to a non-dict value
    non_dict_tool = MagicMock()
    non_dict_tool.name = "non_dict_tool"
    non_dict_tool.description = "Tool with list inputs"
    non_dict_tool.inputs = ["not", "a", "dict"]
    non_dict_tool.output_type = "json"
    registry.register("test.non_dict_inputs", non_dict_tool)

    resp = await client.get(
        "/tools/test.non_dict_inputs",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["inputs"] == {}
    assert data["output_type"] == "json"


# ===========================================================================
# Group 4: Invoke boundary 404
# ===========================================================================


@pytest.mark.asyncio
async def test_invoke_nonexistent_tool_404_contains_name(
    async_client_with_registries: AsyncClient,
    admin_token: str,
) -> None:
    """POST /tools/nonexistent returns 404 with tool name in error message.

    FILE-09: Proves the boundary 404 (raised outside asyncio.to_thread after
    Task 1 fix) includes the tool_key in the detail message for debugging.
    """
    resp = await async_client_with_registries.post(
        "/tools/nonexistent.tool",
        json={"kwargs": {}},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404
    detail = resp.json()["detail"]
    assert "nonexistent.tool" in detail


# ===========================================================================
# Group 5: Platform unavailable (503)
# ===========================================================================


@pytest.mark.asyncio
async def test_list_tools_platform_none_returns_503(
    async_client: AsyncClient,
    admin_token: str,
) -> None:
    """GET /tools when platform is None returns 503.

    FILE-09: Proves get_tool_registry dependency raises 503 when platform
    is not initialized (async_client fixture sets platform=None).
    """
    resp = await async_client.get(
        "/tools",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_invoke_tool_platform_none_returns_503(
    async_client: AsyncClient,
    admin_token: str,
) -> None:
    """POST /tools/{key} when platform is None returns 503.

    FILE-09: Proves get_tool_registry dependency raises 503 for invoke endpoint
    when platform is not initialized.
    """
    resp = await async_client.post(
        "/tools/any.tool",
        json={"kwargs": {}},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 503
