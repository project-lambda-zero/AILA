"""Coverage tests for tools.py router uncovered paths.

Targets lines 37, 51-52, 72-102, 119-135 in src/aila/api/routers/tools.py.

Tests use async_client_with_registries fixture (real ToolRegistry)
and register mock tool entries to exercise list, detail, invoke, and
the _module_id_from_key helper.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

import pytest
from httpx import AsyncClient

from aila.api.routers.tools import _module_id_from_key

# ---------------------------------------------------------------------------
# Mock tool that satisfies ToolProtocol
# ---------------------------------------------------------------------------


@dataclass
class _MockTool:
    name: str = "mock_tool"
    description: str = "A mock tool for testing"
    inputs: dict[str, object] | None = None
    output_type: str = "string"

    def forward(self, **kwargs: Any) -> Any:
        return {"echo": kwargs}


@dataclass
class _FailingTool:
    name: str = "failing_tool"
    description: str = "A tool that raises on forward()"

    def forward(self, **kwargs: Any) -> Any:
        raise RuntimeError("tool invocation error")


@dataclass
class _AsyncMockTool:
    name: str = "async_mock_tool"
    description: str = "An async mock tool for testing"
    inputs: dict[str, object] | None = None
    output_type: str = "dict"

    async def forward(self, **kwargs: Any) -> Any:
        return {"echo": kwargs}


@dataclass
class _AsyncFailingTool:
    name: str = "async_failing_tool"
    description: str = "An async tool that raises when awaited"

    async def forward(self, **kwargs: Any) -> Any:
        raise RuntimeError("async tool invocation error")


@dataclass
class _ThreadRecordingTool:
    name: str = "thread_recording_tool"
    description: str = "Records the thread that forward() runs on"
    seen_threads: list[int] = field(default_factory=list)

    def forward(self, **kwargs: Any) -> Any:
        self.seen_threads.append(threading.get_ident())
        return {"echo": kwargs}


# ---------------------------------------------------------------------------
# Unit test: _module_id_from_key
# ---------------------------------------------------------------------------


def test_module_id_from_key_with_dot() -> None:
    """_module_id_from_key('vuln.query') returns 'vuln'."""
    assert _module_id_from_key("vuln.query_cves") == "vuln"


def test_module_id_from_key_without_dot() -> None:
    """_module_id_from_key('standalone') returns 'platform' (TRACK_PLATFORM)."""
    assert _module_id_from_key("standalone") == "platform"


def test_module_id_from_key_nested_dots() -> None:
    """_module_id_from_key('a.b.c') returns 'a' (first segment)."""
    assert _module_id_from_key("a.b.c") == "a"


# ---------------------------------------------------------------------------
# Integration tests: GET /tools (list)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_tools_with_registered_tool(
    async_client_with_registries: AsyncClient,
    admin_token: str,
) -> None:
    """GET /tools with a registered tool returns 200 with tool list.

    Covers lines 48-62 (inner loop in list_tools).
    """
    # Register a tool in the fixture's ToolRegistry
    client = async_client_with_registries
    app = client._transport.app  # type: ignore[attr-defined]
    registry = app.state.platform.runtime.tool_registry
    registry.register("vuln.test_tool", _MockTool(name="test_tool", description="A test tool"))

    resp = await client.get(
        "/tools",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1

    tool_entry = next(t for t in data if t["tool_key"] == "vuln.test_tool")
    assert tool_entry["name"] == "test_tool"
    assert tool_entry["description"] == "A test tool"
    assert tool_entry["module_id"] == "vuln"


@pytest.mark.asyncio
async def test_list_tools_empty_registry(
    async_client_with_registries: AsyncClient,
    admin_token: str,
) -> None:
    """GET /tools with empty registry returns 200 with empty list."""
    resp = await async_client_with_registries.get(
        "/tools",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    assert resp.json() == []


# ---------------------------------------------------------------------------
# Integration tests: GET /tools/{key} (detail)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_tool_detail_found(
    async_client_with_registries: AsyncClient,
    admin_token: str,
) -> None:
    """GET /tools/{key} with registered tool returns 200 with full detail.

    Covers lines 72-102 (get_tool detail path).
    """
    client = async_client_with_registries
    app = client._transport.app  # type: ignore[attr-defined]
    registry = app.state.platform.runtime.tool_registry

    tool = _MockTool(
        name="detail_tool",
        description="Tool with schema",
        inputs={"query": {"type": "string"}},
        output_type="dict",
    )
    registry.register("vuln.detail_tool", tool)

    resp = await client.get(
        "/tools/vuln.detail_tool",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["tool_key"] == "vuln.detail_tool"
    assert data["name"] == "detail_tool"
    assert data["module_id"] == "vuln"
    assert data["inputs"] == {"query": {"type": "string"}}
    assert data["output_type"] == "dict"


@pytest.mark.asyncio
async def test_get_tool_detail_not_found(
    async_client_with_registries: AsyncClient,
    admin_token: str,
) -> None:
    """GET /tools/nonexistent.key returns 404.

    Covers line 97-101 (KeyError -> 404 path).
    """
    resp = await async_client_with_registries.get(
        "/tools/nonexistent.key",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404
    assert "not registered" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_get_tool_detail_no_inputs_attr(
    async_client_with_registries: AsyncClient,
    admin_token: str,
) -> None:
    """GET /tools/{key} when tool has no inputs attr returns empty dict for inputs."""
    client = async_client_with_registries
    app = client._transport.app  # type: ignore[attr-defined]
    registry = app.state.platform.runtime.tool_registry

    # Real ToolProtocol double that lacks inputs/output_type attrs
    @dataclass
    class _BareTool:
        name: str = "bare_tool"
        description: str = "No inputs"

        def forward(self, **kwargs: Any) -> Any:
            return {}

    registry.register("platform.bare_tool", _BareTool())

    resp = await client.get(
        "/tools/platform.bare_tool",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["inputs"] == {}
    assert data["output_type"] == "string"  # default


# ---------------------------------------------------------------------------
# Integration tests: POST /tools/{key} (invoke)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_invoke_tool_success(
    async_client_with_registries: AsyncClient,
    admin_token: str,
) -> None:
    """POST /tools/{key} with valid kwargs returns 200 with result.

    Covers lines 119-135 (invoke_tool success path).
    Requires operator+ role; admin qualifies.
    """
    client = async_client_with_registries
    app = client._transport.app  # type: ignore[attr-defined]
    registry = app.state.platform.runtime.tool_registry
    registry.register("vuln.invoke_test", _MockTool())

    resp = await client.post(
        "/tools/vuln.invoke_test",
        json={"kwargs": {"x": 1}},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["tool_key"] == "vuln.invoke_test"
    assert data["result"] == {"echo": {"x": 1}}
    assert data["error"] is None


@pytest.mark.asyncio
async def test_invoke_tool_not_found(
    async_client_with_registries: AsyncClient,
    admin_token: str,
) -> None:
    """POST /tools/nonexistent.key returns 404."""
    resp = await async_client_with_registries.post(
        "/tools/nonexistent.key",
        json={"kwargs": {}},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404
    assert "not registered" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_invoke_tool_error(
    async_client_with_registries: AsyncClient,
    admin_token: str,
) -> None:
    """POST /tools/{key} when forward() raises returns 200 with error field.

    Tool errors are returned in the error field, not as HTTP errors (per docstring).
    Covers the except branch in _invoke (lines 130-132).
    """
    client = async_client_with_registries
    app = client._transport.app  # type: ignore[attr-defined]
    registry = app.state.platform.runtime.tool_registry
    registry.register("vuln.failing", _FailingTool())

    resp = await client.post(
        "/tools/vuln.failing",
        json={"kwargs": {}},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["result"] is None
    assert "tool invocation error" in data["error"]


@pytest.mark.asyncio
async def test_invoke_tool_awaits_async_forward(
    async_client_with_registries: AsyncClient,
    admin_token: str,
) -> None:
    """POST /tools/{key} awaits an async forward() and returns its resolved dict, not a coroutine."""
    client = async_client_with_registries
    app = client._transport.app  # type: ignore[attr-defined]
    registry = app.state.platform.runtime.tool_registry
    registry.register("vuln.async_invoke", _AsyncMockTool())

    resp = await client.post(
        "/tools/vuln.async_invoke",
        json={"kwargs": {"x": 1}},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["tool_key"] == "vuln.async_invoke"
    assert data["result"] == {"echo": {"x": 1}}
    assert data["error"] is None


@pytest.mark.asyncio
async def test_invoke_tool_async_error_returns_error_field(
    async_client_with_registries: AsyncClient,
    admin_token: str,
) -> None:
    """POST /tools/{key} when an async forward() raises when awaited returns 200 with the error field."""
    client = async_client_with_registries
    app = client._transport.app  # type: ignore[attr-defined]
    registry = app.state.platform.runtime.tool_registry
    registry.register("vuln.async_failing", _AsyncFailingTool())

    resp = await client.post(
        "/tools/vuln.async_failing",
        json={"kwargs": {}},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["result"] is None
    assert data["error"] == "async tool invocation error"


@pytest.mark.asyncio
async def test_invoke_tool_sync_forward_runs_off_event_loop(
    async_client_with_registries: AsyncClient,
    admin_token: str,
) -> None:
    """POST /tools/{key} keeps a blocking synchronous forward() on a worker thread and returns its value."""
    client = async_client_with_registries
    app = client._transport.app  # type: ignore[attr-defined]
    registry = app.state.platform.runtime.tool_registry
    tool = _ThreadRecordingTool()
    registry.register("vuln.thread_probe", tool)

    resp = await client.post(
        "/tools/vuln.thread_probe",
        json={"kwargs": {}},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["result"] == {"echo": {}}
    assert data["error"] is None
    assert len(tool.seen_threads) == 1
    assert tool.seen_threads[0] != threading.get_ident()


@pytest.mark.asyncio
async def test_invoke_tool_reader_forbidden(
    async_client_with_registries: AsyncClient,
    reader_token: str,
) -> None:
    """POST /tools/{key} with reader token returns 403 (operator+ required)."""
    resp = await async_client_with_registries.post(
        "/tools/any.tool",
        json={"kwargs": {}},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 403
