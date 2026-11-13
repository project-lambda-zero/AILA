"""Direct tool invocation honours the operator_invocable declaration (#517).

A tool that does not declare operator access is refused for operators and
team-scoped admins before it runs; a platform administrator (admin role,
team_id None) may invoke any registered tool.
"""
from __future__ import annotations

import time
import uuid
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from aila.api.app import create_app
from aila.api.auth import AuthContext, require_user_or_api_key
from aila.platform.runtime.tools import ToolRegistry
from aila.platform.tools import Tool


class _RecordingTool(Tool):
    description = "Records each invocation."

    def __init__(self, name: str) -> None:
        self.name = name
        self.calls: list[dict[str, object]] = []

    def forward(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(kwargs)
        return {"ran": self.name}


class _OperatorTool(_RecordingTool):
    operator_invocable = True


@pytest_asyncio.fixture(scope="function")
async def invoke_app(test_db):
    registry = ToolRegistry()
    tools = {
        "test.declared": _OperatorTool("declared"),
        "test.undeclared": _RecordingTool("undeclared"),
    }
    for key, tool in tools.items():
        registry.register(key, tool)
    stub_platform = MagicMock()
    stub_platform.runtime.tool_registry = registry
    app = create_app()
    app.state.platform = stub_platform
    app.state.start_time = time.monotonic()
    return app, tools


def _principal(role: str, *, scoped: bool) -> AuthContext:
    return AuthContext(
        user_id=f"{role}-{uuid.uuid4().hex}",
        role=role,
        auth_type="user",
        team_id=f"team-{uuid.uuid4().hex}" if scoped else None,
    )


async def _invoke(app, principal: AuthContext, tool_key: str):
    app.dependency_overrides[require_user_or_api_key] = lambda: principal
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        return await c.post(f"/tools/{tool_key}", json={"kwargs": {"probe": 1}})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("role", "scoped"),
    [("operator", True), ("operator", False), ("admin", True)],
    ids=["team-operator", "teamless-operator", "team-admin"],
)
async def test_undeclared_tool_is_refused_before_it_runs(invoke_app, role: str, scoped: bool) -> None:
    app, tools = invoke_app

    response = await _invoke(app, _principal(role, scoped=scoped), "test.undeclared")

    assert response.status_code == 403
    assert tools["test.undeclared"].calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("role", "scoped"),
    [("operator", True), ("admin", True), ("admin", False)],
    ids=["team-operator", "team-admin", "platform-admin"],
)
async def test_declared_tool_runs_for_operators_and_admins(invoke_app, role: str, scoped: bool) -> None:
    app, tools = invoke_app

    response = await _invoke(app, _principal(role, scoped=scoped), "test.declared")

    assert response.status_code == 200
    assert response.json()["result"] == {"ran": "declared"}
    assert tools["test.declared"].calls == [{"probe": 1}]


@pytest.mark.asyncio
async def test_platform_admin_runs_undeclared_tool(invoke_app) -> None:
    app, tools = invoke_app

    response = await _invoke(app, _principal("admin", scoped=False), "test.undeclared")

    assert response.status_code == 200
    assert response.json()["result"] == {"ran": "undeclared"}
    assert tools["test.undeclared"].calls == [{"probe": 1}]
