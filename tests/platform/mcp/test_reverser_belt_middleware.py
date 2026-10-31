"""reverser-belt middleware: handle affinity, injection, pending poll.

:class:`aila.platform.mcp.middleware.reverser_belt.ReverserBeltMiddleware`
bridges AILA's path-addressed convention to the reverser-belt server's
handle model: it opens the server-injected ``target_path`` once via
``open_binary`` (caching ``path -> binary_id`` on the session) and
rewrites each handle tool to carry that ``binary_id``. The raw
``target_path`` is never forwarded. Background analysis that answers
``status: pending`` is re-issued until it lands ``ready`` within a
bounded wall-clock budget.

These drive the middleware with a transport-less
:class:`~aila.platform.mcp.mcp_session.McpSession` plus a fake client
exposing exactly the surface the middleware touches
(``mcp_session`` / ``recorder_context`` / ``post`` / ``list_tool_specs``)
-- no MCP server, no subprocess.
"""
from __future__ import annotations

import contextlib
import os
from typing import Any

from aila.platform.mcp.mcp_session import McpSession
from aila.platform.mcp.middleware.reverser_belt import (
    REVERSER_BELT_TARGET_KWARG,
    ReverserBeltMiddleware,
)
from aila.platform.mcp.server_specs import SERVER_SPECS

__all__: list[str] = []

_SPECS = [
    {"name": "open_binary", "params": [{"name": "path"}]},
    {"name": "list_functions", "params": [{"name": "binary_id"}]},
    {"name": "decompile", "params": [{"name": "binary_id"}, {"name": "address_or_name"}]},
    {"name": "worker_status", "params": []},
    {"name": "miasm_simplify_expression", "params": [{"name": "expression"}]},
]


class _StateSession(McpSession):
    """Session carrying only ``state`` + ``affinity``; transport unused."""

    async def request(self, method: str, params: dict[str, Any], *, timeout: float) -> Any:
        raise AssertionError(f"transport must not be used: {method}")

    async def aclose(self) -> None:
        return None


class _FakeClient:
    """McpClient stand-in for the recorder_context/post surface.

    ``open_results`` maps a path to the ``open_binary`` envelope; default
    returns a deterministic binary_id. ``pending_counts`` maps an action
    to the number of ``pending`` replies to emit before ``ready``.
    """

    def __init__(self, session: McpSession) -> None:
        self._session = session
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.open_results: dict[str, dict[str, Any]] = {}
        self.pending_counts: dict[str, int] = {}
        self._open_seq = 0

    async def mcp_session(self) -> McpSession:
        return self._session

    @contextlib.asynccontextmanager
    async def recorder_context(self, action: str):  # noqa: ANN201
        ctx: dict[str, Any] = {"action": action}
        yield ctx

    async def post(self, action: str, payload: dict[str, Any], *, ctx=None) -> dict[str, Any]:
        self.calls.append((action, dict(payload)))
        if action == "open_binary":
            path = payload.get("path")
            if path in self.open_results:
                return self.open_results[path]
            self._open_seq += 1
            return {"status": "ready", "binary_id": f"b_{self._open_seq}"}
        remaining = self.pending_counts.get(action, 0)
        if remaining > 0:
            self.pending_counts[action] = remaining - 1
            return {"status": "pending"}
        return {"status": "ready", "action": action}

    async def list_tool_specs(self) -> list[dict[str, Any]]:
        return _SPECS

    def actions(self) -> list[str]:
        return [a for a, _ in self.calls]

    def payloads_for(self, action: str) -> list[dict[str, Any]]:
        return [p for a, p in self.calls if a == action]


def _middleware() -> ReverserBeltMiddleware:
    return ReverserBeltMiddleware(spec=SERVER_SPECS["reverser_belt"], module_id="malware")


class TestHandleAffinity:
    async def test_opens_once_and_injects_binary_id(self) -> None:
        session = _StateSession()
        client = _FakeClient(session)
        mw = _middleware()

        r1 = await mw.forward(client, "list_functions", {
            REVERSER_BELT_TARGET_KWARG: "/samples/a.bin",
        })
        r2 = await mw.forward(client, "decompile", {
            "address_or_name": "main", REVERSER_BELT_TARGET_KWARG: "/samples/a.bin",
        })

        assert r1["status"] == "ready" and r2["status"] == "ready"
        # Exactly one open_binary for the shared path; binary_id cached.
        assert client.actions().count("open_binary") == 1
        assert session.state["belt_binaries"] == {"/samples/a.bin": "b_1"}
        # Both handle tools carry the resolved binary_id.
        assert client.payloads_for("list_functions")[0]["binary_id"] == "b_1"
        assert client.payloads_for("decompile")[0]["binary_id"] == "b_1"
        # target_path is consumed, never forwarded.
        for _action, payload in client.calls:
            assert REVERSER_BELT_TARGET_KWARG not in payload

    async def test_distinct_targets_open_separately(self) -> None:
        session = _StateSession()
        client = _FakeClient(session)
        mw = _middleware()

        await mw.forward(client, "list_functions", {REVERSER_BELT_TARGET_KWARG: "/a"})
        await mw.forward(client, "list_functions", {REVERSER_BELT_TARGET_KWARG: "/b"})

        assert client.actions().count("open_binary") == 2
        assert session.state["belt_binaries"] == {"/a": "b_1", "/b": "b_2"}


class TestPassthrough:
    async def test_passthrough_tool_not_opened_or_injected(self) -> None:
        session = _StateSession()
        client = _FakeClient(session)
        mw = _middleware()

        r = await mw.forward(client, "worker_status", {REVERSER_BELT_TARGET_KWARG: "/a"})

        assert r["status"] == "ready"
        assert "open_binary" not in client.actions()
        payload = client.payloads_for("worker_status")[0]
        assert "binary_id" not in payload
        assert REVERSER_BELT_TARGET_KWARG not in payload

    async def test_non_handle_tool_not_injected(self) -> None:
        session = _StateSession()
        client = _FakeClient(session)
        mw = _middleware()

        await mw.forward(client, "miasm_simplify_expression", {
            "expression": "a ^ a", REVERSER_BELT_TARGET_KWARG: "/a",
        })

        assert "open_binary" not in client.actions()
        payload = client.payloads_for("miasm_simplify_expression")[0]
        assert "binary_id" not in payload


class TestPendingPoll:
    async def test_pending_is_reissued_until_ready(self) -> None:
        os.environ["REVERSER_BELT_PENDING_POLL_INTERVAL"] = "0.01"
        os.environ["REVERSER_BELT_PENDING_POLL_TIMEOUT"] = "5"
        try:
            session = _StateSession()
            client = _FakeClient(session)
            client.pending_counts["list_functions"] = 2
            mw = _middleware()

            r = await mw.forward(client, "list_functions", {
                REVERSER_BELT_TARGET_KWARG: "/a",
            })

            assert r["status"] == "ready"
            # Initial call + 2 pending re-issues = 3 list_functions posts.
            assert client.actions().count("list_functions") == 3
        finally:
            os.environ.pop("REVERSER_BELT_PENDING_POLL_INTERVAL", None)
            os.environ.pop("REVERSER_BELT_PENDING_POLL_TIMEOUT", None)


class TestOpenFailure:
    async def test_open_error_propagates_without_handle_call(self) -> None:
        session = _StateSession()
        client = _FakeClient(session)
        client.open_results["/bad"] = {"status": "error", "error": "no such binary"}
        mw = _middleware()

        r = await mw.forward(client, "list_functions", {
            REVERSER_BELT_TARGET_KWARG: "/bad",
        })

        assert r["status"] == "error"
        # The handle tool is never dispatched when the open fails.
        assert "list_functions" not in client.actions()
        assert "/bad" not in session.state.get("belt_binaries", {})


class TestMissingTarget:
    async def test_handle_tool_without_target_errors(self) -> None:
        session = _StateSession()
        client = _FakeClient(session)
        mw = _middleware()

        r = await mw.forward(client, "list_functions", {})

        assert r["status"] == "error"
        assert "open_binary" not in client.actions()
