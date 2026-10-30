"""REA middleware target-affinity tests.

:class:`aila.platform.mcp.middleware.rea.ReaMiddleware` serializes
per-session access to REA's single active target while letting calls
against the ACTIVE target run concurrently. These tests drive the
middleware with a fake :class:`~aila.platform.mcp.client.McpClient` +
a real (transport-less) :class:`~aila.platform.mcp.mcp_session.McpSession`
so the ``affinity`` condition / ``state`` dict behave exactly as in
production -- no MCP server, no subprocess, no Docker.

Pinned behaviours:

* Same-target calls overlap (they join the active target without
  waiting for the in-flight set to drain).
* A different target waits for every in-flight call to finish, then
  switches with one ``open_binary`` while holding the condition.
* An ``open_binary`` failure is returned to the caller and leaves NO
  in-flight slot held (no leak -> no wedge for the next target).
* The server-injected ``target_path`` kwarg is consumed by the
  middleware and never forwarded to REA verbatim.
"""
from __future__ import annotations

import asyncio
from typing import Any

from aila.platform.mcp.mcp_session import McpSession
from aila.platform.mcp.middleware.rea import (
    REA_TARGET_KWARG,
    ReaMiddleware,
)
from aila.platform.mcp.server_specs import SERVER_SPECS

__all__: list[str] = []



class _StateSession(McpSession):
    """Session carrying only ``state`` + ``affinity``; the fake client
    answers calls itself, so the transport methods are never reached."""

    async def request(self, method: str, params: dict[str, Any], *, timeout: float) -> Any:
        raise AssertionError(f"transport must not be used: {method}")

    async def aclose(self) -> None:
        return None


class _FakeClient:
    """Minimal McpClient stand-in recording every call_tool dispatch.

    ``gates`` maps an action name to an :class:`asyncio.Event` that must
    be set before the call returns -- the hook the concurrency/drain
    tests use to hold a call in flight deterministically. ``open_results``
    maps a path to the ``open_binary`` envelope to return (default ready).
    """

    def __init__(self, session: McpSession) -> None:
        self._session = session
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.open_results: dict[str, dict[str, Any]] = {}
        self.gates: dict[str, asyncio.Event] = {}

    async def mcp_session(self) -> McpSession:
        return self._session

    async def call_tool(
        self, action: str, payload: dict[str, Any],
    ) -> dict[str, Any]:
        self.calls.append((action, dict(payload)))
        if action == "open_binary":
            return self.open_results.get(
                payload.get("path"), {"status": "ready"},
            )
        gate = self.gates.get(action)
        if gate is not None:
            await gate.wait()
        return {"status": "ready", "action": action}

    def actions(self) -> list[str]:
        return [a for a, _ in self.calls]

    def payloads_for(self, action: str) -> list[dict[str, Any]]:
        return [p for a, p in self.calls if a == action]


def _middleware() -> ReaMiddleware:
    return ReaMiddleware(spec=SERVER_SPECS["rea"], module_id="vr")


async def _wait_for(predicate, timeout: float = 5.0) -> None:
    """Poll ``predicate`` until it returns truthy (tests, not production)."""
    deadline = asyncio.get_event_loop().time() + timeout
    while True:
        if predicate():
            return
        if asyncio.get_event_loop().time() > deadline:
            raise AssertionError("predicate never became true")
        await asyncio.sleep(0.01)


# ---------------------------------------------------------------------------
# Same-target concurrency
# ---------------------------------------------------------------------------


class TestSameTargetConcurrency:
    async def test_same_target_calls_overlap(self) -> None:
        session = _StateSession()
        client = _FakeClient(session)
        mw = _middleware()
        client.gates["analyze_function"] = asyncio.Event()

        async def call() -> dict[str, Any]:
            return await mw.forward(client, "analyze_function", {
                "procedure": "main", REA_TARGET_KWARG: "/samples/a.bin",
            })

        first = asyncio.ensure_future(call())
        await _wait_for(lambda: session.state.get("inflight") == 1)
        # While the first call is in flight, the second joins the SAME
        # target instead of queueing behind it.
        second = asyncio.ensure_future(call())
        await _wait_for(lambda: session.state.get("inflight") == 2)

        client.gates["analyze_function"].set()
        r1, r2 = await asyncio.gather(first, second)
        assert r1["status"] == "ready" and r2["status"] == "ready"
        # ONE open_binary for the shared target, two analysis calls.
        assert client.actions().count("open_binary") == 1
        assert client.actions().count("analyze_function") == 2
        assert session.state["active_target"] == "/samples/a.bin"
        assert session.state["inflight"] == 0


# ---------------------------------------------------------------------------
# Different target: drain in-flight, then open_binary
# ---------------------------------------------------------------------------


class TestTargetSwitchDrain:
    async def test_different_target_waits_for_drain_then_opens(
        self,
    ) -> None:
        session = _StateSession()
        client = _FakeClient(session)
        mw = _middleware()
        client.gates["procedure_info"] = asyncio.Event()

        holder = asyncio.ensure_future(
            mw.forward(client, "procedure_info", {
                "procedure": "p", REA_TARGET_KWARG: "/a",
            }),
        )
        await _wait_for(lambda: session.state.get("inflight") == 1)

        waiter = asyncio.ensure_future(
            mw.forward(client, "binary_overview", {
                REA_TARGET_KWARG: "/b",
            }),
        )
        await asyncio.sleep(0.2)
        # Still waiting: the other target's call is in flight, so no
        # open_binary for /b has been issued yet.
        assert ("open_binary", {"path": "/b"}) not in client.calls
        assert session.state["active_target"] == "/a"

        # Let the /a call finish; /b drains, opens, then runs.
        client.gates["procedure_info"].set()
        results = await asyncio.gather(holder, waiter)
        assert all(r["status"] == "ready" for r in results)
        assert session.state["active_target"] == "/b"
        # Ordering: /b's open_binary happened only AFTER /a's tool call.
        assert client.actions().index("binary_overview") > (
            client.actions().index("procedure_info")
        )
        assert ("open_binary", {"path": "/b"}) in client.calls


# ---------------------------------------------------------------------------
# open_binary failure: returned, no in-flight leak
# ---------------------------------------------------------------------------


class TestOpenBinaryError:
    async def test_open_error_returned_without_inflight_leak(self) -> None:
        session = _StateSession()
        client = _FakeClient(session)
        mw = _middleware()
        client.open_results["/corrupt"] = {
            "status": "error", "error": "not a recognized binary",
        }

        result = await mw.forward(client, "analyze_function", {
            "procedure": "main", REA_TARGET_KWARG: "/corrupt",
        })
        assert result["status"] == "error"
        assert result["error"] == "not a recognized binary"
        # No slot held, no active target set: the next target is free
        # to open (the condition is not wedged).
        assert session.state.get("inflight", 0) == 0
        assert "active_target" not in session.state

    async def test_recovery_after_open_error_opens_next_target(self) -> None:
        session = _StateSession()
        client = _FakeClient(session)
        mw = _middleware()
        client.open_results["/corrupt"] = {"status": "error", "error": "bad"}

        bad = await mw.forward(client, "analyze_function", {
            REA_TARGET_KWARG: "/corrupt",
        })
        assert bad["status"] == "error"
        good = await mw.forward(client, "analyze_function", {
            REA_TARGET_KWARG: "/good",
        })
        assert good["status"] == "ready"
        assert ("open_binary", {"path": "/good"}) in client.calls


# ---------------------------------------------------------------------------
# target_path handling
# ---------------------------------------------------------------------------


class TestTargetPathKwarg:
    async def test_target_path_never_forwarded_verbatim(self) -> None:
        session = _StateSession()
        client = _FakeClient(session)
        mw = _middleware()
        await mw.forward(client, "list_procedures", {
            "limit": 5, REA_TARGET_KWARG: "/a",
        })
        payloads = client.payloads_for("list_procedures")
        assert payloads == [{"limit": 5}]
        for _action, payload in client.calls:
            assert REA_TARGET_KWARG not in payload

    async def test_path_arg_tool_defaults_path_from_target(self) -> None:
        # Offline inspection tools take an explicit ``path``; when the
        # agent omits it the middleware defaults it from target_path
        # (still never forwarding the target_path key itself).
        session = _StateSession()
        client = _FakeClient(session)
        mw = _middleware()
        await mw.forward(client, "inspect_pe_imports", {
            REA_TARGET_KWARG: "/a",
        })
        assert client.payloads_for("inspect_pe_imports") == [{"path": "/a"}]

    async def test_agent_supplied_path_wins_over_target(self) -> None:
        session = _StateSession()
        client = _FakeClient(session)
        mw = _middleware()
        await mw.forward(client, "inspect_pe_imports", {
            "path": "/other/dll", REA_TARGET_KWARG: "/a",
        })
        assert client.payloads_for("inspect_pe_imports") == [{"path": "/other/dll"}]

    async def test_no_target_passthrough(self) -> None:
        # A call with no target_path (settings, session queries) goes
        # straight through untouched.
        session = _StateSession()
        client = _FakeClient(session)
        mw = _middleware()
        result = await mw.forward(client, "binary_session", {})
        assert result["status"] == "ready"
        assert client.calls == [("binary_session", {})]


# ---------------------------------------------------------------------------
# Explicit open/close clears the remembered target
# ---------------------------------------------------------------------------


class TestExplicitOpenClose:
    async def test_explicit_open_forgets_affinity(self) -> None:
        session = _StateSession()
        client = _FakeClient(session)
        mw = _middleware()
        await mw.forward(client, "analyze_function", {
            REA_TARGET_KWARG: "/a",
        })
        assert session.state["active_target"] == "/a"
        # Agent-driven open_binary changes the target out of band; the
        # middleware must forget its cached active target.
        await mw.forward(client, "open_binary", {"path": "/elsewhere"})
        assert "active_target" not in session.state
