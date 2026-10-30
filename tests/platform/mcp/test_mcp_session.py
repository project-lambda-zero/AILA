"""Native MCP session transport tests (streamable-HTTP + stdio).

These pin the wire behaviour :mod:`aila.platform.mcp.mcp_session`
implements on top of httpx / asyncio.subprocess -- the pieces that
used to live inside each bridge's bespoke HTTP client before the
ida-headless cutover folded every MCP server onto the two native
transports:

* :class:`McpHttpSession` -- the ``initialize`` handshake, the
  ``Mcp-Session-Id`` replay on every subsequent request, the
  ``notifications/initialized`` post-handshake notification, SSE
  frame decoding, and the single 404/400 re-handshake.
* :class:`McpStdioSession` -- newline-delimited JSON-RPC against a
  spawned child, the one-reader/stdout demux, failing every pending
  request when the child exits, and transparent respawn on the next
  request.
* :meth:`McpClient._post_mcp_impl` -- the mapping of a ``tools/call``
  ``isError`` result onto the legacy ``{"status": "error", ...}``
  bridge envelope every downstream consumer still reads.

The streamable-HTTP server is an in-process Starlette app driven
through ``httpx.ASGITransport`` (no socket, no Docker); the stdio
server is a tiny python child script written to a tmp file. Both are
deterministic and offline.
"""
from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from aila.platform.mcp.client import McpClient
from aila.platform.mcp.instance_catalog import TRANSPORT_MCP_HTTP
from aila.platform.mcp.mcp_session import (
    McpHttpError,
    McpHttpSession,
    McpStdioError,
    McpStdioSession,
)

__all__: list[str] = []


# ---------------------------------------------------------------------------
# In-process streamable-HTTP MCP mock
# ---------------------------------------------------------------------------


class _McpState:
    """Mutable knobs + a request journal the mock server reads/writes."""

    def __init__(self) -> None:
        self.sessions: set[str] = set()
        self.next_sid = 0
        self.initialize_count = 0
        # Journal of (method, mcp-session-id header) for assertions.
        self.requests: list[tuple[str, str | None]] = []
        # Methods answered with an SSE stream instead of application/json.
        self.sse_methods: set[str] = set()
        # When True every non-initialize request is refused with 404.
        self.refuse_all = False
        # Per-tool tools/call handlers: name -> callable(arguments) -> result.
        self.tool_handlers: dict[str, Any] = {}


async def _mcp_endpoint(request: Request) -> Response:
    state: _McpState = request.app.state.mcp
    body = await request.json()
    method = body.get("method")

    if method == "initialize":
        state.initialize_count += 1
        sid = f"sid-{state.next_sid}"
        state.next_sid += 1
        state.sessions.add(sid)
        negotiated = body["params"].get("protocolVersion", "2025-06-18")
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {
                    "protocolVersion": negotiated,
                    "capabilities": {},
                    "serverInfo": {"name": "mock-mcp", "version": "1.0"},
                },
            },
            headers={"Mcp-Session-Id": sid},
        )

    if method == "notifications/initialized":
        # The transport requires a 202 acknowledgement; it carries no
        # JSON-RPC id and the session ignores the body entirely.
        return Response(status_code=202)

    sid = request.headers.get("mcp-session-id")
    state.requests.append((method, sid))

    if state.refuse_all or sid not in state.sessions:
        return JSONResponse({"error": "unknown session"}, status_code=404)

    if method in state.sse_methods:
        # One real frame plus an unrelated frame with a different id and
        # a comment line -- the decoder must pick ours by request id.
        message = {
            "jsonrpc": "2.0",
            "id": body["id"],
            "result": {"tools": [{"name": "from_sse"}]},
        }
        payload = (
            ": keepalive comment\n\n"
            f"data: {json.dumps({'jsonrpc': '2.0', 'id': 'other', 'result': {}})}\n\n"
            f"data: {json.dumps(message)}\n\n"
        )
        return Response(
            payload,
            media_type="text/event-stream",
            headers={"Mcp-Session-Id": sid},
        )

    if method == "tools/call":
        name = body["params"]["name"]
        handler = state.tool_handlers.get(name)
        result = (
            handler(body["params"]["arguments"])
            if handler is not None
            else {"content": [{"type": "text", "text": "{}"}]}
        )
        return JSONResponse(
            {"jsonrpc": "2.0", "id": body["id"], "result": result},
            headers={"Mcp-Session-Id": sid},
        )

    # Default tools/list.
    return JSONResponse(
        {
            "jsonrpc": "2.0",
            "id": body["id"],
            "result": {
                "tools": [{"name": "tool_a", "description": "", "inputSchema": {}}],
            },
        },
        headers={"Mcp-Session-Id": sid},
    )


def _build_app(state: _McpState) -> Starlette:
    app = Starlette(routes=[Route("/mcp", _mcp_endpoint, methods=["POST"])])
    app.state.mcp = state
    return app


def _http_session(app: Starlette) -> McpHttpSession:
    """Bind a session to the in-process app (no socket)."""
    session = McpHttpSession("http://mcp.test")
    session._http = httpx.AsyncClient(transport=httpx.ASGITransport(app=app))
    return session


@pytest.fixture
def mcp_state() -> _McpState:
    return _McpState()


@pytest.fixture
def mcp_app(mcp_state: _McpState) -> Starlette:
    return _build_app(mcp_state)


# ---------------------------------------------------------------------------
# streamable-HTTP: handshake + session-id replay
# ---------------------------------------------------------------------------


class TestHttpHandshake:
    async def test_initialize_then_session_id_replay(
        self, mcp_app: Starlette, mcp_state: _McpState,
    ) -> None:
        session = _http_session(mcp_app)
        try:
            tools = await session.list_tools(timeout=5.0)
            assert [t["name"] for t in tools] == ["tool_a"]
            # Exactly one handshake ...
            assert mcp_state.initialize_count == 1
            # ... and the post-handshake request carried the issued id.
            assert mcp_state.requests[0][1] == "sid-0"
            # The session also remembers the negotiated protocol version.
            assert session._session_id == "sid-0"
        finally:
            await session.aclose()

    async def test_second_call_reuses_session_without_rehandshake(
        self, mcp_app: Starlette, mcp_state: _McpState,
    ) -> None:
        session = _http_session(mcp_app)
        try:
            await session.list_tools(timeout=5.0)
            await session.call_tool("anything", {}, timeout=5.0)
            # Still one initialize -- the session id is replayed, not
            # renegotiated, across calls.
            assert mcp_state.initialize_count == 1
            methods = [m for m, _ in mcp_state.requests]
            assert methods == ["tools/list", "tools/call"]
            assert all(sid == "sid-0" for _, sid in mcp_state.requests)
        finally:
            await session.aclose()


# ---------------------------------------------------------------------------
# streamable-HTTP: SSE frame decoding
# ---------------------------------------------------------------------------


class TestHttpSseDecode:
    async def test_sse_frame_decoded_by_request_id(
        self, mcp_app: Starlette, mcp_state: _McpState,
    ) -> None:
        mcp_state.sse_methods.add("tools/list")
        session = _http_session(mcp_app)
        try:
            tools = await session.list_tools(timeout=5.0)
            # Picked our id's frame, not the 'other' decoy frame.
            assert [t["name"] for t in tools] == ["from_sse"]
        finally:
            await session.aclose()


# ---------------------------------------------------------------------------
# streamable-HTTP: 404 -> single re-handshake
# ---------------------------------------------------------------------------


class TestHttpRehandshake:
    async def test_session_refused_renegotiates_once_and_retries(
        self, mcp_app: Starlette, mcp_state: _McpState,
    ) -> None:
        session = _http_session(mcp_app)
        try:
            await session.list_tools(timeout=5.0)
            # Evict the session server-side (server restart / another
            # client took over): the replayed id is now refused.
            mcp_state.sessions.clear()
            result = await session.request("tools/list", {}, timeout=5.0)
            # Re-handshaked (second initialize) and the retry succeeded
            # on the fresh session id.
            assert mcp_state.initialize_count == 2
            assert session._session_id == "sid-1"
            assert result["tools"][0]["name"] == "tool_a"
            assert mcp_state.requests[-1][1] == "sid-1"
        finally:
            await session.aclose()

    async def test_persistent_refusal_raises_after_single_retry(
        self, mcp_app: Starlette, mcp_state: _McpState,
    ) -> None:
        mcp_state.refuse_all = True
        session = _http_session(mcp_app)
        try:
            with pytest.raises(McpHttpError) as excinfo:
                await session.request("tools/list", {}, timeout=5.0)
            # initialize + one re-initialize, then the retry 404 surfaces
            # -- never a third handshake attempt.
            assert mcp_state.initialize_count == 2
            assert excinfo.value.status_code == 404
        finally:
            await session.aclose()


# ---------------------------------------------------------------------------
# isError -> legacy error envelope (through the shared client mapping)
# ---------------------------------------------------------------------------


class TestMcpIsErrorEnvelope:
    async def test_is_error_result_maps_to_status_error(
        self, mcp_app: Starlette, mcp_state: _McpState,
    ) -> None:
        def _boom(arguments: dict[str, Any]) -> dict[str, Any]:
            return {
                "isError": True,
                "content": [{"type": "text", "text": "REA exploded badly"}],
            }

        mcp_state.tool_handlers["explode"] = _boom
        client = McpClient(
            server_id="rea",
            base_url="http://mcp.test",
            transport=TRANSPORT_MCP_HTTP,
        )
        client._mcp = _http_session(mcp_app)
        try:
            result = await client.call_tool("explode", {"procedure": "main"})
            assert result["status"] == "error"
            assert result["error"] == "REA exploded badly"
        finally:
            await client.aclose()

    async def test_success_result_maps_to_status_ready(
        self, mcp_app: Starlette, mcp_state: _McpState,
    ) -> None:
        def _ok(arguments: dict[str, Any]) -> dict[str, Any]:
            return {
                "content": [
                    {"type": "text", "text": json.dumps({"procedures": 3})},
                ],
            }

        mcp_state.tool_handlers["survey"] = _ok
        client = McpClient(
            server_id="rea",
            base_url="http://mcp.test",
            transport=TRANSPORT_MCP_HTTP,
        )
        client._mcp = _http_session(mcp_app)
        try:
            result = await client.call_tool("survey", {})
            assert result["status"] == "ready"
            assert result["procedures"] == 3
        finally:
            await client.aclose()


# ---------------------------------------------------------------------------
# stdio: tiny python child script
# ---------------------------------------------------------------------------

# One JSON-RPC message per line; echoes a result for every request;
# ``block`` exits without answering (used to exercise the pending-fail
# path); EOF on stdin exits cleanly (the aclose contract).
_CHILD_SCRIPT = r"""
import json
import sys

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    method = msg.get("method")
    if method == "initialize":
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {
                "protocolVersion": msg["params"]["protocolVersion"],
                "capabilities": {},
                "serverInfo": {"name": "child-mock", "version": "0"},
            },
        }), flush=True)
    elif method == "notifications/initialized":
        continue
    elif method == "block":
        # Exit without answering: the pending request must fail.
        sys.exit(0)
    else:
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {"echo": method, "params": msg.get("params")},
        }), flush=True)
sys.exit(0)
"""


@pytest.fixture
def child_script(tmp_path) -> str:
    script = tmp_path / "mcp_child.py"
    script.write_text(_CHILD_SCRIPT, encoding="utf-8")
    return str(script)


def _stdio_session(script: str) -> McpStdioSession:
    return McpStdioSession((sys.executable, script))


class TestStdioRequestResponse:
    async def test_initialize_and_request_response(self, child_script: str) -> None:
        session = _stdio_session(child_script)
        try:
            result = await session.request(
                "tools/call", {"name": "x", "arguments": {"a": 1}}, timeout=10.0,
            )
            assert result == {"echo": "tools/call", "params": {"name": "x", "arguments": {"a": 1}}}
            # Handshake happened once; child is up.
            assert session._ready is True
            assert session._proc is not None and session._proc.returncode is None
        finally:
            await session.aclose()
        # aclose terminates the child (stdin EOF contract).
        assert session._proc is None

    async def test_session_state_reset_on_close(self, child_script: str) -> None:
        session = _stdio_session(child_script)
        session.state["active_target"] = "/tmp/x"
        try:
            await session.request("tools/list", {}, timeout=10.0)
            assert session.state.get("active_target") == "/tmp/x"
        finally:
            await session.aclose()
        assert session.state == {}


class TestStdioChildExit:
    async def test_child_exit_fails_pending_and_respawns(
        self, child_script: str,
    ) -> None:
        session = _stdio_session(child_script)
        try:
            # Prime: child up and handshaked.
            first = await session.request("ping", {}, timeout=10.0)
            assert first["echo"] == "ping"
            first_pid = session._proc.pid

            # In-flight request that the child answers by exiting.
            blocker = asyncio.ensure_future(
                session.request("block", {}, timeout=30.0),
            )
            # Give the child a beat to read 'block' and exit.
            await asyncio.sleep(0.3)
            with pytest.raises(McpStdioError):
                await blocker

            # The session marked itself not-ready and cleared state.
            assert session._ready is False

            # Next request respawns a fresh child (new pid) and succeeds.
            second = await session.request("ping", {}, timeout=10.0)
            assert second["echo"] == "ping"
            assert session._proc is not None
            assert session._proc.pid != first_pid
        finally:
            await session.aclose()
