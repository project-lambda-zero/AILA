"""Health probe dispatch for :class:`McpRegistryServiceBase` (issue #306).

The resolved URL selects the protocol. A ``stdio://`` endpoint is probed with a
native ``tools/list`` over a probe-owned stdio session that is closed before the
probe returns; any other endpoint keeps the HTTP ``/openapi.json`` probe. Both
paths are exercised against in-memory fakes: no child process spawns and no
socket opens.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, ClassVar, NamedTuple
from uuid import uuid4

import httpx
import pytest

import aila.platform.mcp.registry as registry_module
from aila.platform.mcp.instance_catalog import TRANSPORT_STDIO
from aila.platform.mcp.mcp_session import (
    McpStdioError,
    close_shared_sessions,
    shared_session,
)
from aila.platform.mcp.registry import McpRegistryServiceBase

__all__: list[str] = []

_ENV_VAR = "REA_MCP_URL_NEVER_SET_306"
_ListTools = Callable[[], Awaitable[list[dict[str, Any]]]]


class _StubRegistry(McpRegistryServiceBase):
    """Binds the real ``rea`` stdio spec (``SERVER_SPECS``) under a private scope."""

    _module_id: ClassVar[str] = f"issue306-{uuid4().hex[:8]}"
    _servers: ClassVar[tuple[dict[str, str], ...]] = (
        {
            "id": "rea",
            "name": "rea",
            "description": "probe test",
            "env_var": _ENV_VAR,
            "config_key": "rea_mcp_url",
            "default_url": "stdio://rea",
        },
    )


class _FakeSession:
    """Stands in for :class:`McpStdioSession`; ``answer`` decides ``tools/list``."""

    def __init__(self, answer: _ListTools, closed: list[int]) -> None:
        self._answer = answer
        self._closed = closed

    async def list_tools(self, *, timeout: float) -> list[dict[str, Any]]:
        del timeout
        return await self._answer()

    async def aclose(self) -> None:
        self._closed.append(1)


def _answers(tools: list[dict[str, Any]]) -> _ListTools:
    async def answer() -> list[dict[str, Any]]:
        return tools

    return answer


def _raises(exc: BaseException) -> _ListTools:
    async def answer() -> list[dict[str, Any]]:
        raise exc

    return answer


def _hangs() -> _ListTools:
    async def answer() -> list[dict[str, Any]]:
        await asyncio.Event().wait()
        return []

    return answer


def _install_stdio(
    monkeypatch: pytest.MonkeyPatch, answer: _ListTools,
) -> tuple[list[tuple[str, ...]], list[int]]:
    """Route ``McpStdioSession`` to a fake; return (spawn argv, aclose calls)."""
    keys: list[tuple[str, ...]] = []
    closed: list[int] = []

    def fake_session(command: Sequence[str], **_kwargs: Any) -> _FakeSession:
        keys.append(tuple(command))
        return _FakeSession(answer, closed)

    monkeypatch.setattr(registry_module, "McpStdioSession", fake_session)
    return keys, closed


class _Call(NamedTuple):
    """One pending ``tools/list`` request, resolved by the test."""

    session: _ScriptedSession
    future: asyncio.Future[list[dict[str, Any]]]


class _ScriptedSession:
    """Stdio stand-in whose ``tools/list`` waits on a future the test resolves.

    ``aclose`` cancels only this session's pending calls, as
    :meth:`McpStdioSession.aclose` does.
    """

    def __init__(self, command: tuple[str, ...], calls: asyncio.Queue[_Call]) -> None:
        self.command = command
        self.closed = 0
        self._calls = calls
        self._pending: set[asyncio.Future[list[dict[str, Any]]]] = set()

    async def list_tools(self, *, timeout: float) -> list[dict[str, Any]]:
        del timeout
        future: asyncio.Future[list[dict[str, Any]]] = (
            asyncio.get_running_loop().create_future()
        )
        self._pending.add(future)
        self._calls.put_nowait(_Call(self, future))
        try:
            return await future
        finally:
            self._pending.discard(future)

    async def aclose(self) -> None:
        self.closed += 1
        for future in tuple(self._pending):
            future.cancel()


def _script_stdio_children(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[list[_ScriptedSession], asyncio.Queue[_Call]]:
    """Route every ``McpStdioSession`` construction to a scripted session."""
    sessions: list[_ScriptedSession] = []
    calls: asyncio.Queue[_Call] = asyncio.Queue()

    def make(command: Sequence[str], **_kwargs: Any) -> _ScriptedSession:
        session = _ScriptedSession(tuple(command), calls)
        sessions.append(session)
        return session

    monkeypatch.setattr(registry_module, "McpStdioSession", make)
    return sessions, calls


class _FakeResponse:
    def __init__(self, body: dict[str, Any]) -> None:
        self._body = body

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self._body


def _install_http(
    monkeypatch: pytest.MonkeyPatch, body: dict[str, Any],
) -> tuple[list[str], list[float]]:
    """Replace ``httpx.AsyncClient``; return (GET urls, client timeouts)."""
    gets: list[str] = []
    timeouts: list[float] = []

    class _FakeAsyncClient:
        def __init__(self, *, timeout: float) -> None:
            timeouts.append(timeout)

        async def __aenter__(self) -> _FakeAsyncClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def get(self, url: str) -> _FakeResponse:
            gets.append(url)
            return _FakeResponse(body)

    monkeypatch.setattr(registry_module.httpx, "AsyncClient", _FakeAsyncClient)
    return gets, timeouts


@pytest.fixture
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_ENV_VAR, raising=False)
    monkeypatch.delenv("REA_MCP_COMMAND", raising=False)


@pytest.mark.asyncio
@pytest.mark.usefixtures("_clean_env")
async def test_stdio_probe_reports_sorted_string_tool_names(
    test_db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A healthy stdio child is reachable; non-string tool names are dropped."""
    del test_db
    gets, constructed = _install_http(monkeypatch, {})
    keys, closed = _install_stdio(
        monkeypatch,
        _answers([{"name": "b_tool"}, {"name": "a_tool"}, {"name": 42}, {}]),
    )
    svc = _StubRegistry()
    result = await svc._probe(svc._servers[0])

    assert result["status"] == "reachable"
    assert result["error"] is None
    assert result["tools"] == ["a_tool", "b_tool"]
    assert result["tool_count"] == 2
    assert isinstance(result["latency_ms"], int)
    assert result["base_url"] == "stdio://rea"
    assert result["base_url_source"] == "default"
    # Spawn argv is SERVER_SPECS["rea"]; no HTTP at all.
    assert keys == [("rea", "mcp")]
    assert closed == [1]  # the probe closes the child it owns
    assert gets == []
    assert constructed == []


@pytest.mark.asyncio
@pytest.mark.usefixtures("_clean_env")
async def test_stdio_probe_spawn_failure_is_unreachable_without_http(
    test_db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A child that cannot spawn is unreachable with its own error class, not HTTP."""
    del test_db
    _gets, constructed = _install_http(monkeypatch, {})
    _keys, closed = _install_stdio(
        monkeypatch,
        _raises(McpStdioError("cannot spawn MCP server 'rea': not found")),
    )
    svc = _StubRegistry()
    result = await svc._probe(svc._servers[0])

    assert result["status"] == "unreachable"
    assert result["latency_ms"] is None
    assert result["tools"] == []
    assert result["tool_count"] == 0
    assert result["error"].startswith("McpStdioError: cannot spawn")
    assert "UnsupportedProtocol" not in result["error"]
    assert closed == [1]  # the failed probe's session is still closed
    assert constructed == []


@pytest.mark.asyncio
@pytest.mark.usefixtures("_clean_env")
async def test_stdio_probe_is_bounded_by_the_probe_timeout(
    test_db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A hung child cannot stall the probe past the shared probe timeout."""
    del test_db
    monkeypatch.setattr(registry_module, "_PROBE_TIMEOUT_SECONDS", 0.05)
    _keys, closed = _install_stdio(monkeypatch, _hangs())
    svc = _StubRegistry()
    result = await asyncio.wait_for(svc._probe(svc._servers[0]), timeout=5.0)

    assert result["status"] == "unreachable"
    assert result["error"].startswith("TimeoutError")
    assert closed == [1]  # the hung child's session is closed, not left live


@pytest.mark.asyncio
@pytest.mark.usefixtures("_clean_env")
async def test_stdio_probe_honours_command_override(
    test_db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``REA_MCP_COMMAND`` (shlex-split) replaces the default spawn argv."""
    del test_db
    monkeypatch.setenv("REA_MCP_COMMAND", "C:/tools/rea/rea.mjs mcp --verbose")
    keys, _closed = _install_stdio(monkeypatch, _answers([{"name": "x"}]))
    svc = _StubRegistry()
    result = await svc._probe(svc._servers[0])

    assert result["status"] == "reachable"
    assert keys == [("C:/tools/rea/rea.mjs", "mcp", "--verbose")]


@pytest.mark.asyncio
@pytest.mark.usefixtures("_clean_env")
async def test_http_probe_reports_tools_from_openapi_paths(
    test_db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An HTTP server keeps the /openapi.json probe and reads /tools/* paths."""
    del test_db
    monkeypatch.setenv(_ENV_VAR, "http://10.0.0.7:18823")
    spec = {"paths": {"/tools/zeta": {}, "/tools/alpha": {}, "/health": {}}}
    gets, timeouts = _install_http(monkeypatch, spec)
    keys, _closed = _install_stdio(monkeypatch, _answers([]))
    svc = _StubRegistry()
    result = await svc._probe(svc._servers[0])

    assert result["status"] == "reachable"
    assert result["base_url"] == "http://10.0.0.7:18823"
    assert result["base_url_source"] == "env"
    assert result["tools"] == ["alpha", "zeta"]
    assert result["tool_count"] == 2
    assert gets == ["http://10.0.0.7:18823/openapi.json"]
    assert timeouts == [registry_module._PROBE_TIMEOUT_SECONDS]
    assert keys == []


@pytest.mark.asyncio
@pytest.mark.usefixtures("_clean_env")
async def test_stdio_default_overridden_to_http_never_spawns_a_child(
    test_db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Overriding a stdio default with an http(s) URL probes over HTTP only."""
    del test_db
    monkeypatch.setenv(_ENV_VAR, "https://mcp.example.invalid")
    gets, _timeouts = _install_http(monkeypatch, {"paths": {}})
    keys, _closed = _install_stdio(monkeypatch, _answers([{"name": "must-not-run"}]))
    svc = _StubRegistry()
    result = await svc._probe(svc._servers[0])

    assert gets == ["https://mcp.example.invalid/openapi.json"]
    assert keys == []
    assert result["status"] == "reachable"
    assert result["tools"] == []


@pytest.mark.asyncio
@pytest.mark.usefixtures("_clean_env")
async def test_http_connect_failure_is_unreachable_with_its_own_error(
    test_db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refused HTTP endpoint reports its transport error class, not a stdio one."""
    del test_db
    monkeypatch.setenv(_ENV_VAR, "http://127.0.0.1:18823")

    class _RefusingAsyncClient:
        def __init__(self, *, timeout: float) -> None:
            del timeout

        async def __aenter__(self) -> _RefusingAsyncClient:
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def get(self, url: str) -> _FakeResponse:
            raise httpx.ConnectError(f"refused: {url}")

    monkeypatch.setattr(registry_module.httpx, "AsyncClient", _RefusingAsyncClient)
    keys, _closed = _install_stdio(monkeypatch, _answers([]))
    svc = _StubRegistry()
    result = await svc._probe(svc._servers[0])

    assert result["status"] == "unreachable"
    assert result["error"].startswith("ConnectError")
    assert keys == []


@pytest.mark.asyncio
@pytest.mark.usefixtures("_clean_env")
async def test_malformed_command_override_is_unreachable_not_an_error(
    test_db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unclosed quote in ``REA_MCP_COMMAND`` yields an unreachable row, never a raise."""
    del test_db
    monkeypatch.setenv("REA_MCP_COMMAND", 'C:/tools/"rea.mjs mcp')
    keys, closed = _install_stdio(monkeypatch, _answers([{"name": "must-not-run"}]))
    svc = _StubRegistry()
    result = await svc._probe(svc._servers[0])

    assert result["status"] == "unreachable"
    assert result["error"].startswith("ValueError")
    assert keys == []  # no session is created for an unparseable command
    assert closed == []


@pytest.mark.asyncio
@pytest.mark.usefixtures("_clean_env")
async def test_stalled_session_close_is_bounded(
    test_db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wedged ``aclose()`` cannot hold the failed probe response open."""
    del test_db
    monkeypatch.setattr(registry_module, "_PROBE_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(registry_module, "_STDIO_CLOSE_TIMEOUT_SECONDS", 0.05)

    class _StuckCloseSession(_FakeSession):
        async def aclose(self) -> None:
            await asyncio.Event().wait()

    monkeypatch.setattr(
        registry_module,
        "McpStdioSession",
        lambda command, **_kwargs: _StuckCloseSession(_hangs(), []),
    )
    svc = _StubRegistry()
    result = await asyncio.wait_for(svc._probe(svc._servers[0]), timeout=5.0)

    assert result["status"] == "unreachable"
    assert result["error"].startswith("TimeoutError")


@pytest.mark.asyncio
@pytest.mark.usefixtures("_clean_env")
async def test_timed_out_probe_closes_its_child_and_next_probe_spawns_its_own(
    test_db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A timed-out probe closes its child; the next probe spawns a fresh one."""
    del test_db
    monkeypatch.setattr(registry_module, "_PROBE_TIMEOUT_SECONDS", 0.05)
    answers = [_hangs(), _answers([{"name": "again"}])]
    closed: list[int] = []
    constructed: list[tuple[str, ...]] = []

    def fake_session(command: Sequence[str], **_kwargs: Any) -> _FakeSession:
        constructed.append(tuple(command))
        return _FakeSession(answers.pop(0), closed)

    monkeypatch.setattr(registry_module, "McpStdioSession", fake_session)
    svc = _StubRegistry()

    first = await svc._probe(svc._servers[0])
    assert first["status"] == "unreachable"
    assert closed == [1]  # the hung child is torn down by its own probe

    monkeypatch.setattr(registry_module, "_PROBE_TIMEOUT_SECONDS", 3.0)
    second = await svc._probe(svc._servers[0])
    assert second["status"] == "reachable"
    assert second["tools"] == ["again"]
    assert len(constructed) == 2  # one child per probe, none shared
    assert closed == [1, 1]


@pytest.mark.asyncio
@pytest.mark.usefixtures("_clean_env")
async def test_staggered_probe_failure_does_not_cancel_the_second_probe(
    test_db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One probe's failed handshake leaves a concurrent probe's pending call intact."""
    del test_db
    sessions, calls = _script_stdio_children(monkeypatch)
    svc = _StubRegistry()
    spec = svc._servers[0]
    first = asyncio.create_task(svc._probe(spec))
    first_call = await calls.get()
    second = asyncio.create_task(svc._probe(spec))
    second_call = await calls.get()

    first_call.future.set_exception(McpStdioError("child exited during handshake"))
    first_result = await asyncio.wait_for(first, timeout=5.0)

    assert first_result["status"] == "unreachable"
    # Pre-fix: the first probe's reset cancelled this pending call.
    assert not second_call.future.done()
    second_call.future.set_result([{"name": "late_tool"}])
    second_result = await asyncio.wait_for(second, timeout=5.0)

    assert second_result["status"] == "reachable"
    assert second_result["tools"] == ["late_tool"]
    assert [s.closed for s in sessions] == [1, 1]  # each probe closed its own child


@pytest.mark.asyncio
@pytest.mark.usefixtures("_clean_env")
async def test_probe_failure_leaves_an_unrelated_active_bridge_call_pending(
    test_db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed probe handshake never cancels a bridge call on the shared session."""
    del test_db
    _sessions, calls = _script_stdio_children(monkeypatch)
    shared = shared_session(
        (TRANSPORT_STDIO, "rea", "mcp"),
        lambda: _ScriptedSession(("rea", "mcp"), calls),  # type: ignore[arg-type,return-value]
    )
    try:
        bridge = asyncio.create_task(shared.list_tools(timeout=60.0))
        bridge_call = await calls.get()
        svc = _StubRegistry()
        probe = asyncio.create_task(svc._probe(svc._servers[0]))
        probe_call = await calls.get()

        probe_call.future.set_exception(McpStdioError("probe handshake failed"))
        probe_result = await asyncio.wait_for(probe, timeout=5.0)

        assert probe_result["status"] == "unreachable"
        # Pre-fix: the probe reused the shared session and its reset cancelled this.
        assert not bridge_call.future.done()
        bridge_call.future.set_result([{"name": "bridge_tool"}])
        assert await asyncio.wait_for(bridge, timeout=5.0) == [{"name": "bridge_tool"}]
    finally:
        await close_shared_sessions()


class _FakeCatalogRow:
    def __init__(self, endpoint: str, transport: str) -> None:
        self.id = "row-306"
        self.name = "rea"
        self.module_scope = None
        self.endpoint = endpoint
        self.transport = transport
        self.capability_tags = "[]"
        self.enabled = True


class _FakeCatalog:
    def __init__(self, row: _FakeCatalogRow) -> None:
        self._row = row

    async def get_by_scope_and_name(
        self, module_scope: str | None, name: str, *, approved_only: bool,
    ) -> _FakeCatalogRow:
        del module_scope, name, approved_only
        return self._row


@pytest.mark.asyncio
@pytest.mark.usefixtures("_clean_env")
async def test_catalog_row_with_http_endpoint_probes_over_http_not_stdio(
    test_db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stdio-transport catalog row whose endpoint is http(s) is probed over HTTP."""
    del test_db
    gets, _timeouts = _install_http(monkeypatch, {"paths": {"/tools/only": {}}})
    keys, _closed = _install_stdio(monkeypatch, _answers([{"name": "must-not-run"}]))
    row = _FakeCatalogRow("http://10.1.2.3:9000", TRANSPORT_STDIO)
    svc = _StubRegistry(catalog=_FakeCatalog(row))  # type: ignore[arg-type]
    result = await svc._probe(svc._servers[0])

    assert result["base_url_source"] == "catalog"
    assert gets == ["http://10.1.2.3:9000/openapi.json"]
    assert keys == []
    assert result["status"] == "reachable"
    assert result["tools"] == ["only"]
