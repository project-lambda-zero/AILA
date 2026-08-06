"""RFC-11 steps 0/3/4 -- unit tests for the generic MCP client,
capability-based module binding, instance pooling, and per-call
``instance_id`` provenance.

The tests use a mocked HTTP transport (monkeypatched
:class:`httpx.AsyncClient`) so no live MCP server is required and the
assertions run in milliseconds. A test-only concrete ``mcp_call_log``
table is defined here to exercise the ``instance_id`` column added to
:class:`aila.platform.contracts.mcp_call_log_base.McpCallLogRecordBase`
without pulling in the VR or malware module tables.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from functools import partial
from typing import Any, ClassVar
from unittest.mock import patch
from uuid import uuid4

import httpx
import pytest
from sqlmodel import select

from aila.modules.vr.agents.vuln_researcher import (
    _applicable_servers_by_capability as _vr_capability_helper,
)
from aila.platform.contracts.mcp_call_log_base import McpCallLogRecordBase

# Test-only concrete table -- inherits every column from the base plus
# the RFC-11 ``instance_id`` field. Registering the class at module
# import time keeps ``SQLModel.metadata.create_all`` in the session
# fixture aware of the table before tests run.
from aila.platform.mcp.call_logger import record_call as _platform_record_call
from aila.platform.mcp.client import (
    EmptyPoolError,
    InstancePool,
    McpClient,
    ResolvedInstance,
    compact_tool_spec,
    resolve_instance,
)
from aila.platform.mcp.instance_catalog import (
    TRANSPORT_HTTP,
    McpInstanceCatalog,
)
from aila.platform.mcp.registry import McpRegistryServiceBase
from aila.storage.database import async_session_scope

__all__: list[str] = []


class _TestMcpCallLog(McpCallLogRecordBase, table=True):
    """Ephemeral concrete ``mcp_call_log`` used only by these tests."""

    __tablename__ = "rfc11test_mcp_call_log"


record_call = partial(
    _platform_record_call,
    record_model=_TestMcpCallLog,
    log_prefix="rfc11test.mcp_call_log",
)


def _fresh_scope() -> str:
    return f"rfc11cli-{uuid4().hex[:8]}"


# ── mock transport helpers ────────────────────────────────────────────


class _MockResponse:
    """Just enough of ``httpx.Response`` for the client's happy path."""

    def __init__(
        self,
        *,
        status_code: int = 200,
        json_body: Any = None,
        text_body: str = "",
    ) -> None:
        self.status_code = status_code
        self._json = json_body
        self.text = text_body
        self.content = text_body.encode() if text_body else b"{}"

    def json(self) -> Any:
        if isinstance(self._json, Exception):
            raise self._json
        return self._json


class _MockAsyncClient:
    """Records every request; returns queued responses in FIFO order."""

    def __init__(
        self,
        *,
        get_response: _MockResponse | None = None,
        post_response: _MockResponse | None = None,
        raise_on: Exception | None = None,
        **_kwargs: Any,
    ) -> None:
        self._get_response = get_response or _MockResponse(json_body=[])
        self._post_response = post_response or _MockResponse(
            json_body={"status": "ready"},
        )
        self._raise_on = raise_on
        self.posts: list[dict[str, Any]] = []
        self.gets: list[str] = []

    async def __aenter__(self) -> _MockAsyncClient:
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        return None

    async def get(self, url: str) -> _MockResponse:
        self.gets.append(url)
        if self._raise_on is not None:
            raise self._raise_on
        return self._get_response

    async def post(self, url: str, json: dict[str, Any]) -> _MockResponse:
        self.posts.append({"url": url, "json": json})
        if self._raise_on is not None:
            raise self._raise_on
        return self._post_response


# ── McpClient dispatch tests ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_mcp_client_dispatches_to_resolved_endpoint() -> None:
    """``call_tool`` POSTs to ``<base>/tools/<action>`` with the payload."""
    mock_client = _MockAsyncClient(
        post_response=_MockResponse(json_body={"status": "ready", "hits": 3}),
    )
    with patch("httpx.AsyncClient", return_value=mock_client):
        client = McpClient(
            server_id="test_mcp",
            base_url="http://mock:1234/",
        )
        payload = await client.call_tool("scan", {"target": "x"})
    assert payload == {"status": "ready", "hits": 3}
    assert len(mock_client.posts) == 1
    assert mock_client.posts[0]["url"] == "http://mock:1234/tools/scan"
    assert mock_client.posts[0]["json"] == {"target": "x"}


@pytest.mark.asyncio
async def test_mcp_client_lists_tools_and_caches() -> None:
    """``list_tool_specs`` fetches ``GET /tools`` once then serves the cache."""
    raw = [
        {
            "name": "search_functions",
            "description": "search",
            "parameters": {
                "properties": {"pattern": {"type": "string"}},
                "required": ["pattern"],
            },
        },
    ]
    mock_client = _MockAsyncClient(get_response=_MockResponse(json_body=raw))
    with patch("httpx.AsyncClient", return_value=mock_client):
        client = McpClient(server_id="test_mcp", base_url="http://mock:1234")
        first = await client.list_tool_specs()
        second = await client.list_tool_specs()
    assert first == second
    assert first[0]["name"] == "search_functions"
    assert first[0]["params"][0] == {
        "name": "pattern", "type": "string", "required": True,
    }
    # Cached: only one GET even after two calls.
    assert len(mock_client.gets) == 1


@pytest.mark.asyncio
async def test_mcp_client_wraps_bare_list_body() -> None:
    """Non-dict bodies wrap into ``{"status": "ready", "result": ...}``."""
    mock_client = _MockAsyncClient(
        post_response=_MockResponse(json_body=[1, 2, 3]),
    )
    with patch("httpx.AsyncClient", return_value=mock_client):
        client = McpClient(server_id="test_mcp", base_url="http://mock:1234")
        payload = await client.call_tool("action", {})
    assert payload == {"status": "ready", "result": [1, 2, 3]}


@pytest.mark.asyncio
async def test_mcp_client_injects_status_ready_when_missing() -> None:
    """A dict body without ``status`` gets ``status: ready`` on HTTP 2xx."""
    mock_client = _MockAsyncClient(
        post_response=_MockResponse(json_body={"hits": []}),
    )
    with patch("httpx.AsyncClient", return_value=mock_client):
        client = McpClient(server_id="test_mcp", base_url="http://mock:1234")
        payload = await client.call_tool("action", {})
    assert payload["status"] == "ready"
    assert payload["hits"] == []


@pytest.mark.asyncio
async def test_mcp_client_connect_error_returns_envelope() -> None:
    """A transport failure returns a uniform error envelope, no raise."""
    mock_client = _MockAsyncClient(
        raise_on=httpx.ConnectError("refused"),
    )
    with patch("httpx.AsyncClient", return_value=mock_client):
        client = McpClient(server_id="test_mcp", base_url="http://mock:1234")
        payload = await client.call_tool("action", {})
    assert payload["status"] == "error"
    assert "refused" in payload["error"]


@pytest.mark.asyncio
async def test_mcp_client_resolves_via_resolver_callback() -> None:
    """Deferred resolver runs once, caches, and re-runs after invalidate."""
    calls = 0

    async def _resolver() -> ResolvedInstance:
        nonlocal calls
        calls += 1
        return ResolvedInstance(
            url=f"http://resolved-{calls}",
            source="catalog",
            instance_id=f"inst-{calls}",
        )

    client = McpClient(server_id="test_mcp", resolver=_resolver)
    resolved_a = await client.resolve()
    resolved_b = await client.resolve()
    assert resolved_a is resolved_b  # cached
    assert calls == 1
    assert resolved_a.instance_id == "inst-1"

    client.invalidate_base_url()
    resolved_c = await client.resolve()
    assert calls == 2
    assert resolved_c.instance_id == "inst-2"


# ── compact_tool_spec ─────────────────────────────────────────────────


def test_compact_tool_spec_projects_parameters() -> None:
    """Projection shape matches the pre-RFC-11 per-bridge helper."""
    raw = {
        "name": "search_functions",
        "description": "search x" + "y" * 800,  # over-long description clipped
        "parameters": {
            "properties": {
                "pattern": {"type": "string", "description": "regex"},
                "limit": {"type": "integer", "default": 10},
            },
            "required": ["pattern"],
        },
    }
    projected = compact_tool_spec(raw)
    assert projected["name"] == "search_functions"
    assert len(projected["description"]) <= 400
    assert projected["required"] == ["pattern"]
    assert len(projected["params"]) == 2
    limit_param = next(p for p in projected["params"] if p["name"] == "limit")
    assert limit_param["default"] == 10
    assert limit_param["required"] is False


# ── capability resolution ─────────────────────────────────────────────


class _CapRegistry(McpRegistryServiceBase):
    """Test-only registry subclass bound to a private module scope."""

    _module_id: ClassVar[str] = "rfc11cap"
    _servers: ClassVar[tuple[dict[str, str], ...]] = (
        {
            "id": "audit_mcp",
            "name": "audit-mcp",
            "description": "test stub",
            "env_var": "RFC11CAP_AUDIT_MCP_URL_NEVER_SET",
            "config_key": "audit_mcp_url",
            "default_url": "http://code-default:18822",
        },
    )


@pytest.mark.asyncio
async def test_resolve_by_capability_picks_matching_tag(test_db) -> None:
    """Only enabled rows tagged with the requested capability come back."""
    del test_db
    catalog = McpInstanceCatalog()
    scope = _fresh_scope()

    # Two audit_mcp instances tagged for source_audit, one binary_audit.
    await catalog.add_instance(
        name="audit_mcp",
        transport=TRANSPORT_HTTP,
        endpoint="http://a1:18822",
        capability_tags=["source_audit"],
        module_scope=scope,
    )
    await catalog.add_instance(
        name="audit_mcp_west",
        transport=TRANSPORT_HTTP,
        endpoint="http://a2:18822",
        capability_tags=["source_audit", "graph"],
        module_scope=scope,
    )
    await catalog.add_instance(
        name="ida_headless",
        transport=TRANSPORT_HTTP,
        endpoint="http://b1:18821",
        capability_tags=["binary_audit"],
        module_scope=scope,
    )

    class _S(McpRegistryServiceBase):
        _module_id: ClassVar[str] = scope
        _servers: ClassVar[tuple[dict[str, str], ...]] = ()

    svc = _S()
    source_rows = await svc.resolve_by_capability("source_audit")
    assert sorted(r.name for r in source_rows) == ["audit_mcp", "audit_mcp_west"]
    assert {r.source for r in source_rows} == {"catalog"}
    assert all(r.instance_id for r in source_rows)

    binary_rows = await svc.resolve_by_capability("binary_audit")
    assert [r.name for r in binary_rows] == ["ida_headless"]


@pytest.mark.asyncio
async def test_resolve_by_capability_skips_disabled(test_db) -> None:
    """Disabled rows never appear in the enabled pool."""
    del test_db
    catalog = McpInstanceCatalog()
    scope = _fresh_scope()

    live = await catalog.add_instance(
        name="ida_a",
        transport=TRANSPORT_HTTP,
        endpoint="http://live:18821",
        capability_tags=["binary_audit"],
        module_scope=scope,
    )
    dead = await catalog.add_instance(
        name="ida_b",
        transport=TRANSPORT_HTTP,
        endpoint="http://dead:18821",
        capability_tags=["binary_audit"],
        module_scope=scope,
    )
    await catalog.set_enabled(dead.id, False)

    class _S(McpRegistryServiceBase):
        _module_id: ClassVar[str] = scope
        _servers: ClassVar[tuple[dict[str, str], ...]] = ()

    svc = _S()
    rows = await svc.resolve_by_capability("binary_audit")
    assert [r.instance_id for r in rows] == [live.id]


@pytest.mark.asyncio
async def test_resolve_by_capability_empty_catalog_returns_empty(test_db) -> None:
    """Empty catalog for the scope -> caller falls back to static default."""
    del test_db
    scope = _fresh_scope()

    class _S(McpRegistryServiceBase):
        _module_id: ClassVar[str] = scope
        _servers: ClassVar[tuple[dict[str, str], ...]] = ()

    svc = _S()
    assert await svc.resolve_by_capability("anything") == []


@pytest.mark.asyncio
async def test_bind_returns_pool_per_capability(test_db) -> None:
    """`bind` maps each requested capability to its resolved pool."""
    del test_db
    catalog = McpInstanceCatalog()
    scope = _fresh_scope()

    await catalog.add_instance(
        name="src_a",
        transport=TRANSPORT_HTTP,
        endpoint="http://src:18822",
        capability_tags=["source_audit"],
        module_scope=scope,
    )
    await catalog.add_instance(
        name="bin_a",
        transport=TRANSPORT_HTTP,
        endpoint="http://bin:18821",
        capability_tags=["binary_audit"],
        module_scope=scope,
    )

    class _S(McpRegistryServiceBase):
        _module_id: ClassVar[str] = scope
        _servers: ClassVar[tuple[dict[str, str], ...]] = ()

    svc = _S()
    bound = await svc.bind(["source_audit", "binary_audit", "missing"])
    assert [r.name for r in bound["source_audit"]] == ["src_a"]
    assert [r.name for r in bound["binary_audit"]] == ["bin_a"]
    assert bound["missing"] == []


# ── instance pooling ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_instance_pool_round_robin_alternates() -> None:
    """Two members alternate strictly under repeated ``next`` calls."""
    a = ResolvedInstance(url="http://a", source="catalog", instance_id="a")
    b = ResolvedInstance(url="http://b", source="catalog", instance_id="b")
    pool = InstancePool([a, b])
    picks = [(await pool.next()).instance_id for _ in range(6)]
    assert picks == ["a", "b", "a", "b", "a", "b"]


@pytest.mark.asyncio
async def test_instance_pool_empty_raises() -> None:
    """An empty pool raises ``EmptyPoolError`` so the caller falls back."""
    pool = InstancePool([])
    with pytest.raises(EmptyPoolError):
        await pool.next()


@pytest.mark.asyncio
async def test_pool_for_capability_alternates_across_two_rows(test_db) -> None:
    """Two enabled catalog rows of one capability share load via round-robin."""
    del test_db
    catalog = McpInstanceCatalog()
    scope = _fresh_scope()

    left = await catalog.add_instance(
        name="ida_left",
        transport=TRANSPORT_HTTP,
        endpoint="http://left:18821",
        capability_tags=["binary_audit"],
        module_scope=scope,
    )
    right = await catalog.add_instance(
        name="ida_right",
        transport=TRANSPORT_HTTP,
        endpoint="http://right:18821",
        capability_tags=["binary_audit"],
        module_scope=scope,
    )

    class _S(McpRegistryServiceBase):
        _module_id: ClassVar[str] = scope
        _servers: ClassVar[tuple[dict[str, str], ...]] = ()

    svc = _S()
    pool = await svc.pool_for_capability("binary_audit")
    assert len(pool) == 2
    picks = [(await pool.next()).instance_id for _ in range(4)]
    # Deterministic 2-cycle, exactly 2 hits each within 4 calls.
    assert sorted(picks[:2]) == sorted([left.id, right.id])
    assert picks[0] == picks[2]
    assert picks[1] == picks[3]


# ── resolve_instance 4-tier ordering ──────────────────────────────────


@pytest.mark.asyncio
async def test_resolve_instance_prefers_env(test_db) -> None:
    """Env var beats catalog + default even when the catalog has a row."""
    del test_db
    catalog = McpInstanceCatalog()
    scope = _fresh_scope()
    await catalog.add_instance(
        name="audit_mcp",
        transport=TRANSPORT_HTTP,
        endpoint="http://catalog:18822",
        module_scope=scope,
    )
    os.environ["RFC11CLI_ENV_ONLY"] = "http://env-wins:18822"
    try:
        resolved = await resolve_instance(
            module_scope=scope,
            server_name="audit_mcp",
            env_var="RFC11CLI_ENV_ONLY",
            config_key="audit_mcp_url",
            default_url="http://code:18822",
            catalog=catalog,
        )
    finally:
        os.environ.pop("RFC11CLI_ENV_ONLY", None)
    assert resolved.url == "http://env-wins:18822"
    assert resolved.source == "env"
    assert resolved.instance_id is None  # env tier has no catalog id


@pytest.mark.asyncio
async def test_resolve_instance_catalog_carries_instance_id(test_db) -> None:
    """Catalog tier stamps instance_id + capability_tags on the result."""
    del test_db
    catalog = McpInstanceCatalog()
    scope = _fresh_scope()
    row = await catalog.add_instance(
        name="audit_mcp",
        transport=TRANSPORT_HTTP,
        endpoint="http://cat:18822",
        capability_tags=["source_audit", "graph"],
        module_scope=scope,
    )
    os.environ.pop("RFC11CLI_NO_ENV", None)
    resolved = await resolve_instance(
        module_scope=scope,
        server_name="audit_mcp",
        env_var="RFC11CLI_NO_ENV",
        config_key="unused_key_never_set",
        default_url="http://code:18822",
        catalog=catalog,
    )
    assert resolved.url == "http://cat:18822"
    assert resolved.source == "catalog"
    assert resolved.instance_id == row.id
    assert resolved.capability_tags == ("source_audit", "graph")


@pytest.mark.asyncio
async def test_resolve_instance_falls_through_to_default(test_db) -> None:
    """Empty catalog, no env, no config -> code-embedded default wins."""
    del test_db
    os.environ.pop("RFC11CLI_NO_ENV_2", None)
    resolved = await resolve_instance(
        module_scope=_fresh_scope(),
        server_name="audit_mcp",
        env_var="RFC11CLI_NO_ENV_2",
        config_key="unused_key_never_set_2",
        default_url="http://code:18822/",
        catalog=McpInstanceCatalog(),
    )
    assert resolved.url == "http://code:18822"
    assert resolved.source == "default"
    assert resolved.instance_id is None


# ── instance_id recording via record_call ─────────────────────────────


@pytest.mark.asyncio
async def test_record_call_stamps_instance_id(test_db) -> None:
    """Every ``record_call`` write persists the resolver's instance_id."""
    del test_db
    server_id = f"srv-{uuid4().hex[:6]}"
    async with record_call(
        server_id=server_id,
        base_url="http://mock",
        action="scan",
        instance_id="inst-42",
    ) as ctx:
        ctx["status"] = "ready"
        ctx["http_status"] = 200

    async with async_session_scope() as session:
        rows = (
            await session.exec(
                select(_TestMcpCallLog).where(
                    _TestMcpCallLog.server_id == server_id,
                ),
            )
        ).all()
    assert len(rows) == 1
    assert rows[0].instance_id == "inst-42"
    assert rows[0].status == "ready"
    assert rows[0].http_status == 200


@pytest.mark.asyncio
async def test_record_call_instance_id_defaults_to_none(test_db) -> None:
    """Backward compat: omitting ``instance_id`` writes NULL."""
    del test_db
    server_id = f"srv-{uuid4().hex[:6]}"
    async with record_call(
        server_id=server_id,
        base_url="http://mock",
        action="ping",
    ) as ctx:
        ctx["status"] = "ready"

    async with async_session_scope() as session:
        rows = (
            await session.exec(
                select(_TestMcpCallLog).where(
                    _TestMcpCallLog.server_id == server_id,
                ),
            )
        ).all()
    assert len(rows) == 1
    assert rows[0].instance_id is None


# ── McpClient dispatch records instance_id via bound recorder ─────────


@pytest.mark.asyncio
async def test_mcp_client_calls_recorder_with_instance_id() -> None:
    """The client threads the resolved instance_id into the recorder ctx."""
    captured: dict[str, Any] = {}

    @asynccontextmanager
    async def _recorder(**kwargs: Any):
        captured.update(kwargs)
        ctx: dict[str, Any] = {}
        try:
            yield ctx
        finally:
            captured["ctx_final"] = dict(ctx)

    async def _resolver() -> ResolvedInstance:
        return ResolvedInstance(
            url="http://mock:1234",
            source="catalog",
            instance_id="cat-instance-77",
            capability_tags=("source_audit",),
        )

    mock_client = _MockAsyncClient(
        post_response=_MockResponse(json_body={"status": "ready"}),
    )
    with patch("httpx.AsyncClient", return_value=mock_client):
        client = McpClient(
            server_id="test_mcp",
            resolver=_resolver,
            recorder=_recorder,
        )
        result = await client.call_tool("scan", {"target": "x"})

    assert result["status"] == "ready"
    assert captured["instance_id"] == "cat-instance-77"
    assert captured["server_id"] == "test_mcp"
    assert captured["action"] == "scan"
    assert captured["base_url"] == "http://mock:1234"
    assert captured["ctx_final"]["status"] == "ready"


# ── researcher capability wiring smoke test ───────────────────────────


@pytest.mark.asyncio
async def test_vr_capability_helper_falls_through_on_empty(test_db) -> None:
    """Empty catalog -> ``_applicable_servers_by_capability`` returns None."""
    del test_db
    result = await _vr_capability_helper("source_repo")
    assert result is None


@pytest.mark.asyncio
async def test_vr_capability_helper_uses_catalog_when_populated(test_db) -> None:
    """Populated catalog -> researcher resolves servers by capability."""
    del test_db
    catalog = McpInstanceCatalog()

    # Row in the VR module scope tagged with source_audit.
    row_id = f"vrcap-{uuid4().hex[:6]}"
    await catalog.add_instance(
        instance_id=row_id,
        name="my_audit_mcp",
        transport=TRANSPORT_HTTP,
        endpoint="http://mocked:19999",
        capability_tags=["source_audit"],
        module_scope="vr",
    )
    try:
        result = await _vr_capability_helper("source_repo")
        assert result is not None
        assert "my_audit_mcp" in result
    finally:
        await catalog.remove_instance(row_id)


# ── smoke: pool + record_call round-trip ──────────────────────────────


@pytest.mark.asyncio
async def test_pool_dispatch_records_alternating_instance_ids(test_db) -> None:
    """Two pool members served in rotation stamp distinct instance_ids in the log."""
    del test_db
    catalog = McpInstanceCatalog()
    scope = _fresh_scope()

    a = await catalog.add_instance(
        name="pool_a",
        transport=TRANSPORT_HTTP,
        endpoint="http://a:18821",
        capability_tags=["binary_audit"],
        module_scope=scope,
    )
    b = await catalog.add_instance(
        name="pool_b",
        transport=TRANSPORT_HTTP,
        endpoint="http://b:18821",
        capability_tags=["binary_audit"],
        module_scope=scope,
    )

    class _S(McpRegistryServiceBase):
        _module_id: ClassVar[str] = scope
        _servers: ClassVar[tuple[dict[str, str], ...]] = ()

    svc = _S()
    pool = await svc.pool_for_capability("binary_audit")

    server_id = f"srv-{uuid4().hex[:6]}"
    recorded_ids: list[str | None] = []

    @asynccontextmanager
    async def _rec(**kwargs):
        recorded_ids.append(kwargs.get("instance_id"))
        async with record_call(
            server_id=kwargs["server_id"],
            base_url=kwargs["base_url"],
            action=kwargs["action"],
            instance_id=kwargs.get("instance_id"),
        ) as ctx:
            yield ctx

    for _ in range(4):
        inst = await pool.next()
        mock_client = _MockAsyncClient(
            post_response=_MockResponse(json_body={"status": "ready"}),
        )
        with patch("httpx.AsyncClient", return_value=mock_client):
            client = McpClient(
                server_id=server_id,
                base_url=inst.url,
                recorder=_rec,
            )
            # Force the resolved instance_id even though a fixed
            # base_url is set: the client dispatches through the
            # resolver -- so wire the recorder to record the pool's
            # instance_id explicitly by threading it via a resolver.
            async def _r(inst_captured: ResolvedInstance = inst) -> ResolvedInstance:
                return inst_captured

            client._resolver = _r  # type: ignore[assignment]
            client._fixed_base_url = None  # let the resolver run
            await client.call_tool("action", {})

    # 4 calls alternate between a and b -- expect a, b, a, b.
    assert recorded_ids == [a.id, b.id, a.id, b.id]

    # The audit log rows carry the same alternation.
    async with async_session_scope() as session:
        rows = (
            await session.exec(
                select(_TestMcpCallLog)
                .where(_TestMcpCallLog.server_id == server_id)
                .order_by(_TestMcpCallLog.called_at),
            )
        ).all()
    assert [r.instance_id for r in rows] == [a.id, b.id, a.id, b.id]
