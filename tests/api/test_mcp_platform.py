"""Targeted tests for req 10/40 -- platform-owned MCP surface.

Covers pure logic that does not require a live Postgres:

* :func:`_flatten` -- comma-OR + repeated query param collapse.
* :func:`_split_composite` -- ``"<module_scope>:<server_id>"`` parsing.
* :meth:`McpInstanceCatalog.ensure_instance` -- semantic contract via a
  fake session (idempotent upsert that never clobbers operator-owned
  columns on the update path).

The full round-trip through Postgres lives in the live-infra suite (marked
skip below); this file guards the branching + composition, which is where
the bugs actually live.
"""
from __future__ import annotations

from typing import Any

import pytest

from aila.api.routers.platform_mcp import _flatten, _split_composite
from aila.platform.mcp import instance_catalog as ic


class TestFlatten:
    def test_none_returns_none(self) -> None:
        assert _flatten(None) is None

    def test_empty_returns_none(self) -> None:
        assert _flatten([]) is None

    def test_repeated_values_dedupe_and_preserve_order(self) -> None:
        assert _flatten(["vr", "malware", "vr"]) == ["vr", "malware"]

    def test_comma_joined_value_expands(self) -> None:
        assert _flatten(["vr,malware"]) == ["vr", "malware"]

    def test_mixed_repeated_and_comma_joined(self) -> None:
        assert _flatten(["vr,malware", "vr"]) == ["vr", "malware"]

    def test_strips_whitespace_and_drops_empties(self) -> None:
        assert _flatten(["  vr  ,,,  malware ", ""]) == ["vr", "malware"]

    def test_only_empties_returns_none(self) -> None:
        assert _flatten(["", ",,", "   "]) is None


class TestSplitComposite:
    def test_simple_scope_and_server_id(self) -> None:
        assert _split_composite("vr:audit_mcp") == ("vr", "audit_mcp")

    def test_first_colon_is_the_split_point(self) -> None:
        # Server ids do not carry colons by convention, but if one ever
        # did, the split must be on the FIRST colon so the module scope
        # stays a bare identifier. The right side is preserved verbatim.
        assert _split_composite("malware:ida:exp") == ("malware", "ida:exp")

    def test_no_colon_is_none(self) -> None:
        assert _split_composite("audit_mcp") is None

    def test_empty_scope_is_none(self) -> None:
        assert _split_composite(":audit_mcp") is None

    def test_empty_server_is_none(self) -> None:
        assert _split_composite("vr:") is None

    def test_whitespace_only_sides_reject(self) -> None:
        assert _split_composite("  :  ") is None


# ---------------------------------------------------------------------------
# ensure_instance semantics -- exercised through a fake async session so the
# test needs no Postgres and no `test_db` fixture.
# ---------------------------------------------------------------------------


class _FakeExecResult:
    def __init__(self, first: Any) -> None:
        self._first = first

    def first(self) -> Any:
        return self._first


class _FakeSession:
    """Minimal async session that satisfies :meth:`ensure_instance`.

    Tracks ``add`` / ``commit`` / ``refresh`` invocations so a test can
    assert whether the update path wrote to the DB. ``exec`` returns the
    row pre-loaded via ``preload`` (or ``None`` for the insert path).
    """

    def __init__(self, preload: Any = None) -> None:
        self._preload = preload
        self.added: list[Any] = []
        self.commits = 0
        self.refreshes = 0

    async def exec(self, _statement: Any) -> _FakeExecResult:
        return _FakeExecResult(self._preload)

    def add(self, row: Any) -> None:
        self.added.append(row)

    async def commit(self) -> None:
        self.commits += 1

    async def refresh(self, _row: Any) -> None:
        self.refreshes += 1


class _FakeSessionScope:
    def __init__(self, session: _FakeSession) -> None:
        self._session = session

    async def __aenter__(self) -> _FakeSession:
        return self._session

    async def __aexit__(self, *_exc: Any) -> None:
        return None


@pytest.mark.asyncio
async def test_ensure_instance_insert_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Absent row -> insert with PENDING + enabled=True + module_scope set."""
    session = _FakeSession(preload=None)
    monkeypatch.setattr(
        ic, "async_session_scope", lambda: _FakeSessionScope(session),
    )

    catalog = ic.McpInstanceCatalog()
    row = await catalog.ensure_instance(
        module_scope="vr",
        name="audit_mcp",
        transport="http",
        endpoint="http://localhost:18822",
        capability_tags=["source_audit"],
    )

    assert session.added == [row], "insert path must add exactly one row"
    assert session.commits == 1
    assert row.module_scope == "vr"
    assert row.name == "audit_mcp"
    assert row.transport == "http"
    assert row.endpoint == "http://localhost:18822"
    assert row.enabled is True
    assert row.approval_state == ic.McpApprovalState.PENDING.value


@pytest.mark.asyncio
async def test_ensure_instance_update_preserves_operator_columns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Present row -> transport/endpoint refresh only; approval + enabled untouched."""
    existing = ic.McpServerInstance(
        id="fixed-id",
        name="audit_mcp",
        transport="http",
        endpoint="http://old-endpoint",
        capability_tags=ic.encode_capability_tags(["source_audit"]),
        enabled=False,  # operator-disabled -- must survive reconciliation
        module_scope="vr",
        team_id=None,
        approval_state=ic.McpApprovalState.APPROVED.value,  # operator-approved
        approved_hash="deadbeef",
        schema_hash="deadbeef",
        server_card_json=None,
    )
    session = _FakeSession(preload=existing)
    monkeypatch.setattr(
        ic, "async_session_scope", lambda: _FakeSessionScope(session),
    )

    catalog = ic.McpInstanceCatalog()
    row = await catalog.ensure_instance(
        module_scope="vr",
        name="audit_mcp",
        transport="http",
        endpoint="http://new-endpoint",  # new transport-layer contract
        capability_tags=["binary_audit"],  # MUST be ignored on update
    )

    assert row is existing, "update path must return the existing row"
    assert row.endpoint == "http://new-endpoint"
    # Operator-owned columns preserved verbatim:
    assert row.enabled is False
    assert row.approval_state == ic.McpApprovalState.APPROVED.value
    assert row.approved_hash == "deadbeef"
    # capability_tags NEVER clobbered by boot reconciliation:
    assert ic.decode_capability_tags(row.capability_tags) == ["source_audit"]


@pytest.mark.asyncio
async def test_ensure_instance_idempotent_when_transport_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same transport + endpoint -> no write, no updated_at bump."""
    existing = ic.McpServerInstance(
        id="fixed-id",
        name="audit_mcp",
        transport="http",
        endpoint="http://same",
        capability_tags="[]",
        enabled=True,
        module_scope="vr",
        team_id=None,
        approval_state=ic.McpApprovalState.PENDING.value,
    )
    session = _FakeSession(preload=existing)
    monkeypatch.setattr(
        ic, "async_session_scope", lambda: _FakeSessionScope(session),
    )

    catalog = ic.McpInstanceCatalog()
    row = await catalog.ensure_instance(
        module_scope="vr",
        name="audit_mcp",
        transport="http",
        endpoint="http://same",
        capability_tags=[],
    )

    assert row is existing
    assert session.added == [], "no-op update must not add"
    assert session.commits == 0, "no-op update must not commit"


@pytest.mark.skip(
    reason="Round-trip through Postgres for the migrated mcp_call_log lives in the live-infra suite.",
)
def test_platform_mcp_calls_end_to_end() -> None:
    """Full HTTP round-trip is exercised against a real DB by the live suite."""
    raise NotImplementedError
