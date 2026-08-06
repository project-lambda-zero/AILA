"""RFC-11 step 1 -- unit tests for :class:`McpInstanceCatalog`.

Covers the model round-trip (add, list, set_enabled, update_endpoint,
update_capability_tags, remove), the JSON serialisation of the
``capability_tags`` text column, the ``(module_scope, name)`` filter on
``list_instances``, and the registry catalog-first fallback semantics
(catalog row overrides ``default_url``; empty catalog falls back to the
static tuple; disabled row is treated as no-override).
"""
from __future__ import annotations

import os
from typing import ClassVar
from uuid import uuid4

import pytest

# Top-level import so SQLModel.metadata registers the table BEFORE the
# session-scoped test_db fixture calls create_all.
from aila.platform.mcp.instance_catalog import (
    TRANSPORT_HTTP,
    TRANSPORT_STDIO,
    McpInstanceCatalog,
    McpServerInstance,
    decode_capability_tags,
)
from aila.platform.mcp.registry import McpRegistryServiceBase

__all__: list[str] = []


def _fresh_scope() -> str:
    """Per-test module_scope so parallel runs never collide on the unique key."""
    return f"rfc11test-{uuid4().hex[:8]}"


@pytest.mark.asyncio
async def test_add_and_list_instance(test_db) -> None:
    """add_instance persists a row; list_instances returns it."""
    del test_db
    catalog = McpInstanceCatalog()
    scope = _fresh_scope()

    row = await catalog.add_instance(
        name="audit_mcp",
        transport=TRANSPORT_HTTP,
        endpoint="http://10.0.0.1:18822",
        capability_tags=["source_audit", "graph"],
        module_scope=scope,
    )
    assert row.id  # uuid generated when not supplied
    assert row.name == "audit_mcp"
    assert row.transport == TRANSPORT_HTTP
    assert row.endpoint == "http://10.0.0.1:18822"
    assert row.enabled is True
    assert row.module_scope == scope
    assert row.created_at is not None
    assert row.updated_at is None

    listed = await catalog.list_instances(module_scope=scope)
    assert [r.id for r in listed] == [row.id]
    assert isinstance(listed[0], McpServerInstance)


@pytest.mark.asyncio
async def test_capability_tags_json_roundtrip(test_db) -> None:
    """capability_tags survive JSON encode/decode across list/add/update."""
    del test_db
    catalog = McpInstanceCatalog()
    scope = _fresh_scope()

    row = await catalog.add_instance(
        name="ida_headless",
        transport=TRANSPORT_HTTP,
        endpoint="http://10.0.0.2:18821",
        capability_tags=["binary_audit", "decompile", "exploit"],
        module_scope=scope,
    )
    assert decode_capability_tags(row.capability_tags) == [
        "binary_audit", "decompile", "exploit",
    ]

    # An empty list also round-trips cleanly and is the default.
    empty = await catalog.add_instance(
        name="android_mcp",
        transport=TRANSPORT_HTTP,
        endpoint="http://10.0.0.3:18823",
        module_scope=scope,
    )
    assert decode_capability_tags(empty.capability_tags) == []

    # Update the tags and confirm they parse back.
    updated = await catalog.update_capability_tags(row.id, ["source_audit"])
    assert updated is not None
    assert decode_capability_tags(updated.capability_tags) == ["source_audit"]

    # The dict projection converts to a real list, not the raw JSON string.
    projected = catalog.instance_to_dict(updated)
    assert projected["capability_tags"] == ["source_audit"]


@pytest.mark.asyncio
async def test_set_enabled_toggles_flag(test_db) -> None:
    """set_enabled flips the bit and stamps updated_at."""
    del test_db
    catalog = McpInstanceCatalog()
    scope = _fresh_scope()

    row = await catalog.add_instance(
        name="audit_mcp",
        transport=TRANSPORT_HTTP,
        endpoint="http://10.0.0.4:18822",
        module_scope=scope,
    )
    assert row.enabled is True

    disabled = await catalog.set_enabled(row.id, False)
    assert disabled is not None
    assert disabled.enabled is False
    assert disabled.updated_at is not None

    re_enabled = await catalog.set_enabled(row.id, True)
    assert re_enabled is not None
    assert re_enabled.enabled is True

    # Unknown id returns None instead of raising.
    missing = await catalog.set_enabled("no-such-id", False)
    assert missing is None


@pytest.mark.asyncio
async def test_update_endpoint_retargets(test_db) -> None:
    """update_endpoint rewrites the URL and stamps updated_at."""
    del test_db
    catalog = McpInstanceCatalog()
    scope = _fresh_scope()

    row = await catalog.add_instance(
        name="audit_mcp",
        transport=TRANSPORT_HTTP,
        endpoint="http://10.0.0.5:18822",
        module_scope=scope,
    )
    assert row.endpoint == "http://10.0.0.5:18822"

    moved = await catalog.update_endpoint(row.id, "http://10.0.0.99:18822")
    assert moved is not None
    assert moved.endpoint == "http://10.0.0.99:18822"
    assert moved.updated_at is not None

    missing = await catalog.update_endpoint("no-such-id", "http://x")
    assert missing is None


@pytest.mark.asyncio
async def test_module_scope_filter(test_db) -> None:
    """list_instances honours module_scope and returns only that scope's rows."""
    del test_db
    catalog = McpInstanceCatalog()
    scope_vr = _fresh_scope()
    scope_malware = _fresh_scope()

    await catalog.add_instance(
        name="audit_mcp",
        transport=TRANSPORT_HTTP,
        endpoint="http://vr:18822",
        module_scope=scope_vr,
    )
    await catalog.add_instance(
        name="ida_headless",
        transport=TRANSPORT_HTTP,
        endpoint="http://vr:18821",
        module_scope=scope_vr,
    )
    await catalog.add_instance(
        name="audit_mcp",
        transport=TRANSPORT_HTTP,
        endpoint="http://malware:18822",
        module_scope=scope_malware,
    )

    vr_rows = await catalog.list_instances(module_scope=scope_vr)
    assert sorted(r.name for r in vr_rows) == ["audit_mcp", "ida_headless"]
    assert all(r.module_scope == scope_vr for r in vr_rows)

    malware_rows = await catalog.list_instances(module_scope=scope_malware)
    assert [r.name for r in malware_rows] == ["audit_mcp"]
    assert malware_rows[0].endpoint == "http://malware:18822"


@pytest.mark.asyncio
async def test_get_by_scope_and_name(test_db) -> None:
    """The registry uses (module_scope, name) to resolve endpoints."""
    del test_db
    catalog = McpInstanceCatalog()
    scope = _fresh_scope()

    await catalog.add_instance(
        name="audit_mcp",
        transport=TRANSPORT_HTTP,
        endpoint="http://10.0.0.6:18822",
        module_scope=scope,
    )

    hit = await catalog.get_by_scope_and_name(scope, "audit_mcp")
    assert hit is not None
    assert hit.endpoint == "http://10.0.0.6:18822"

    # Different scope, same name -- miss (no cross-scope leak).
    miss = await catalog.get_by_scope_and_name(_fresh_scope(), "audit_mcp")
    assert miss is None


@pytest.mark.asyncio
async def test_stdio_transport_accepted(test_db) -> None:
    """The stdio transport is a valid value on the transport column."""
    del test_db
    catalog = McpInstanceCatalog()
    scope = _fresh_scope()

    row = await catalog.add_instance(
        name="local_stdio",
        transport=TRANSPORT_STDIO,
        endpoint="python -m aila.tools.local_mcp",
        module_scope=scope,
    )
    assert row.transport == TRANSPORT_STDIO
    assert row.endpoint == "python -m aila.tools.local_mcp"


@pytest.mark.asyncio
async def test_unknown_transport_rejected(test_db) -> None:
    """add_instance validates the transport enum."""
    del test_db
    catalog = McpInstanceCatalog()
    with pytest.raises(ValueError, match="unknown transport"):
        await catalog.add_instance(
            name="broken",
            transport="grpc",
            endpoint="grpc://x",
            module_scope=_fresh_scope(),
        )


@pytest.mark.asyncio
async def test_remove_instance(test_db) -> None:
    """remove_instance deletes by PK and returns True; missing returns False."""
    del test_db
    catalog = McpInstanceCatalog()
    scope = _fresh_scope()

    row = await catalog.add_instance(
        name="audit_mcp",
        transport=TRANSPORT_HTTP,
        endpoint="http://10.0.0.7:18822",
        module_scope=scope,
    )
    assert await catalog.remove_instance(row.id) is True
    assert await catalog.remove_instance(row.id) is False
    assert await catalog.list_instances(module_scope=scope) == []


class _ProbeStubRegistry(McpRegistryServiceBase):
    """Minimal subclass used by the fallback tests below."""

    _module_id: ClassVar[str] = "rfc11test"
    _servers: ClassVar[tuple[dict[str, str], ...]] = (
        {
            "id": "audit_mcp",
            "name": "audit-mcp",
            "description": "test stub",
            "env_var": "RFC11TEST_AUDIT_MCP_URL_NEVER_SET",
            "config_key": "audit_mcp_url",
            "default_url": "http://code-default:18822",
        },
    )


@pytest.mark.asyncio
async def test_registry_falls_back_to_static_when_catalog_empty(test_db) -> None:
    """Empty catalog for this scope -> resolver keeps returning the static default."""
    del test_db
    # Ensure the env var is not set.
    os.environ.pop("RFC11TEST_AUDIT_MCP_URL_NEVER_SET", None)
    svc = _ProbeStubRegistry()
    url, source = await svc._resolved_url(svc._servers[0])
    assert url == "http://code-default:18822"
    assert source == "default"


@pytest.mark.asyncio
async def test_registry_uses_catalog_row_when_present(test_db) -> None:
    """A catalog row for this scope beats the static default_url."""
    del test_db
    os.environ.pop("RFC11TEST_AUDIT_MCP_URL_NEVER_SET", None)
    catalog = McpInstanceCatalog()
    await catalog.add_instance(
        name="audit_mcp",
        transport=TRANSPORT_HTTP,
        endpoint="http://catalog-endpoint:19000",
        module_scope=_ProbeStubRegistry._module_id,
    )
    svc = _ProbeStubRegistry()
    url, source = await svc._resolved_url(svc._servers[0])
    assert url == "http://catalog-endpoint:19000"
    assert source == "catalog"


@pytest.mark.asyncio
async def test_registry_ignores_disabled_catalog_row(test_db) -> None:
    """A disabled catalog row is treated as absent -- fall back to default."""
    del test_db
    os.environ.pop("RFC11TEST_AUDIT_MCP_URL_NEVER_SET", None)
    catalog = McpInstanceCatalog()
    row = await catalog.add_instance(
        name="audit_mcp",
        transport=TRANSPORT_HTTP,
        endpoint="http://catalog-endpoint:19001",
        module_scope=_ProbeStubRegistry._module_id,
    )
    disabled = await catalog.set_enabled(row.id, False)
    assert disabled is not None

    svc = _ProbeStubRegistry()
    url, source = await svc._resolved_url(svc._servers[0])
    assert url == "http://code-default:18822"
    assert source == "default"


@pytest.mark.asyncio
async def test_registry_env_still_wins_over_catalog(test_db) -> None:
    """Env var priority is preserved when the catalog is populated."""
    del test_db
    catalog = McpInstanceCatalog()
    await catalog.add_instance(
        name="audit_mcp",
        transport=TRANSPORT_HTTP,
        endpoint="http://catalog-endpoint:19002",
        module_scope=_ProbeStubRegistry._module_id,
    )
    os.environ["RFC11TEST_AUDIT_MCP_URL_NEVER_SET"] = "http://env-override:20000"
    try:
        svc = _ProbeStubRegistry()
        url, source = await svc._resolved_url(svc._servers[0])
        assert url == "http://env-override:20000"
        assert source == "env"
    finally:
        os.environ.pop("RFC11TEST_AUDIT_MCP_URL_NEVER_SET", None)
