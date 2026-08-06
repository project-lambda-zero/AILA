"""RFC-11 -- module-declared MCP descriptors + capability-first
registry + generic-client wire-shape assertion.

The tests here prove three claims from the RFC-11 acceptance surface:

1. Modules DECLARE their MCP servers as
   :class:`aila.platform.mcp.McpServerDescriptor` instances published to
   the platform :class:`aila.platform.mcp.McpCapabilityRegistry`; the
   platform never hard-codes a per-module server catalog. The VR + malware
   modules already declare their descriptors at ``create_module()`` time
   via :meth:`McpCapabilityRegistry.declare_all`; the registry snapshot
   is inspected here.
2. Capability-based binding: a caller resolves an instance BY CAPABILITY
   (``android_audit``, ``binary_audit``, ``source_audit``), never by
   module name. The RFC-05 boundary rule holds -- the platform accepts
   whatever ``module_scope`` a declaration ships with and the resolver
   scopes lookups to the caller's chosen scope, no literal module names
   in the platform code path.
3. Wire-shape proof: opening an
   :class:`~aila.platform.mcp.McpClient` from the ``android_audit``
   descriptor and calling ``analyze_native_libs`` produces the exact
   HTTP wire request the operator-critical live dispatch path emits
   (URL, method, JSON body). No live server is contacted; the mock
   :class:`httpx.AsyncClient` records every call.

RFC-11 Tier C deleted the three bespoke bridges
(``AndroidMcpBridgeTool`` / ``AuditMcpBridgeTool`` / ``IDABridgeTool``)
in favour of the generic :class:`aila.platform.mcp.bridge_tool.McpBridgeTool`
+ per-server :class:`aila.platform.mcp.middleware.McpMiddleware` plugins.
The parity half of the wire-shape test (which asserted the pre-Tier-C
``AndroidMcpBridgeTool.forward`` matched the generic client byte for
byte) and the ``test_all_bridges_remain_registered`` regression are
both gone with those classes.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from aila.modules.malware.services.mcp_registry import (
    get_descriptors as malware_descriptors,
)
from aila.modules.vr.services.mcp_registry import (
    get_descriptors as vr_descriptors,
)
from aila.platform.mcp import (
    McpCapabilityRegistry,
    McpClient,
    McpServerDescriptor,
    ModuleDescriptorDeclaration,
    descriptors_from_static_specs,
)

__all__: list[str] = []


# ── mock transport helpers ────────────────────────────────────────────


class _MockResponse:
    """Minimal ``httpx.Response`` stand-in for the parity assertions."""

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
        return self._json


class _MockAsyncClient:
    """Records every request; returns queued responses in FIFO order.

    The generic :class:`McpClient` constructs a new context-managed
    ``httpx.AsyncClient`` per call. The mock supports the ``async with``
    context manager entry point; extra kwargs (``timeout=``, ``limits=``)
    are captured but ignored.
    """

    def __init__(
        self,
        *,
        post_response: _MockResponse | None = None,
        **_kwargs: Any,
    ) -> None:
        self._post_response = post_response or _MockResponse(
            json_body={"status": "ready"},
        )
        self.posts: list[dict[str, Any]] = []

    async def __aenter__(self) -> _MockAsyncClient:
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        return None

    async def post(
        self, url: str, json: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> _MockResponse:
        self.posts.append({
            "url": url, "json": json, "timeout": timeout,
        })
        return self._post_response

    async def get(self, url: str) -> _MockResponse:
        # Bridge's ``list_tool_specs`` runs a GET before dispatch when
        # its class-level cache is cold. The parity test skips catalog
        # validation by pre-populating the cache in the fixture below.
        return _MockResponse(json_body={"tools": []})

    async def aclose(self) -> None:
        return None


# ── McpServerDescriptor construction + validation ─────────────────────


def test_descriptor_normalises_and_rejects_empty_fields() -> None:
    """The frozen descriptor strips whitespace and rejects empty fields."""
    d = McpServerDescriptor(
        name="  android_mcp  ",
        capability_tags=("  android_audit ",),
        env_var="  ANDROID_MCP_URL ",
        config_key=" android_mcp_url ",
        default_url="http://127.0.0.1:18823/",
        description="  android bridge  ",
    )
    assert d.name == "android_mcp"
    assert d.env_var == "ANDROID_MCP_URL"
    assert d.config_key == "android_mcp_url"
    assert d.default_url == "http://127.0.0.1:18823"
    assert d.capability_tags == ("android_audit",)
    assert d.advertises("android_audit") is True
    assert d.advertises("binary_audit") is False

    with pytest.raises(ValueError, match="name"):
        McpServerDescriptor(
            name="   ", capability_tags=("t",),
            env_var="E", config_key="c", default_url="http://x",
        )
    with pytest.raises(ValueError, match="capability_tags"):
        McpServerDescriptor(
            name="n", capability_tags=(),
            env_var="E", config_key="c", default_url="http://x",
        )
    with pytest.raises(ValueError, match="transport"):
        McpServerDescriptor(
            name="n", capability_tags=("t",),
            env_var="E", config_key="c", default_url="http://x",
            transport="grpc",
        )


def test_descriptors_from_static_specs_maps_capability_defaults() -> None:
    """The adapter reads MCP_SERVERS + SERVER_CAPABILITY_DEFAULTS."""
    specs = (
        {
            "id": "audit_mcp",
            "name": "audit-mcp",
            "description": "src audit",
            "env_var": "AUDIT_MCP_URL",
            "config_key": "audit_mcp_url",
            "default_url": "http://127.0.0.1:18822",
        },
        {
            "id": "android_mcp",
            "name": "android-mcp",
            "description": "android audit",
            "env_var": "ANDROID_MCP_URL",
            "config_key": "android_mcp_url",
            "default_url": "http://127.0.0.1:18823",
        },
        {
            "id": "unknown_server",
            "name": "no-caps",
            "env_var": "UNK_URL",
            "config_key": "unk_url",
            "default_url": "http://127.0.0.1:19999",
        },
    )
    caps = {
        "audit_mcp": ("source_audit",),
        "android_mcp": ("android_audit",),
        # unknown_server: intentionally absent; the adapter skips it.
    }
    out = descriptors_from_static_specs(specs, caps)
    names = [d.name for d in out]
    assert names == ["audit_mcp", "android_mcp"]  # unknown skipped
    assert out[1].capability_tags == ("android_audit",)


# ── module-declared descriptors ───────────────────────────────────────


def test_vr_module_declares_android_and_source_audit_descriptors() -> None:
    """The VR module publishes descriptors for android + source + binary."""
    ds = vr_descriptors()
    names = sorted(d.name for d in ds)
    assert names == ["android_mcp", "audit_mcp", "ida_headless"]
    caps = {d.name: d.capability_tags for d in ds}
    assert caps["android_mcp"] == ("android_audit",)
    assert caps["audit_mcp"] == ("source_audit",)
    assert caps["ida_headless"] == ("binary_audit",)


def test_malware_module_declares_binary_and_source_audit_descriptors() -> None:
    """The malware module publishes descriptors under its own scope."""
    ds = malware_descriptors()
    names = sorted(d.name for d in ds)
    assert names == ["audit_mcp", "ida_headless_exp"]
    caps = {d.name: d.capability_tags for d in ds}
    assert caps["ida_headless_exp"] == ("binary_audit",)
    assert caps["audit_mcp"] == ("source_audit",)


# ── McpCapabilityRegistry ─────────────────────────────────────────────


def test_capability_registry_declare_and_resolve() -> None:
    """``declare_all`` + ``descriptors_for_capability`` roundtrip."""
    reg = McpCapabilityRegistry()
    reg.declare_all("vr", vr_descriptors())
    reg.declare_all("malware", malware_descriptors())

    android = reg.descriptors_for_capability("android_audit")
    assert [(d.module_scope, d.descriptor.name) for d in android] == [
        ("vr", "android_mcp"),
    ]

    binary = reg.descriptors_for_capability("binary_audit")
    assert sorted((d.module_scope, d.descriptor.name) for d in binary) == [
        ("malware", "ida_headless_exp"),
        ("vr", "ida_headless"),
    ]

    source = reg.descriptors_for_capability("source_audit")
    assert sorted((d.module_scope, d.descriptor.name) for d in source) == [
        ("malware", "audit_mcp"),
        ("vr", "audit_mcp"),
    ]

    # Scoped lookup narrows to one module.
    vr_binary = reg.descriptors_for_capability(
        "binary_audit", module_scope="vr",
    )
    assert [d.descriptor.name for d in vr_binary] == ["ida_headless"]

    # Unknown capability returns an empty tuple; empty capability likewise.
    assert reg.descriptors_for_capability("unknown_capability") == ()
    assert reg.descriptors_for_capability("") == ()


def test_capability_registry_declare_is_idempotent() -> None:
    """Re-declaring under the same (scope, name) supersedes the old row."""
    reg = McpCapabilityRegistry()
    d1 = McpServerDescriptor(
        name="probe_mcp",
        capability_tags=("test_capability",),
        env_var="PROBE_MCP_URL",
        config_key="probe_mcp_url",
        default_url="http://127.0.0.1:19998",
    )
    reg.declare("test_scope", d1)
    reg.declare("test_scope", d1)  # idempotent
    all_records = reg.declarations(module_scope="test_scope")
    assert len(all_records) == 1
    assert all_records[0].descriptor is d1


def test_capability_registry_open_pool_for_capability_single_descriptor() -> None:
    """``open_pool_for_capability`` returns one wired ``McpClient`` per match.

    RFC-11 pooling composition: for a capability advertised by exactly
    one declared descriptor, the pool is a singleton tuple carrying an
    ``McpClient`` whose ``server_id`` and ``timeout`` mirror what
    :meth:`McpCapabilityRegistry.open_client` would return.
    """
    reg = McpCapabilityRegistry()
    descriptor = McpServerDescriptor(
        name="probe_mcp",
        capability_tags=("binary_audit",),
        env_var="PROBE_MCP_URL",
        config_key="probe_mcp_url",
        default_url="http://127.0.0.1:19998",
        timeout_s=42.0,
    )
    reg.declare("test_scope", descriptor)

    pool = reg.open_pool_for_capability("binary_audit")

    assert isinstance(pool, tuple)
    assert len(pool) == 1
    (client,) = pool
    assert isinstance(client, McpClient)
    assert client.server_id == "probe_mcp"
    # Parity with :meth:`McpCapabilityRegistry.open_client`: the
    # descriptor's timeout flows through to the client's internal
    # timeout budget so pooled fan-out matches direct open.
    assert client._timeout == 42.0  # noqa: SLF001


def test_capability_registry_open_pool_for_capability_multi_descriptor() -> None:
    """Multi-descriptor capability: the pool fans out across scopes.

    Two modules each declare their own descriptor advertising the same
    capability. The pool contains one ``McpClient`` per declaration in
    declaration order, each pre-wired to its own descriptor.
    """
    reg = McpCapabilityRegistry()
    d_vr = McpServerDescriptor(
        name="audit_mcp",
        capability_tags=("source_audit",),
        env_var="VR_AUDIT_MCP_URL",
        config_key="audit_mcp_url",
        default_url="http://127.0.0.1:18822",
    )
    d_malware = McpServerDescriptor(
        name="audit_mcp",
        capability_tags=("source_audit",),
        env_var="MALWARE_AUDIT_MCP_URL",
        config_key="audit_mcp_url",
        default_url="http://127.0.0.1:18823",
    )
    reg.declare("vr", d_vr)
    reg.declare("malware", d_malware)

    pool = reg.open_pool_for_capability("source_audit")

    assert isinstance(pool, tuple)
    assert len(pool) == 2
    assert all(isinstance(c, McpClient) for c in pool)
    # Same server name under two scopes -> two distinct clients wired
    # to the same server_id but resolving through separate scopes.
    assert {c.server_id for c in pool} == {"audit_mcp"}

    # Narrowing by module_scope reduces the pool to that scope only.
    vr_pool = reg.open_pool_for_capability(
        "source_audit", module_scope="vr",
    )
    assert len(vr_pool) == 1
    assert isinstance(vr_pool[0], McpClient)


def test_capability_registry_open_pool_for_capability_empty() -> None:
    """No descriptor advertises the capability -> empty tuple, no raise.

    The pool is a fan-out target; an empty pool is a legitimate
    "nothing to do" signal rather than an error. Mirrors
    :meth:`McpRegistryServiceBase.pool_for_capability` which also
    emits an empty pool rather than raising.
    """
    reg = McpCapabilityRegistry()
    descriptor = McpServerDescriptor(
        name="probe_mcp",
        capability_tags=("binary_audit",),
        env_var="PROBE_MCP_URL",
        config_key="probe_mcp_url",
        default_url="http://127.0.0.1:19998",
    )
    reg.declare("test_scope", descriptor)

    assert reg.open_pool_for_capability("no_such_capability") == ()
    # An empty registry also produces an empty pool.
    empty_reg = McpCapabilityRegistry()
    assert empty_reg.open_pool_for_capability("binary_audit") == ()
    # Blank capability is treated as "no match" -- consistent with
    # ``descriptors_for_capability("")``.
    assert reg.open_pool_for_capability("") == ()


# ── Generic-client wire-shape assertion ──────────────────────────────
#
# The Step-0 test also exercised the pre-Tier-C ``AndroidMcpBridgeTool``
# to prove byte-for-byte parity. Tier C deleted that bridge (behaviour
# now lives on :class:`AndroidMcpMiddleware`), so the parity half is
# gone; only the McpClient-direct wire assertion is kept because it
# still exercises the generic client's URL + JSON body shape without
# a live server.


@pytest.fixture
def _android_descriptor() -> McpServerDescriptor:
    """The android_mcp descriptor the VR module declares."""
    ds = [d for d in vr_descriptors() if d.name == "android_mcp"]
    assert ds, "VR module must declare an android_mcp descriptor"
    return ds[0]


@pytest.mark.asyncio
async def test_generic_client_wire_shape(
    _android_descriptor: McpServerDescriptor,
) -> None:
    """``McpClient.call_tool`` posts ``<base>/tools/<action>`` with the
    kwargs as the JSON body.

    Pins the fixed base URL so the four-tier resolver is bypassed and
    the assertion is deterministic without a catalog row. ``httpx.AsyncClient``
    is patched with a mock that records every request; the recorded
    POST is inspected for URL, method, and JSON body.
    """
    base_url = "http://mock-android:18823"
    action = "analyze_native_libs"
    kwargs = {
        "so_path": "/decompiled_libs/lib_target.so",
        "deep_scan": True,
    }

    reg = McpCapabilityRegistry()
    declaration = reg.declare("vr", _android_descriptor)
    client = McpClient(server_id="android_mcp", base_url=base_url)
    generic_mock = _MockAsyncClient(
        post_response=_MockResponse(json_body={"status": "ready", "ok": True}),
    )
    with patch("httpx.AsyncClient", return_value=generic_mock):
        generic_result = await client.call_tool(action, kwargs)

    assert generic_result.get("status") == "ready"
    assert len(generic_mock.posts) == 1
    generic_post = generic_mock.posts[0]

    # URL: ``<base>/tools/<action>``.
    assert generic_post["url"] == f"{base_url}/tools/{action}"
    # JSON body: the tool kwargs verbatim.
    assert generic_post["json"] == kwargs
    # The descriptor resolves under the vr scope + android_audit
    # capability (module-name-agnostic dispatch surface).
    assert declaration.module_scope == "vr"
    assert declaration.descriptor.advertises("android_audit")


def test_capability_registry_declaration_never_needs_module_name_literal() -> None:
    """RFC-05 boundary sanity: the platform registry never learns which
    modules exist. A caller can declare an entirely made-up scope and
    the registry stores it verbatim -- the platform does not gate on
    a hard-coded module id set.
    """
    reg = McpCapabilityRegistry()
    made_up = McpServerDescriptor(
        name="new_server",
        capability_tags=("brand_new_capability",),
        env_var="NEW_SERVER_URL",
        config_key="new_server_url",
        default_url="http://127.0.0.1:19997",
    )
    reg.declare("some_future_module_id", made_up)
    resolved = reg.descriptors_for_capability("brand_new_capability")
    assert len(resolved) == 1
    assert resolved[0].module_scope == "some_future_module_id"


def test_module_descriptor_declaration_is_frozen() -> None:
    """``ModuleDescriptorDeclaration`` is immutable so registry
    snapshots hand safely across concurrent consumers.
    """
    d = McpServerDescriptor(
        name="freeze_test",
        capability_tags=("test",),
        env_var="X_URL",
        config_key="x_url",
        default_url="http://x",
    )
    record = ModuleDescriptorDeclaration(module_scope="scope", descriptor=d)
    with pytest.raises(AttributeError):
        record.module_scope = "other"  # type: ignore[misc]
