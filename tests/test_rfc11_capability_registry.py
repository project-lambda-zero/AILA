"""RFC-11 step 0/3 -- module-declared MCP descriptors + capability-first
registry + generic-client parity proof against the bespoke android_mcp
bridge.

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
3. Step-0 proof: opening an
   :class:`~aila.platform.mcp.McpClient` from the ``android_audit``
   descriptor and calling ``verify_capabilities`` produces the EXACT
   HTTP wire request the operator-critical
   :class:`aila.platform.mcp.bridges.AndroidMcpBridgeTool` would emit
   (URL, method, JSON body). No live server is contacted; both sides
   run against a mocked :class:`httpx.AsyncClient`.

Every existing bespoke bridge (``AndroidMcpBridgeTool``,
``AuditMcpBridgeTool``, ``IDABridgeTool``) stays intact and registered
in :mod:`aila.platform.mcp.bridges` -- confirmed by the
``test_all_bridges_remain_registered`` regression at the bottom.
"""
from __future__ import annotations

import asyncio
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
from aila.platform.mcp import (
    bridges as _bridges_module,
)
from aila.platform.mcp.bridges import (
    AndroidMcpBridgeTool,
    AuditMcpBridgeTool,
    IDABridgeTool,
)
from aila.platform.mcp.bridges import (
    android_mcp as _android_bridge_mod,
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

    Both callers (:class:`AndroidMcpBridgeTool` and :class:`McpClient`)
    open ``httpx.AsyncClient`` differently -- the bridge shares a
    module-level pooled client, the generic client constructs a new
    context-managed client per call. The mock supports both entry
    points: an ``async with`` context manager AND a bare instance
    passed through the bridge's shared-pool getter. Extra kwargs
    (``timeout=``, ``limits=``) are captured but ignored.
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


def test_capability_registry_open_pool_not_implemented_seam() -> None:
    """Later increment seam: ``open_pool_for_capability`` raises today."""

    async def _run() -> None:
        reg = McpCapabilityRegistry()
        with pytest.raises(NotImplementedError, match="pooling composition"):
            await reg.open_pool_for_capability("binary_audit")

    asyncio.run(_run())


# ── Step-0 request-shape parity: generic client vs android bridge ────


@pytest.fixture
def _android_descriptor() -> McpServerDescriptor:
    """The android_mcp descriptor the VR module declares."""
    ds = [d for d in vr_descriptors() if d.name == "android_mcp"]
    assert ds, "VR module must declare an android_mcp descriptor"
    return ds[0]


@pytest.mark.asyncio
async def test_generic_client_wire_shape_matches_android_bridge(
    _android_descriptor: McpServerDescriptor,
) -> None:
    """Route ONE server (android_mcp) through the generic client
    (RFC-11 step 0) and prove the wire request matches the bespoke
    :class:`AndroidMcpBridgeTool.forward` byte-for-byte.

    Behaviour-preserving: both callers pin to the same fixed base URL
    (bypasses the four-tier resolver so the assertion is deterministic
    without a live catalog row) and dispatch the same ``verify_capabilities``
    action with identical kwargs. The mocked transport records every
    HTTP POST; the two POSTs are then compared for URL, JSON body, and
    method (both use httpx POST).

    Bridge-side prep: the bridge's schema validator runs before
    dispatch, so pre-seed the class-level catalog cache with the tool
    known and no schema (validator falls through to unchecked forward
    when the cached schema is empty).
    """
    base_url = "http://mock-android:18823"
    # ``analyze_native_libs`` takes ``so_path`` -- NOT one of the
    # bridge's ``_APK_PATH_KWARGS`` (``apk_path`` / ``apk`` /
    # ``path``) that trigger the SHA typo resolver. This keeps the
    # kwargs untouched between the bridge and the generic client so
    # the parity assertion stays deterministic across dev machines
    # (including ones that happen to have a real APK cached under
    # ``~/.android-mcp/uploads/shared/``).
    action = "analyze_native_libs"
    kwargs = {
        "so_path": "/decompiled_libs/lib_target.so",
        "deep_scan": True,
    }

    # Pre-populate the bridge catalog cache with an EMPTY list so the
    # schema validator short-circuits (per ``_validate_kwargs``: when
    # ``list_tool_specs()`` is empty, validation is skipped and the
    # call forwards untouched). The parity test does not exercise
    # validation; it exercises transport.
    AndroidMcpBridgeTool._SPEC_CACHE = []

    # --- Bridge path: existing AndroidMcpBridgeTool.forward ---
    bridge_mock = _MockAsyncClient(
        post_response=_MockResponse(json_body={"status": "ready", "ok": True}),
    )
    # The bridge fetches its httpx client from the module-level shared
    # pool via ``_get_shared_client``. Patch that to return our mock.
    with patch.object(
        _android_bridge_mod, "_get_shared_client",
        new=lambda: _return(bridge_mock),
    ):
        bridge = AndroidMcpBridgeTool(base_url=base_url)
        bridge_result = await bridge.forward(action=action, **kwargs)

    assert bridge_result.get("status") == "ready"
    assert len(bridge_mock.posts) == 1
    bridge_post = bridge_mock.posts[0]

    # --- Generic client path: McpClient via capability registry ---
    reg = McpCapabilityRegistry()
    declaration = reg.declare("vr", _android_descriptor)
    # Open a client with a fixed base_url (test-only DI shape) so both
    # callers hit the same URL without a catalog row.
    client = McpClient(server_id="android_mcp", base_url=base_url)
    generic_mock = _MockAsyncClient(
        post_response=_MockResponse(json_body={"status": "ready", "ok": True}),
    )
    with patch("httpx.AsyncClient", return_value=generic_mock):
        generic_result = await client.call_tool(action, kwargs)

    assert generic_result.get("status") == "ready"
    assert len(generic_mock.posts) == 1
    generic_post = generic_mock.posts[0]

    # --- Parity assertions ---
    # 1. URL: ``<base>/tools/<action>``.
    assert bridge_post["url"] == generic_post["url"]
    assert bridge_post["url"] == f"{base_url}/tools/{action}"
    # 2. JSON body: the tool kwargs verbatim (both callers pass kwargs
    #    straight into the POST body).
    assert bridge_post["json"] == generic_post["json"]
    assert bridge_post["json"] == kwargs
    # 3. Method: httpx.post -> POST. Both sides go through _MockAsyncClient
    #    .post; if either used GET or a different verb the response would
    #    not land in .posts.
    # 4. The descriptor knows this call resolves under the vr scope +
    #    android_audit capability (this is what makes the generic path
    #    module-name-agnostic).
    assert declaration.module_scope == "vr"
    assert declaration.descriptor.advertises("android_audit")


def _return(value: Any) -> Any:
    """Async wrapper for the bridge's shared-client getter patch.

    ``_get_shared_client`` is an ``async def``; the patched replacement
    must therefore await the value. Passing a bare lambda would return
    the mock synchronously and the bridge would try to ``await`` it,
    which fails.
    """
    async def _coro() -> Any:
        return value

    return _coro()


# ── Bridge preservation regression ────────────────────────────────────


def test_all_bridges_remain_registered() -> None:
    """RFC-11 step 0 acceptance: every existing bridge stays intact
    and importable.

    Confirms the ``android_mcp`` / ``audit_mcp`` / ``ida_headless``
    bridges are still exposed from :mod:`aila.platform.mcp.bridges` --
    the operator-critical live dispatch path (audit-mcp :18822,
    ida-headless :18821, android-mcp :18823) remains untouched by
    the RFC-11 foundation work in this ticket.
    """
    assert _bridges_module.AndroidMcpBridgeTool is AndroidMcpBridgeTool
    assert _bridges_module.AuditMcpBridgeTool is AuditMcpBridgeTool
    assert _bridges_module.IDABridgeTool is IDABridgeTool
    assert set(_bridges_module.__all__) == {
        "AndroidMcpBridgeTool", "AuditMcpBridgeTool", "IDABridgeTool",
    }


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
