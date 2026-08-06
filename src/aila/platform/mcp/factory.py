"""RFC-11 Tier C -- construct the generic MCP bridge for a server id.

``make_bridge("ida_headless", module_id="vr", recorder=record_call)``
replaces the pre-Tier-C ``IDABridgeTool(recorder=record_call,
module_id="vr")`` and its two siblings. The transport parameters come
from :data:`aila.platform.mcp.server_specs.SERVER_SPECS`; the
server-specific behaviour comes from a :class:`McpMiddleware` plugin
resolved lazily by server id so this module carries no import-time
dependency on the concrete plugins.

A server id with no registered plugin (an operator adds a brand-new MCP
server to the catalog) resolves to a synthesized spec + the pass-through
:class:`GenericMiddleware`, so a new server advertising a bound
capability dispatches without a code change.
"""
from __future__ import annotations

import importlib
from typing import Any

from aila.platform.mcp.bridge_tool import McpBridgeTool
from aila.platform.mcp.middleware import McpMiddleware
from aila.platform.mcp.server_specs import SERVER_SPECS, ServerSpec

__all__ = ["make_bridge", "load_middleware", "middleware_family"]


# server_id -> (module path, class name). Lazy so the factory imports
# before the plugin modules exist and so importing the factory does not
# drag every plugin (and its regex tables) into memory. A server id
# absent from this map falls back to the pass-through GenericMiddleware.
_MIDDLEWARE_REF: dict[str, tuple[str, str]] = {
    "ida_headless": ("aila.platform.mcp.middleware.ida", "IdaMiddleware"),
    "ida_headless_exp": ("aila.platform.mcp.middleware.ida", "IdaMiddleware"),
    "audit_mcp": ("aila.platform.mcp.middleware.audit", "AuditMcpMiddleware"),
    "android_mcp": ("aila.platform.mcp.middleware.android", "AndroidMcpMiddleware"),
}

_GENERIC_REF: tuple[str, str] = (
    "aila.platform.mcp.middleware.generic", "GenericMiddleware",
)


def _resolve_spec(server_id: str) -> ServerSpec:
    """Return the canonical spec, or synthesize one for a new server.

    A catalog-only server (no static :data:`SERVER_SPECS` entry) is
    dispatched exclusively through a router-pinned instance, so its
    env / config / default resolver inputs are placeholders -- the
    endpoint always arrives via the pinned catalog row.
    """
    spec = SERVER_SPECS.get(server_id)
    if spec is not None:
        return spec
    return ServerSpec(
        server_id=server_id,
        tool_name=server_id,
        env_var=f"{server_id.upper()}_URL",
        config_key=f"{server_id}_url",
        default_url="",
        default_timeout=120.0,
        persistent_pool=False,
    )


def middleware_family(server_id: str) -> str:
    """Return the middleware class name that serves ``server_id``.

    The router pools only instances that share a family -- ``ida_headless``
    and ``ida_headless_exp`` both map to ``IdaMiddleware`` so a call for
    one can fail over to / share load with the other, while an unrelated
    server (a differently-contracted tool set) is never a pool member
    even when it shares a capability tag.
    """
    ref = _MIDDLEWARE_REF.get(server_id)
    return ref[1] if ref is not None else _GENERIC_REF[1]


def load_middleware(spec: ServerSpec, *, module_id: str) -> McpMiddleware:
    """Instantiate the middleware plugin bound to ``spec``.

    Falls back to :class:`GenericMiddleware` for a server id with no
    registered plugin so a new catalog server still dispatches.
    """
    module_path, class_name = _MIDDLEWARE_REF.get(spec.server_id, _GENERIC_REF)
    module = importlib.import_module(module_path)
    middleware_cls = getattr(module, class_name)
    return middleware_cls(spec=spec, module_id=module_id)


def make_bridge(
    server_id: str,
    *,
    module_id: str,
    recorder: Any | None = None,
) -> McpBridgeTool:
    """Return a :class:`McpBridgeTool` for ``server_id`` under ``module_id``.

    ``recorder`` is the module's ``record_call`` audit-log context factory
    (or ``None`` for ad-hoc / test callers, which write no rows).
    """
    spec = _resolve_spec(server_id)
    middleware = load_middleware(spec, module_id=module_id)
    return McpBridgeTool(
        middleware=middleware, module_id=module_id, recorder=recorder,
    )
