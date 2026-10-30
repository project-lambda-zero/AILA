"""RFC-11 Tier C -- canonical transport parameters per MCP server id.

Before Tier C each module's ``MCP_SERVERS`` tuple carried the resolver
inputs (``env_var`` / ``config_key`` / ``default_url``) for every server
it used, duplicating the same global constants across modules (the
audit-mcp env var name and default port are identical under ``vr`` and
``malware``). Tier C makes this table the single source of transport
parameters keyed by the stable ``server_id``; the module registries
select which server ids they expose and attach capability tags, but the
env var names, config keys, default endpoints, timeouts, and pool policy
live here.

``audit_mcp`` / ``android_mcp`` are the in-repo HTTP servers; ``rea``
is the external MCP-native reverse-engineering server (see its entry
below). ``persistent_pool`` reuses one httpx client across calls for
android-mcp only, matching its pre-Tier-C module-level connection pool;
the remaining http servers open a fresh client per call, byte-identical
to their old bespoke bridges.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass

from aila.platform.mcp.instance_catalog import TRANSPORT_HTTP, TRANSPORT_STDIO

__all__ = ["ServerSpec", "SERVER_SPECS", "spec_for"]


#: Interpreter used to spawn the in-repo stdio servers. ``sys.executable``
#: is absolute, so the child always runs the same install that started
#: the bridge (a PATH ``python`` may lack the re-analytics extra).
_PY_EXE = sys.executable or "python"


@dataclass(frozen=True)
class ServerSpec:
    """Immutable transport parameters for one MCP server id.

    ``tool_name`` is the agent-facing suffix the generic bridge exposes
    as ``f"{module_id}.{tool_name}"`` so external callers reading
    ``bridge.name`` see the pre-Tier-C value. ``default_timeout`` is the
    fallback per-call HTTP timeout in seconds; a middleware MAY narrow or
    widen it from its own env var.
    ``transport`` selects the wire protocol: ``"http"`` (the legacy
    bridge contract), ``"mcp-http"`` (streamable-HTTP MCP JSON-RPC), or
    ``"stdio"`` (MCP stdio JSON-RPC; ``command`` is the spawn argv).
    """

    server_id: str
    tool_name: str
    env_var: str
    config_key: str
    default_url: str
    default_timeout: float
    persistent_pool: bool
    transport: str = TRANSPORT_HTTP
    command: tuple[str, ...] = ()


SERVER_SPECS: dict[str, ServerSpec] = {
    "audit_mcp": ServerSpec(
        server_id="audit_mcp",
        tool_name="audit_mcp_bridge",
        env_var="AUDIT_MCP_URL",
        config_key="audit_mcp_url",
        default_url="http://127.0.0.1:18822",
        default_timeout=300.0,
        persistent_pool=False,
    ),
    "android_mcp": ServerSpec(
        server_id="android_mcp",
        tool_name="android_mcp_bridge",
        env_var="ANDROID_MCP_URL",
        config_key="android_mcp_url",
        default_url="http://127.0.0.1:18823",
        default_timeout=1800.0,
        persistent_pool=True,
    ),
    # REA (morluto/rea, npm ``rea-agents``) -- the first external,
    # MCP-native server. Serves the core binary reverse-engineering
    # surface (decompile, disassemble, xrefs, call graphs, segments,
    # strings, byte/entropy reads) across Ghidra/IDA/Hopper/Kuna
    # providers.
    #
    # Default transport is stdio: REA's documented client model is one
    # dedicated stdio process per client, and its HTTP listener serves
    # ONE client with ONE shared active target (the newest initialize
    # evicts the previous session). A per-process stdio child therefore
    # gives every AILA process (backend, each worker) its own REA without
    # cross-process session or target thrash. The spawn argv is
    # ``REA_MCP_COMMAND`` (shlex-split) when set, else ``rea mcp`` from
    # PATH. Setting ``REA_MCP_URL`` / ``rea_mcp_url`` to an http(s) URL,
    # or approving a catalog row with transport ``mcp-http``, points the
    # bridge at a remote ``rea mcp --http`` instance instead.
    #
    # The 900 s timeout covers the cold-Ghidra first query per binary
    # (observed 400-600 s on a constrained host); repeats take ms.
    "rea": ServerSpec(
        server_id="rea",
        tool_name="rea_bridge",
        env_var="REA_MCP_URL",
        config_key="rea_mcp_url",
        default_url="stdio://rea",
        default_timeout=900.0,
        persistent_pool=False,
        transport=TRANSPORT_STDIO,
        command=("rea", "mcp"),
    ),
    # re_analytics -- AILA-owned native MCP server (this repo,
    # ``python -m aila.platform.re_analytics``). Preserves the
    # ida-headless tool surface REA lacks (capa_scan, classification,
    # anti-analysis, crypto/dataflow analytics, diffing, session
    # mutations) with the same tool/arg names, taking ``target_path``
    # (absolute local path) instead of ida's binary handle.
    #
    # stdio transport like REA: one child process per AILA process, no
    # external service to operate. The spawn argv uses ``sys.executable``
    # so the child always runs this repo's interpreter (a bare
    # ``python`` could resolve to a different install without the
    # re-analytics extra). GenericMiddleware is used (no _MIDDLEWARE_REF
    # entry): the bridge forwards ``target_path`` as a real argument and
    # the server opens the binary from disk itself.
    #
    # The 900 s timeout matches the REA spec: cold capa rule loading plus
    # a first extractor build on a large binary is the long pole; cached
    # repeat calls return in seconds.
    "re_analytics": ServerSpec(
        server_id="re_analytics",
        tool_name="re_analytics_bridge",
        env_var="REA_ANALYTICS_MCP_URL",
        config_key="re_analytics_mcp_url",
        default_url="stdio://re_analytics",
        default_timeout=900.0,
        persistent_pool=False,
        transport=TRANSPORT_STDIO,
        command=(_PY_EXE, "-m", "aila.platform.re_analytics"),
    ),
}


def spec_for(server_id: str) -> ServerSpec:
    """Return the :class:`ServerSpec` for ``server_id``.

    Raises :class:`KeyError` with the known ids when the server is
    unregistered so a typo surfaces at construction rather than as a
    silent dispatch-to-nowhere.
    """
    try:
        return SERVER_SPECS[server_id]
    except KeyError as exc:
        known = ", ".join(sorted(SERVER_SPECS))
        raise KeyError(
            f"unknown MCP server id {server_id!r}; known: {known}",
        ) from exc
