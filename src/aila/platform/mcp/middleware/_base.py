"""RFC-11 Tier C -- the middleware contract every MCP server plugin implements.

A :class:`McpMiddleware` is the server-specific half of a bridge. The
generic :class:`aila.platform.mcp.bridge_tool.McpBridgeTool` owns the
:class:`aila.platform.mcp.client.McpClient` transport and calls the
middleware for every dispatch. A plugin ports the old bespoke bridge's
``forward()`` / ``list_tool_specs()`` bodies verbatim, swapping the raw
``httpx`` POST for the transport primitives the client exposes:

* ``await client.post(action, payload, *, timeout=None, ctx=None)`` --
  raw POST + JSON parse + status normalisation, NO audit-log row. Used
  for the primary dispatch (pass ``ctx`` so the one recorded row tracks
  the final outcome) and for every secondary call that must not add a
  row (pending-poll retries, prewarm fan-out, read_function fallbacks).
* ``async with client.recorder_context(action) as ctx:`` -- opens the
  single audit-log envelope for one ``forward`` call. The middleware
  annotates ``ctx["status"]`` / ``ctx["http_status"]`` /
  ``ctx["error_excerpt"]`` (``post(..., ctx=ctx)`` does this for the
  primary call; a poll loop overwrites ``ctx["status"]`` with the final
  resolution so the recorded status matches pre-Tier-C behaviour: one
  row per call, final status wins).
* ``await client.base_url()`` / ``client.resolve()`` /
  ``client.instance_id()`` -- URL resolution (env > config > catalog >
  default), cached per client and re-resolvable via
  ``client.invalidate_base_url()``. The dispatch router pins a specific
  catalog instance by writing ``client._resolved`` before ``forward``.
* ``await client.list_tool_specs()`` -- default ``GET /tools`` fetch +
  ``compact_tool_spec`` projection. Plugins that need per-tool schema
  hops (android-mcp) or a virtual-tool spec injection (audit-mcp
  ``read_lines``) override :meth:`list_tool_specs` and call this as the
  base fetch.

Behaviour-preservation rule: a plugin MUST reproduce its bridge's
observable behaviour byte-for-byte -- same URL, same payload after
transforms, same return-dict shape for every success and error branch.
The empty/default path (no transform applies) MUST be identical to a
bare ``client.call_tool``.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from aila.platform.mcp.client import McpClient

__all__ = ["McpMiddleware"]


@runtime_checkable
class McpMiddleware(Protocol):
    """Server-specific behaviour layered over the generic transport.

    Attributes are read once by :class:`McpBridgeTool` at construction to
    wire the client's resolver + timeout + pool policy:

    * ``server_id`` -- the stable server token (``"ida_headless"``,
      ``"audit_mcp"``, ``"android_mcp"``). Matches the catalog ``name``
      column and the ``spec['id']`` in the module's static
      ``MCP_SERVERS`` tuple. This is the resolver's ``server_name``.
    * ``tool_name`` -- the agent-facing tool suffix (``"ida_bridge"``,
      ``"audit_mcp_bridge"``, ``"android_mcp_bridge"``). The generic
      tool's ``name`` is ``f"{module_id}.{tool_name}"`` so external
      callers that read ``bridge.name`` see the pre-Tier-C value.
    * ``env_var`` / ``config_key`` / ``default_url`` -- the four-tier
      resolver inputs (``env > config > catalog > default``).
    * ``default_timeout`` -- per-call HTTP timeout in seconds.
    * ``persistent_pool`` -- when ``True`` the client reuses one
      ``httpx.AsyncClient`` across calls (android-mcp's module-level
      pool). When ``False`` (ida/audit) each call opens and closes its
      own client, byte-identical to the pre-Tier-C bridges.
    """

    server_id: str
    tool_name: str
    env_var: str
    config_key: str
    default_url: str
    default_timeout: float
    persistent_pool: bool

    async def forward(
        self,
        client: McpClient,
        action: str | None,
        kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        """Run one server-specific dispatch and return the result dict.

        This is the old bridge ``forward(action, **kwargs)`` body with
        ``client`` as the transport. ``kwargs`` is a fresh mutable dict
        the middleware owns (the generic tool copies the agent's kwargs
        before handing them over). A ``None``/empty ``action`` lists the
        server's tools; a virtual action (audit ``read_lines``, ida
        ``upload``) is handled entirely middleware-side.
        """
        ...

    async def list_tool_specs(self, client: McpClient) -> list[dict[str, Any]]:
        """Fetch + project + augment the server's tool catalogue.

        Default plugins delegate to ``await client.list_tool_specs()``.
        android-mcp overrides to fan out per-tool schema fetches;
        audit-mcp overrides to inject the virtual ``read_lines`` spec.
        The returned list is a sequence of ``compact_tool_spec`` outputs.
        """
        ...
