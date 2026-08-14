"""RFC-11 Tier C -- the one generic MCP bridge tool.

Replaces the three bespoke ``Tool`` subclasses (``IDABridgeTool``,
``AuditMcpBridgeTool``, ``AndroidMcpBridgeTool``). One
:class:`McpBridgeTool` owns an :class:`McpClient` transport and delegates
every server-specific decision to a bound :class:`McpMiddleware`.
Construct one via :func:`aila.platform.mcp.factory.make_bridge`.

The public surface matches the pre-Tier-C bridges so the callers that
read ``.name`` / ``.module_id`` or await ``.forward`` / ``.list_tool_specs``
/ ``._resolve_base_url`` / ``.base_url`` / ``.invalidate_base_url`` do not
change. The dispatch router (RFC-07 reroute) pins a specific catalog
instance by assigning ``bridge._resolved``; the proxy property threads
that write onto the underlying client so the next call targets the
router's chosen endpoint.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.exc import SQLAlchemyError

from aila.platform.mcp.client import McpClient, ResolvedInstance, resolve_instance
from aila.platform.mcp.middleware import McpMiddleware
from aila.platform.mcp.tool_hash import (
    ToolDescriptionMismatchError,
    verify_or_record_tool_specs,
)
from aila.platform.tools import Tool
from aila.storage.registry import ConfigRegistry

__all__ = ["McpBridgeTool"]

_log = logging.getLogger(__name__)


async def _resolve_hash_strict_flag() -> bool:
    """Read ``platform.mcp_tool_hash_strict`` from :class:`ConfigRegistry`.

    Returns ``False`` on any registry failure so a broken DB never
    silently upgrades the pin from warn to refuse -- the operator
    opts into strict mode explicitly by setting the key.
    """
    try:
        raw = await ConfigRegistry().get("platform", "mcp_tool_hash_strict")
    except (OSError, RuntimeError, ValueError, TypeError, SQLAlchemyError):
        return False
    if raw is None:
        return False
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.strip().lower() in ("1", "true", "yes", "on")
    return bool(raw)


class McpBridgeTool(Tool):
    """Generic MCP bridge: transport via :class:`McpClient`, behaviour via middleware.

    ``forward`` copies nothing extra -- Python's ``**kwargs`` already
    hands the middleware a fresh dict it may mutate (pop flags, normalise
    aliases). ``list_tool_specs`` delegates to the middleware so android's
    per-tool schema fetch and audit's virtual-tool spec injection are
    preserved.
    """

    def __init__(
        self,
        *,
        middleware: McpMiddleware,
        module_id: str,
        recorder: Any | None = None,
    ) -> None:
        self._mw = middleware
        self.module_id = module_id
        self.server_id = middleware.server_id
        self.name = f"{module_id}.{middleware.tool_name}"
        self._client = McpClient(
            server_id=middleware.server_id,
            resolver=lambda: resolve_instance(
                module_scope=module_id,
                server_name=middleware.server_id,
                env_var=middleware.env_var,
                config_key=middleware.config_key,
                default_url=middleware.default_url,
            ),
            timeout=middleware.default_timeout,
            recorder=recorder,
            persistent_pool=middleware.persistent_pool,
        )

    @property
    def _resolved(self) -> ResolvedInstance | None:
        """Proxy the client's cached resolution for the RFC-07 reroute.

        The dispatch router assigns ``bridge._resolved = instance`` to
        pin the bridge at a router-chosen catalog instance before calling
        ``forward``. Threading it onto the client keeps that mechanism
        working unchanged after the bespoke bridges collapse onto the
        generic tool.
        """
        return self._client._resolved

    @_resolved.setter
    def _resolved(self, value: ResolvedInstance | None) -> None:
        self._client._resolved = value

    async def forward(self, action: str | None = None, **kwargs: Any) -> dict[str, Any]:
        """Dispatch one agent tool call through the server's middleware."""
        return await self._mw.forward(self._client, action, kwargs)

    async def list_tool_specs(self) -> list[dict[str, Any]]:
        """Return the server's compacted tool catalogue via the middleware.

        #159 part 1: every projected catalog is hashed and verified via
        :func:`aila.platform.mcp.tool_hash.verify_or_record_tool_specs`
        so a description swap between two ``tools/list`` calls surfaces
        in the platform log. The strict flag is read from
        ``platform.mcp_tool_hash_strict``; when set, a mismatch raises
        :class:`ToolDescriptionMismatchError` and the bridge refuses
        to return the poisoned catalog. In the default (warn) mode the
        rotated hash is accepted and the caller sees the new specs.
        """
        specs = await self._mw.list_tool_specs(self._client)
        strict = await _resolve_hash_strict_flag()
        try:
            verify_or_record_tool_specs(
                self.module_id, self.server_id, specs, strict=strict,
            )
        except ToolDescriptionMismatchError:
            # Refuse the catalog under strict mode so a poisoned tool
            # description never lands in the agent prompt. The caller
            # (prompt builder, tool_executor.registered_tools) sees an
            # exception rather than a mutated tool set.
            _log.error(
                "mcp bridge %s/%s: STRICT tool_hash mismatch -- refusing "
                "to return catalog",
                self.module_id, self.server_id,
            )
            raise
        return specs

    async def _resolve_base_url(self) -> str:
        """Resolve the current base URL (env > config > catalog > default)."""
        return await self._client.base_url()

    async def base_url(self) -> str:
        """Public alias for :meth:`_resolve_base_url` (auto-steering path)."""
        return await self._client.base_url()

    async def health(self) -> dict[str, Any]:
        """Best-effort ``GET /health`` via the shared McpClient transport.

        Returns the server's health payload, or the uniform
        ``{"status": "error", "error": "Unreachable: ..."}`` envelope
        when the server cannot be reached. The HTTP call lives in the
        platform transport, so a module can probe reachability without
        constructing its own HTTP client.
        """
        return await self._client.health()

    def invalidate_base_url(self) -> None:
        """Drop the cached resolution so the next call re-resolves."""
        self._client.invalidate_base_url()

    async def aclose(self) -> None:
        """Close the underlying transport pool if one was opened."""
        await self._client.aclose()
