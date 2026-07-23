"""McpRegistryServiceBase -- operator-facing MCP servers health + config surface.

AILA is orchestration only (D-33). Every analytical action is delegated
to an MCP server running on a workstation. This service surfaces:

* which MCP servers the module knows about (audit-mcp, ida-headless, ...)
* the URL each one currently resolves to (env -> ConfigRegistry -> default)
* a live HTTP health probe (reachable / unreachable + latency)
* the tool count and tool names each server advertises
* a write path so the operator can retarget a server at a different
  workstation without touching env vars

Module-agnostic: a concrete subclass binds ``_module_id`` (the
ConfigRegistry namespace) and ``_servers`` (the module's static catalog
of MCP server specs). The platform base owns the resolve / probe /
update logic and never names a module.

The result projection deliberately uses operator vocabulary -- no
``mcp_handles_json``, no internal task ids. Just ``id``, ``name``,
``description``, ``base_url``, ``status``, ``latency_ms``,
``tool_count``, ``tools``, ``last_probed_at``, and ``error`` when
unreachable.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, ClassVar

import httpx

from aila.platform.contracts import utc_now
from aila.storage.registry import ConfigRegistry

__all__ = ["McpRegistryServiceBase"]

_log = logging.getLogger(__name__)

_PROBE_TIMEOUT_SECONDS = 3.0


class McpRegistryServiceBase:
    """Resolve current URL + probe health for each registered MCP.

    Concrete subclass binds:

    * ``_module_id`` -- ConfigRegistry namespace (also used in log lines).
    * ``_servers`` -- the module's static MCP server catalog.
    """

    _module_id: ClassVar[str]
    _servers: ClassVar[tuple[dict[str, str], ...]]

    def __init__(self, registry: ConfigRegistry | None = None) -> None:
        self._registry = registry or ConfigRegistry()

    async def probe_all(self) -> list[dict[str, Any]]:
        """Concurrently probe every registered MCP and return projections."""
        return list(await asyncio.gather(*(self._probe(s) for s in self._servers)))

    async def update_base_url(self, server_id: str, base_url: str) -> dict[str, Any] | None:
        """Persist ``base_url`` to ConfigRegistry and re-probe.

        Returns the fresh projection, or None if ``server_id`` is unknown.
        Persists via the platform ConfigRegistry which is env->DB->default
        layered, so this overrides DB only -- env still wins on next read.
        """
        spec = self._spec(server_id)
        if spec is None:
            return None
        await self._registry.set(self._module_id, spec["config_key"], base_url.rstrip("/"))
        return await self._probe(spec)

    # --- internals -----------------------------------------------------------

    def _spec(self, server_id: str) -> dict[str, str] | None:
        return next((s for s in self._servers if s["id"] == server_id), None)

    async def _resolved_url(self, spec: dict[str, str]) -> tuple[str, str]:
        """Return (url, source). source in {'env', 'config', 'default'}."""
        env_value = os.environ.get(spec["env_var"])
        if env_value:
            return env_value.rstrip("/"), "env"
        try:
            cfg_value = await self._registry.get(self._module_id, spec["config_key"])
        except (ValueError, RuntimeError) as exc:
            _log.warning(
                "ConfigRegistry get failed for %s/%s: %s",
                self._module_id, spec["config_key"], exc,
            )
            cfg_value = None
        if isinstance(cfg_value, str) and cfg_value.strip():
            return cfg_value.rstrip("/"), "config"
        return spec["default_url"].rstrip("/"), "default"

    async def _probe(self, spec: dict[str, str]) -> dict[str, Any]:
        url, url_source = await self._resolved_url(spec)
        probed_at = utc_now()
        result: dict[str, Any] = {
            "id": spec["id"],
            "name": spec["name"],
            "description": spec["description"],
            "base_url": url,
            "base_url_source": url_source,
            "default_url": spec["default_url"],
            "env_var": spec["env_var"],
            "config_key": spec["config_key"],
            "status": "unreachable",
            "latency_ms": None,
            "tool_count": 0,
            "tools": [],
            "last_probed_at": probed_at.isoformat(),
            "error": None,
        }

        start = asyncio.get_event_loop().time()
        try:
            async with httpx.AsyncClient(timeout=_PROBE_TIMEOUT_SECONDS) as client:
                # Both audit-mcp and ida-headless expose /openapi.json.
                resp = await client.get(f"{url}/openapi.json")
                resp.raise_for_status()
                spec_doc = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"
            return result
        latency_ms = int((asyncio.get_event_loop().time() - start) * 1000)

        tools = sorted(
            path[len("/tools/"):]
            for path in spec_doc.get("paths", {})
            if isinstance(path, str) and path.startswith("/tools/")
        )
        result["status"] = "reachable"
        result["latency_ms"] = latency_ms
        result["tool_count"] = len(tools)
        result["tools"] = tools
        return result
