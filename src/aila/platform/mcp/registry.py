"""McpRegistryServiceBase -- operator-facing MCP servers health + config surface.

AILA is orchestration only (D-33). Every analytical action is delegated
to an MCP server running on a workstation. This service surfaces:

* which MCP servers the module knows about (audit-mcp, ida-headless, ...)
* the URL each one currently resolves to (env -> ConfigRegistry -> catalog
  -> default)
* a live HTTP health probe (reachable / unreachable + latency)
* the tool count and tool names each server advertises
* a write path so the operator can retarget a server at a different
  workstation without touching env vars

Module-agnostic: a concrete subclass binds ``_module_id`` (the
ConfigRegistry namespace) and ``_servers`` (the module's static catalog
of MCP server specs). The platform base owns the resolve / probe /
update logic and never names a module.

RFC-11 step 1 -- the resolver consults an optional DB-backed catalog
(:class:`aila.platform.mcp.instance_catalog.McpInstanceCatalog`) after
env and ConfigRegistry but before falling back to the static
``default_url``. When no catalog row exists for a given
``(module_scope, name)``, resolution is byte-identical to the pre-catalog
behaviour so the live dispatch path is unchanged until the migration
seeds rows. A disabled catalog row (``enabled=False``) is treated as
"no catalog override" -- the operator temporarily disables the catalog
entry and the code-embedded default resumes serving.

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
from collections.abc import Iterable
from typing import Any, ClassVar

import httpx

from aila.platform.contracts import utc_now
from aila.platform.mcp.client import (
    InstancePool,
    ResolvedInstance,
    resolve_instance,
)
from aila.platform.mcp.instance_catalog import (
    McpInstanceCatalog,
    decode_capability_tags,
)
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

    def __init__(
        self,
        registry: ConfigRegistry | None = None,
        catalog: McpInstanceCatalog | None = None,
    ) -> None:
        self._registry = registry or ConfigRegistry()
        # ``catalog`` is optional so tests and pre-migration deployments
        # keep working with the static ``_servers`` tuple only. The
        # default construction is cheap (no DB access at __init__).
        self._catalog = catalog or McpInstanceCatalog()

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

    async def resolve_by_capability(
        self,
        capability: str,
        *,
        include_disabled: bool = False,
    ) -> list[ResolvedInstance]:
        """Return every catalog row for this scope advertising ``capability``.

        RFC-11 step 3 -- capability-based module binding. A module
        declares the capability tags it needs (``["disassembly",
        "decompile"]``); the platform returns every enabled instance
        whose ``capability_tags`` column contains the requested tag.
        Disabled rows are skipped by default so the operator's
        temporary disable flips a member out of the pool without a
        deletion.

        Empty catalog or no matching row returns an empty list; the
        caller decides whether to fall back to the code-embedded
        static server catalog (which is what the pre-RFC-11 modules
        did) or surface the outage. The empty-catalog case therefore
        stays byte-identical to the pre-RFC-11 behaviour.
        """
        rows = await self._catalog.list_instances(
            module_scope=self._module_id, include_disabled=include_disabled,
        )
        out: list[ResolvedInstance] = []
        for row in rows:
            tags = decode_capability_tags(row.capability_tags)
            if capability not in tags:
                continue
            endpoint = (row.endpoint or "").strip().rstrip("/")
            if not endpoint:
                continue
            out.append(
                ResolvedInstance(
                    url=endpoint,
                    source="catalog",
                    instance_id=row.id,
                    capability_tags=tuple(tags),
                    name=row.name,
                    module_scope=row.module_scope,
                ),
            )
        return out

    async def bind(
        self, capabilities: Iterable[str],
    ) -> dict[str, list[ResolvedInstance]]:
        """Return ``{capability: [instances...]}`` for every requested tag.

        RFC-11 step 4 -- one call per turn per module. A capability
        with no matching row lands as an empty list so the caller can
        distinguish "catalog empty for this capability" from "catalog
        has rows but the requested tag is absent".
        """
        return {
            cap: await self.resolve_by_capability(cap) for cap in capabilities
        }

    async def pool_for_capability(self, capability: str) -> InstancePool:
        """Return an :class:`InstancePool` over every enabled instance.

        Two catalog rows of one capability share load: ``pool.next()``
        alternates picks across the members via a monotonic counter
        under an async lock. The caller keeps the pool for the
        lifetime of the turn so successive calls interleave rather
        than repeatedly hammering the same member.
        """
        members = await self.resolve_by_capability(capability)
        return InstancePool(members)

    async def _resolve_instance(self, spec: dict[str, str]) -> ResolvedInstance:
        """Return the full :class:`ResolvedInstance` for a static spec row.

        Byte-identical to :meth:`_resolved_url` but carries the
        ``instance_id`` and ``capability_tags`` when the catalog tier
        wins so the caller can plumb provenance into the audit log.
        """
        return await resolve_instance(
            module_scope=self._module_id,
            server_name=spec["id"],
            env_var=spec["env_var"],
            config_key=spec["config_key"],
            default_url=spec["default_url"],
            catalog=self._catalog,
            registry=self._registry,
        )

    async def _resolved_url(self, spec: dict[str, str]) -> tuple[str, str]:
        """Return (url, source). source in {'env', 'config', 'catalog', 'default'}.

        Resolution order (highest priority first):

        1. ``env`` -- process env var named by ``spec['env_var']``.
           Deployment-level override for local dev / one-off testing.
        2. ``config`` -- ConfigRegistry entry keyed by
           ``spec['config_key']`` under the module namespace. Written
           by :meth:`update_base_url` from the operator UI.
        3. ``catalog`` -- DB row keyed by ``(module_scope=self._module_id,
           name=spec['id'])`` in ``mcp_server_instances``, iff the row
           exists and ``enabled`` is true. Populated by the RFC-11
           migration and by the ``/platform/mcp/instances`` admin
           router. This tier is skipped entirely when the catalog is
           empty for the scope, so pre-migration behaviour is
           byte-identical.
        4. ``default`` -- code-embedded ``spec['default_url']`` from
           the module's static ``MCP_SERVERS`` tuple.
        """
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
        catalog_value = await self._catalog_endpoint(spec["id"])
        if catalog_value is not None:
            return catalog_value.rstrip("/"), "catalog"
        return spec["default_url"].rstrip("/"), "default"

    async def _catalog_endpoint(self, server_id: str) -> str | None:
        """Look up an enabled catalog row's endpoint for this scope.

        Returns ``None`` on a miss (row absent, row disabled, or a DB
        error) so ``_resolved_url`` falls through to the static default
        without a hard failure. A DB error is logged at WARNING and
        swallowed -- the resolver never breaks a live probe on a
        catalog outage; the operator keeps the code-embedded default as
        a safety net.
        """
        try:
            row = await self._catalog.get_by_scope_and_name(
                self._module_id, server_id,
            )
        except (RuntimeError, OSError) as exc:
            _log.warning(
                "mcp instance catalog lookup failed for %s/%s: %s",
                self._module_id, server_id, exc,
            )
            return None
        if row is None or not row.enabled:
            return None
        endpoint = row.endpoint.strip() if row.endpoint else ""
        if not endpoint:
            return None
        return endpoint

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
