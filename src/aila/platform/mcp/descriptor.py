"""RFC-11 -- config-declared MCP server descriptor.

An :class:`McpServerDescriptor` is the module-declared, capability-first
description of ONE MCP server the module is willing to reach through the
generic :class:`aila.platform.mcp.client.McpClient`. A descriptor carries
everything the platform needs to open a connection without knowing a
module by name (per RFC-05):

* ``name`` -- the stable server token (``"audit_mcp"``, ``"android_mcp"``,
  ``"ida_headless"``, ...) that matches the corresponding
  :class:`aila.platform.mcp.instance_catalog.McpServerInstance.name`
  column so the four-tier resolver can find the operator's catalog row.
* ``capability_tags`` -- what the server ADVERTISES it can do (``(
  "source_audit", "graph")``). Modules resolve MCP servers by
  capability, never by module name; the tag is the join key.
* ``transport`` -- ``"http"`` or ``"stdio"``. All three current bridges
  are HTTP; the stdio branch is reserved for future MCP-SDK stdio
  processes and does not run today.
* ``env_var`` / ``config_key`` / ``default_url`` -- the four-tier
  resolver inputs (``env`` > ``config`` > ``catalog`` > ``default``).
* ``description`` -- optional operator-facing prose surfaced in the
  registry probe UI.
* ``timeout_s`` -- optional per-descriptor network ceiling passed to
  :class:`~aila.platform.mcp.client.McpClient`; defaults to 60s.

A descriptor is a plain dataclass, frozen so a caller can safely thread
the same instance through a fan-out of coroutines without racing on
mutable state. The current module-side ``MCP_SERVERS`` tuple + the
sibling ``SERVER_CAPABILITY_DEFAULTS`` map lift into descriptors via
:func:`descriptors_from_static_specs` so this file introduces the
capability-first surface without asking every module to rewrite its
existing declaration site.

The descriptor is deliberately narrower than
:class:`aila.platform.mcp.instance_catalog.McpServerInstance`:
descriptors carry the STATIC contract declared by the module (name,
capabilities, resolver inputs), while :class:`McpServerInstance` rows
carry the OPERATOR overrides (concrete endpoint, enabled/disabled,
catalog id) that the four-tier resolver layers on top. Keeping the two
types separate means the module declaration surface does not depend on
the DB schema and every test can build descriptors in a single call.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from aila.platform.mcp.instance_catalog import TRANSPORT_HTTP

__all__ = [
    "McpServerDescriptor",
    "descriptors_from_static_specs",
]


@dataclass(frozen=True, slots=True)
class McpServerDescriptor:
    """Config-declared descriptor for one MCP server a module wants to reach.

    Immutable so the same instance can be safely fanned out across
    concurrent coroutines. The four-tier resolver still runs at call
    time, so this descriptor never caches a URL -- an operator PATCH
    against the catalog or the ConfigRegistry key takes effect on the
    next :meth:`aila.platform.mcp.client.McpClient.call_tool` without a
    worker restart.
    """

    name: str
    capability_tags: tuple[str, ...]
    env_var: str
    config_key: str
    default_url: str
    transport: str = TRANSPORT_HTTP
    description: str = ""
    timeout_s: float = 60.0

    # Free-form key/value bag reserved for later increments (stdio
    # spawn args, auth-ref pointers, per-descriptor rate limits). Kept
    # empty today so no caller depends on its shape; declared here so
    # the seam is visible in the type without a schema break when the
    # RFC-11 later increments (pooling composition, RFC-07 reroute
    # hooks, bridge deletion) start populating it.
    extras: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        # Validate the surface the caller passed. Frozen dataclass so
        # object.__setattr__ is the only way to normalise fields.
        name = self.name.strip()
        if not name:
            raise ValueError("McpServerDescriptor.name must not be empty")
        env_var = self.env_var.strip()
        if not env_var:
            raise ValueError(
                f"McpServerDescriptor({name!r}).env_var must not be empty",
            )
        config_key = self.config_key.strip()
        if not config_key:
            raise ValueError(
                f"McpServerDescriptor({name!r}).config_key must not be empty",
            )
        default_url = self.default_url.strip().rstrip("/")
        if not default_url:
            raise ValueError(
                f"McpServerDescriptor({name!r}).default_url must not be empty",
            )
        transport = self.transport.strip().lower()
        if transport not in {"http", "stdio"}:
            raise ValueError(
                f"McpServerDescriptor({name!r}).transport must be 'http' or "
                f"'stdio' (got {self.transport!r})",
            )
        tags = tuple(str(t).strip() for t in self.capability_tags)
        if not tags or any(not t for t in tags):
            raise ValueError(
                f"McpServerDescriptor({name!r}).capability_tags must be a "
                f"non-empty tuple of non-empty strings",
            )
        if self.timeout_s <= 0:
            raise ValueError(
                f"McpServerDescriptor({name!r}).timeout_s must be positive",
            )
        # Normalise the normalised values back onto the frozen instance.
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "env_var", env_var)
        object.__setattr__(self, "config_key", config_key)
        object.__setattr__(self, "default_url", default_url)
        object.__setattr__(self, "transport", transport)
        object.__setattr__(self, "capability_tags", tags)

    def advertises(self, capability: str) -> bool:
        """Return ``True`` iff the descriptor's tag set includes ``capability``.

        Used by :meth:`aila.platform.mcp.capability_registry.McpCapabilityRegistry
        .descriptors_for_capability` so the match rule lives on the
        descriptor and later increments (case-insensitive match,
        wildcard tags, glob tags) change one place.
        """
        return capability in self.capability_tags


def descriptors_from_static_specs(
    specs: Iterable[Mapping[str, str]],
    capability_defaults: Mapping[str, Iterable[str]],
) -> tuple[McpServerDescriptor, ...]:
    """Adapt the existing ``MCP_SERVERS`` tuple into descriptors.

    Every module already ships an ``MCP_SERVERS`` tuple of dicts (the
    module-declared server catalog) plus a
    ``SERVER_CAPABILITY_DEFAULTS`` map from server id to capability
    tags (the module-declared advertised capabilities). This adapter
    walks both, produces one :class:`McpServerDescriptor` per row, and
    lets modules keep their existing declaration site verbatim while
    they publish descriptors to the platform capability registry.

    A spec whose ``id`` is missing from ``capability_defaults`` (or
    whose defaults list is empty) is skipped with no error so a module
    can incrementally opt servers into capability-first resolution.
    The task's Step-0 proof only requires ONE server to publish
    descriptors; the rest continue reaching the bespoke bridges and
    the pre-RFC-11 resolver path unchanged.
    """
    out: list[McpServerDescriptor] = []
    for spec in specs:
        server_id = str(spec.get("id") or "").strip()
        if not server_id:
            continue
        tags_iter = capability_defaults.get(server_id)
        if tags_iter is None:
            continue
        tags = tuple(str(t).strip() for t in tags_iter if str(t).strip())
        if not tags:
            continue
        env_var = str(spec.get("env_var") or "").strip()
        config_key = str(spec.get("config_key") or "").strip()
        default_url = str(spec.get("default_url") or "").strip()
        if not (env_var and config_key and default_url):
            continue
        out.append(
            McpServerDescriptor(
                name=server_id,
                capability_tags=tags,
                env_var=env_var,
                config_key=config_key,
                default_url=default_url,
                description=str(spec.get("description") or "").strip(),
            ),
        )
    return tuple(out)
