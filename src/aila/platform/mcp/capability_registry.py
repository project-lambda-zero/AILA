"""RFC-11 -- module-declared, capability-first MCP registry.

The platform owns a single :class:`McpCapabilityRegistry` process
singleton. Modules declare their :class:`McpServerDescriptor` set
against a scope (the module id) at ``create_module()`` time; every
caller then asks the registry for descriptors BY CAPABILITY, never by
module name. The registry never learns which modules exist -- it
accepts whatever scope the caller passes -- so the RFC-05 boundary
rule holds (platform must not name a module).

Two callers today:

* Modules -- ``default_capability_registry().declare_all(module_id,
  descriptors)`` at ``create_module()`` time. Idempotent within a
  process; re-registration under the same ``(module_scope, name)``
  supersedes the previous descriptor so a module can rebuild its
  descriptor set without a worker restart.
* The Step-0 proof callsite -- opens an
  :class:`~aila.platform.mcp.client.McpClient` from a descriptor via
  :meth:`McpCapabilityRegistry.open_client`. The client goes through
  the shared four-tier resolver plus the DB-backed catalog so the
  wire request that lands on the MCP server is byte-identical to what
  the bespoke bridge classes emit (see the parity test in
  ``tests/test_rfc11_capability_registry.py``).

Later increments (deliberately unimplemented today, seams named so a
reviewer can trace where they will land):

* Pooling composition -- ``open_pool_for_capability(capability)``
  would return a list of pre-wired :class:`McpClient`s built from
  every enabled catalog row advertising the requested tag, matching
  :meth:`aila.platform.mcp.registry.McpRegistryServiceBase.pool_for_capability`
  (which already produces the :class:`~aila.platform.mcp.client.InstancePool`
  of :class:`~aila.platform.mcp.client.ResolvedInstance`\\ s).
* RFC-07 reroute -- an unhealthy instance drops from the pool by
  flipping ``McpServerInstance.enabled`` off; the resolver already
  treats a disabled row as absent. The reroute path itself lives on
  the health service, not here.
* Bridge deletion -- once :class:`McpClient` covers the specialised
  transport tricks each bespoke bridge still applies (schema
  validation, APK-path resolver, IDA rewrites), the bespoke classes
  under ``platform/mcp/bridges/`` retire. Today they remain the
  operator-critical dispatch path for audit-mcp / ida-headless /
  android-mcp.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING

from aila.platform.mcp.client import (
    McpClient,
    ResolvedInstance,
    resolve_instance,
)
from aila.platform.mcp.descriptor import McpServerDescriptor

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable
    from contextlib import AbstractAsyncContextManager
    from typing import Any

    from aila.platform.mcp.instance_catalog import McpInstanceCatalog
    from aila.storage.registry import ConfigRegistry

__all__ = [
    "McpCapabilityRegistry",
    "ModuleDescriptorDeclaration",
    "default_capability_registry",
    "reset_default_capability_registry",
]


@dataclass(frozen=True, slots=True)
class ModuleDescriptorDeclaration:
    """One module's declaration of ONE descriptor.

    ``module_scope`` is the module id namespace (``"vr"``, ``"malware"``,
    ...) used by the resolver's ConfigRegistry lookup and the catalog's
    natural key. ``descriptor`` is the immutable configured contract.

    The declaration record is frozen so registry snapshots can be
    handed to concurrent consumers without a defensive copy.
    """

    module_scope: str
    descriptor: McpServerDescriptor


class McpCapabilityRegistry:
    """Process-scoped, module-declared MCP descriptor registry.

    Thread-safe: declarations happen at startup and are read from
    request handlers on the event loop, but the SDK does not
    guarantee both callers share the same thread. The lock covers
    mutation and snapshotting only; the resolver + client dispatch
    lives outside the lock.

    Keyed on ``(module_scope, name)`` -- the same server name may
    appear under multiple scopes (``vr.audit_mcp`` and
    ``malware.audit_mcp`` today) because each module's ConfigRegistry
    namespace and its catalog rows are scoped to the module id.
    """

    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], ModuleDescriptorDeclaration] = {}
        self._lock = threading.Lock()

    def declare(
        self,
        module_scope: str,
        descriptor: McpServerDescriptor,
    ) -> ModuleDescriptorDeclaration:
        """Register ONE descriptor under ``module_scope``.

        Idempotent under the natural key ``(module_scope,
        descriptor.name)`` -- a second call with the same key
        supersedes the earlier record so a module can rebuild its
        descriptor set (tests, hot-reload) without duplicating rows.
        Returns the stored declaration so callers can hand it to a
        follow-up :meth:`open_client` call in the same turn.
        """
        scope = module_scope.strip()
        if not scope:
            raise ValueError(
                "McpCapabilityRegistry.declare: module_scope must not be empty",
            )
        record = ModuleDescriptorDeclaration(
            module_scope=scope, descriptor=descriptor,
        )
        with self._lock:
            self._by_key[(scope, descriptor.name)] = record
        return record

    def declare_all(
        self,
        module_scope: str,
        descriptors: Iterable[McpServerDescriptor],
    ) -> tuple[ModuleDescriptorDeclaration, ...]:
        """Register every descriptor in one call.

        Convenience for the ``create_module()`` wiring where a module
        publishes its full descriptor set at startup. Preserves input
        order in the returned tuple so a caller can iterate the
        declarations back in declaration order. Rejects an empty
        descriptor iterable with a hard ``ValueError`` so a module
        wiring bug (bad import, empty tuple) surfaces at startup
        rather than as a silent capability-lookup miss later.
        """
        recorded: list[ModuleDescriptorDeclaration] = []
        for descriptor in descriptors:
            recorded.append(self.declare(module_scope, descriptor))
        if not recorded:
            raise ValueError(
                f"McpCapabilityRegistry.declare_all({module_scope!r}): "
                f"the descriptor iterable is empty; either omit the call "
                f"or publish at least one descriptor",
            )
        return tuple(recorded)

    def declarations(
        self, *, module_scope: str | None = None,
    ) -> tuple[ModuleDescriptorDeclaration, ...]:
        """Snapshot every declaration, optionally filtered to one scope.

        Returned tuple is stable across the caller's iteration even if
        another thread mutates the registry mid-loop.
        """
        with self._lock:
            values = tuple(self._by_key.values())
        if module_scope is None:
            return values
        scope = module_scope.strip()
        return tuple(d for d in values if d.module_scope == scope)

    def descriptors_for_capability(
        self,
        capability: str,
        *,
        module_scope: str | None = None,
    ) -> tuple[ModuleDescriptorDeclaration, ...]:
        """Return every declared descriptor that advertises ``capability``.

        Optional ``module_scope`` narrows the search to one module's
        declarations; omit it to fan out across every module that
        published this capability. Matching lives on the descriptor
        (see :meth:`McpServerDescriptor.advertises`), so later
        increments (case-insensitive match, wildcard tags) change one
        place.
        """
        cap = capability.strip()
        if not cap:
            return ()
        found = [
            d for d in self.declarations(module_scope=module_scope)
            if d.descriptor.advertises(cap)
        ]
        return tuple(found)

    def open_client(
        self,
        declaration: ModuleDescriptorDeclaration,
        *,
        recorder: (
            Callable[..., AbstractAsyncContextManager[dict[str, Any]]] | None
        ) = None,
        catalog: McpInstanceCatalog | None = None,
        registry: ConfigRegistry | None = None,
    ) -> McpClient:
        """Return an :class:`McpClient` pre-wired to reach ``declaration``.

        The client's ``resolver`` runs
        :func:`aila.platform.mcp.client.resolve_instance` with the
        descriptor's four-tier inputs, so live dispatch stays
        byte-identical to the pre-RFC-11 path -- an operator PATCH on
        the catalog row or the module's ConfigRegistry key takes
        effect on the next :meth:`~aila.platform.mcp.client.McpClient.call_tool`
        without a worker restart.

        Callers pass their own ``recorder`` when they want per-call
        audit logging to land in a module-specific
        :class:`~aila.platform.contracts.mcp_call_log_base.McpCallLogRecordBase`
        table; tests and ad-hoc scripts omit it and the client
        records nothing.
        """
        descriptor = declaration.descriptor
        module_scope = declaration.module_scope

        async def _resolver() -> ResolvedInstance:
            return await resolve_instance(
                module_scope=module_scope,
                server_name=descriptor.name,
                env_var=descriptor.env_var,
                config_key=descriptor.config_key,
                default_url=descriptor.default_url,
                catalog=catalog,
                registry=registry,
            )

        return McpClient(
            server_id=descriptor.name,
            resolver=_resolver,
            timeout=descriptor.timeout_s,
            recorder=recorder,
        )

    def clear(self) -> None:
        """Drop every registration.

        Test-only helper -- production wiring registers once at
        ``create_module()`` time. Exposed so
        :func:`reset_default_capability_registry` and per-test
        fixtures can rebuild without leaking state across tests.
        """
        with self._lock:
            self._by_key.clear()

    # Later increment seams (unimplemented today; the interface names
    # keep the RFC-11 phase 4/5 landing sites visible).

    async def open_pool_for_capability(
        self,
        capability: str,
        *,
        module_scope: str | None = None,
    ) -> tuple[McpClient, ...]:
        """Return one :class:`McpClient` per enabled catalog row of ``capability``.

        Deferred to a later RFC-11 increment. When it lands, it will
        compose with
        :meth:`aila.platform.mcp.registry.McpRegistryServiceBase.pool_for_capability`
        (already implemented; returns the pool of
        :class:`~aila.platform.mcp.client.ResolvedInstance`\\ s) so
        the caller receives a fan-out of clients rather than a manual
        pool. Today the method raises so no accidental caller ships
        against a half-built API; the ``self`` state (module-declared
        descriptors) is what the later increment will consult, hence
        the instance-method signature over a bare function.
        """
        # Read self.declarations() so the eventual implementation site
        # is anchored to the registry state -- also gives PLR6301 an
        # honest reason to accept the instance-method binding today.
        declared = self.descriptors_for_capability(
            capability, module_scope=module_scope,
        )
        raise NotImplementedError(
            f"McpCapabilityRegistry.open_pool_for_capability({capability!r}, "
            f"module_scope={module_scope!r}): RFC-11 pooling composition "
            f"lands in a later increment (would return {len(declared)} "
            f"descriptor pool); use McpRegistryServiceBase.pool_for_capability "
            f"+ open_client per member for now",
        )


_default_registry_lock = threading.Lock()
_default_registry: McpCapabilityRegistry | None = None


def default_capability_registry() -> McpCapabilityRegistry:
    """Return the process-wide :class:`McpCapabilityRegistry` singleton.

    Constructed lazily on first access. Every module's
    ``create_module()`` publishes descriptors here; every caller that
    wants a capability-resolved :class:`McpClient` reads from here.
    """
    global _default_registry
    if _default_registry is not None:
        return _default_registry
    with _default_registry_lock:
        if _default_registry is None:
            _default_registry = McpCapabilityRegistry()
        return _default_registry


def reset_default_capability_registry() -> None:
    """Drop the singleton so the next call rebuilds it empty.

    Test-only helper. Production wiring never calls this; a test that
    mutates the singleton wipes it in a fixture teardown so later
    tests do not see leaked declarations.
    """
    global _default_registry
    with _default_registry_lock:
        if _default_registry is not None:
            _default_registry.clear()
        _default_registry = None
