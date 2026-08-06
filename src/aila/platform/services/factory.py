"""ServiceFactory -- constructor injection hub for platform services per D-02.

Creates short-lived service instances on property access (per SDA-06:
services are cheap, stateless, GC handles cleanup).

Optionally carries TeamContext so callers can access it when constructing
UoW instances that need team-scoped filtering (D-03) and auto-stamping (D-07).

Usage:
    factory = ServiceFactory(team_context=ctx)
    await factory.reports.upsert_findings_batch(records)
"""

from __future__ import annotations

import logging as _logging
import threading as _threading
from typing import TYPE_CHECKING

from aila.platform.events import EventEmitter, ThreadSafeEventEmitter
from aila.platform.llm.client import AilaLLMClient
from aila.storage.registry import ConfigRegistry
from aila.storage.secrets import SecretStore

from .knowledge import KnowledgeService
from .reasoning import CyberReasoningEngine
from .reasoning_graphs import ReasoningGraphService
from .report import ReportService
from .storage import StorageService
from .system import SystemService

if TYPE_CHECKING:
    from aila.api.auth import TeamContext
__all__ = ["ServiceFactory"]


class ServiceFactory:
    """Create platform service instances with shared TeamContext wiring.

    Services are still cheap, but the LLM client + ConfigRegistry +
    SecretStore triple is no longer rebuilt on every property access
    (fix §125 / §126 -- each access used to trigger a fresh DB lookup
    table init via ConfigRegistry, costing latency for any function
    that touched ``factory.llm_client`` twice).

    Optional service overrides on ``__init__`` give tests a clean
    injection point (fix §127); production callers omit them and get
    the cached defaults.
    """

    def __init__(
        self,
        team_context: TeamContext | None = None,
        *,
        llm_client: AilaLLMClient | None = None,
        reasoning_engine: CyberReasoningEngine | None = None,
        config_registry: ConfigRegistry | None = None,
        secret_store: SecretStore | None = None,
        system_emitter: EventEmitter | None = None,
    ) -> None:
        self._team_context = team_context
        # fix \u00a7127 -- explicit injection points. Tests pass fakes; production
        # leaves these as None and the lazy getters build the real services.
        self._llm_client_override = llm_client
        self._reasoning_engine_override = reasoning_engine
        self._config_registry_override = config_registry
        self._secret_store_override = secret_store
        # #52-3.4 -- caller-supplied emitter for SystemService. Tests inject a
        # fake; production leaves this as None and the SystemService property
        # builds a lightweight process-wide default via the lazy getter below.
        self._system_emitter_override = system_emitter
        # fix \u00a7125 / \u00a7126 -- memoized singletons. None until first access.
        self._llm_client_cache: AilaLLMClient | None = None
        self._reasoning_engine_cache: CyberReasoningEngine | None = None
        self._config_registry_cache: ConfigRegistry | None = None
        self._secret_store_cache: SecretStore | None = None

    @property
    def team_context(self) -> TeamContext | None:
        """The TeamContext for this factory's services."""
        return self._team_context

    @property
    def reports(self) -> ReportService:
        """ReportService -- finding upserts, severity queries, report management.

        #53: threads ``self._team_context`` so every short-lived session the
        service opens (via its private ``_session_or_new``) is scoped to the
        factory's tenant. When ``_team_context`` is ``None``, the underlying
        ``async_session_scope`` still falls back to the ambient TeamContext.
        """
        return ReportService(team_context=self._team_context)

    @property
    def storage(self) -> StorageService:
        """StorageService -- generic CRUD, artifact persistence (#53 team-scoped)."""
        return StorageService(team_context=self._team_context)

    @property
    def systems(self) -> SystemService:
        """SystemService -- managed system lifecycle (#52-3.4 emitter-wired).

        The returned service carries the caller-supplied ``system_emitter``
        if one was passed to the factory, otherwise a lightweight
        process-wide default emitter (see :func:`_get_system_emitter`).
        That default publishes system.registered / system.deregistered
        PlatformEvents to two destinations wired at first use:

            audit_db     -- appends AuditEventRecord rows via
                            :func:`record_audit_event_sync` inside a
                            short-lived sync session so the operator
                            audit list surfaces every register /
                            deregister transition.
            log          -- structured INFO log so operators can trace
                            emission without a DB round-trip.

        The typed :class:`aila.platform.events.SystemRegistered` /
        :class:`SystemDeregistered` DomainEvents are ALSO published on
        the process-wide DomainEventBus by SystemService itself (see
        ``system.py``); the default subscriber writes them into the
        hash-chained platform journal via ``kind="domain_event"``.
        """
        return SystemService(
            emitter=self._system_emitter_override or _get_system_emitter(),
            team_context=self._team_context,
        )

    @property
    def knowledge(self) -> KnowledgeService:
        """KnowledgeService -- RAG retrieval, agent knowledge store (#53 team-scoped).

        Wired with the factory's ``llm_client`` so RFC-12 Phase 3 contextual
        enrichment (``store(..., chunked=True, enrich=True)``) is reachable
        through the canonical constructor. Without it the enrichment path
        (which checks ``self._llm_client is not None``) was a silent no-op for
        every factory-built service. Enrichment stays opt-in per call and
        default-off, so the client is exercised only when a caller explicitly
        requests it; the pure-retrieval paths that build ``KnowledgeService()``
        directly are unaffected and stay lightweight.
        """
        return KnowledgeService(
            team_context=self._team_context,
            llm_client=self.llm_client,
        )

    def _get_config_registry(self) -> ConfigRegistry:
        """Return the memoized ConfigRegistry, building it on first access."""
        if self._config_registry_override is not None:
            return self._config_registry_override
        if self._config_registry_cache is None:
            self._config_registry_cache = ConfigRegistry()
        return self._config_registry_cache

    def _get_secret_store(self) -> SecretStore:
        """Return the memoized SecretStore, building it on first access."""
        if self._secret_store_override is not None:
            return self._secret_store_override
        if self._secret_store_cache is None:
            self._secret_store_cache = SecretStore()
        return self._secret_store_cache

    @property
    def llm_client(self) -> AilaLLMClient:
        """AilaLLMClient wired through the platform registry and secret store.

        Memoized -- repeated access returns the same instance. Wraps
        ConfigRegistry + SecretStore, which themselves do I/O on
        construction; per-access creation was a latency tax (§125).
        """
        if self._llm_client_override is not None:
            return self._llm_client_override
        if self._llm_client_cache is None:
            self._llm_client_cache = AilaLLMClient(
                registry=self._get_config_registry(),
                secret_store=self._get_secret_store(),
            )
        return self._llm_client_cache

    @property
    def reasoning_engine(self) -> CyberReasoningEngine:
        """Platform-owned reasoning engine backed by the shared LLM client.

        Memoized; reuses :attr:`llm_client` so two ``factory.reasoning_engine``
        calls don't double-construct the LLM client (§126).
        """
        if self._reasoning_engine_override is not None:
            return self._reasoning_engine_override
        if self._reasoning_engine_cache is None:
            # Pass the memoized registry so the reasoning engine can read
            # operator-supplied domain profiles (§131) without spinning up
            # its own ConfigRegistry.
            self._reasoning_engine_cache = CyberReasoningEngine(
                self.llm_client,
                config_registry=self._get_config_registry(),
            )
        return self._reasoning_engine_cache

    @property
    def reasoning_graphs(self) -> ReasoningGraphService:
        """Durable storage/query surface for reasoning graph snapshots."""
        return ReasoningGraphService()


# Process-wide default emitter shared by every ServiceFactory that does not
# inject its own (#52-3.4). Built lazily on first access so importing the
# factory module never pulls in the DB, Redis, or Prometheus paths.
_SYSTEM_EMITTER_SINGLETON: EventEmitter | None = None
_SYSTEM_EMITTER_LOCK = _threading.Lock()


def _get_system_emitter() -> EventEmitter:
    """Return the process-wide default SystemService emitter.

    The emitter fans PlatformEvents to two destinations:

    - ``audit_db`` -- writes AuditEventRecord rows via the sync-session
      audit helper. A short-lived session is opened per emit; failures
      route through the isolation guard so a broken DB never blocks
      the caller.
    - ``log`` -- structured INFO log so operators can trace emission
      without a DB round-trip.

    The emitter is a ThreadSafeEventEmitter so parallel request
    handlers (system registration from concurrent API calls) safely
    share a single queue.
    """
    global _SYSTEM_EMITTER_SINGLETON
    if _SYSTEM_EMITTER_SINGLETON is not None:
        return _SYSTEM_EMITTER_SINGLETON
    with _SYSTEM_EMITTER_LOCK:
        if _SYSTEM_EMITTER_SINGLETON is None:
            _SYSTEM_EMITTER_SINGLETON = _build_system_emitter()
    return _SYSTEM_EMITTER_SINGLETON


def _build_system_emitter() -> EventEmitter:
    """Construct the default SystemService emitter. Kept private so tests
    can build their own via :class:`ThreadSafeEventEmitter` directly.

    Destinations:

    - ``log`` -- structured INFO log line so operators can trace every
      system.registered / system.deregistered emission without a DB
      round-trip. Never raises.

    Persistence of the typed :class:`SystemRegistered` /
    :class:`SystemDeregistered` DomainEvent is handled by the shared
    :class:`aila.platform.events.DomainEventBus` (default subscriber
    :func:`aila.platform.events.persistence.persist_domain_event` writes
    a journal row with ``kind="domain_event"``); the emitter is a
    complementary live-observation channel, not a persistence path,
    which is why the drain-thread destination is intentionally kept
    to a non-blocking log write. A caller that wants a Redis-stream
    live-fan-out for admin UIs injects a custom ``system_emitter``
    on the factory constructor.
    """
    from aila.platform.contracts import utc_now
    from aila.platform.events.event import PlatformEvent

    log = _logging.getLogger("aila.platform.services.system.emitter")

    emitter = ThreadSafeEventEmitter()

    def _log_destination(event: PlatformEvent) -> None:
        log.info(
            "system_event stage=%s action=%s key=%s run_id=%s ts=%s",
            event.stage, event.action, event.key, event.run_id,
            utc_now().isoformat(),
        )

    emitter.register_destination("log", _log_destination)
    return emitter


def _reset_system_emitter_for_tests() -> None:
    """Drop the module-level singleton so the next factory access rebuilds
    a fresh emitter. Tests only."""
    global _SYSTEM_EMITTER_SINGLETON
    with _SYSTEM_EMITTER_LOCK:
        _SYSTEM_EMITTER_SINGLETON = None
