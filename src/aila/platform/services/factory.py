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

from typing import TYPE_CHECKING

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
    (fix §125 / §126 — each access used to trigger a fresh DB lookup
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
    ) -> None:
        self._team_context = team_context
        # fix §127 — explicit injection points. Tests pass fakes; production
        # leaves these as None and the lazy getters build the real services.
        self._llm_client_override = llm_client
        self._reasoning_engine_override = reasoning_engine
        self._config_registry_override = config_registry
        self._secret_store_override = secret_store
        # fix §125 / §126 — memoized singletons. None until first access.
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
        """ReportService -- finding upserts, severity queries, report management."""
        return ReportService()

    @property
    def storage(self) -> StorageService:
        """StorageService -- generic CRUD, artifact persistence."""
        return StorageService()

    @property
    def systems(self) -> SystemService:
        """SystemService -- managed system lifecycle."""
        return SystemService()

    @property
    def knowledge(self) -> KnowledgeService:
        """KnowledgeService -- RAG retrieval, agent knowledge store."""
        return KnowledgeService()

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

        Memoized — repeated access returns the same instance. Wraps
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
            self._reasoning_engine_cache = CyberReasoningEngine(self.llm_client)
        return self._reasoning_engine_cache

    @property
    def reasoning_graphs(self) -> ReasoningGraphService:
        """Durable storage/query surface for reasoning graph snapshots."""
        return ReasoningGraphService()
