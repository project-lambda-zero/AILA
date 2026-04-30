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

    Each property creates a fresh service instance.  Services are lightweight
    (no connection pools, no state) so per-access creation is fine (T-166-02
    accepted risk).
    """

    def __init__(
        self,
        team_context: TeamContext | None = None,
    ) -> None:
        self._team_context = team_context

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


    @property
    def llm_client(self) -> AilaLLMClient:
        """AilaLLMClient wired through the platform registry and secret store."""
        return AilaLLMClient(
            registry=ConfigRegistry(),
            secret_store=SecretStore(),
        )


    @property
    def reasoning_engine(self) -> CyberReasoningEngine:
        """Platform-owned reasoning engine backed by the shared LLM client."""
        return CyberReasoningEngine(self.llm_client)


    @property
    def reasoning_graphs(self) -> ReasoningGraphService:
        """Durable storage/query surface for reasoning graph snapshots."""
        return ReasoningGraphService()
