from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from ..config import ApplicationSettings
from ..contracts._common import ActionId, JsonObject
from ..contracts.platform import ProgressUpdate
from ..contracts.runtime import PlatformResponse, RunState
from ..runtime.tools import ToolAccess, ToolRegistry

if TYPE_CHECKING:
    from sqlmodel import Session

    from ...storage.memory import PermanentMemoryStore
    from ...storage.registry import ConfigRegistry, SchemaRegistry
    from ...storage.report_store import ReportArtifactStore
    from ..events import EventEmitter
    from ..llm import AilaLLMClient
    from ..services.knowledge import KnowledgeService
    from ..services.report import ReportService
    from ..services.storage import StorageService
    from ..services.system import SystemService
    from ..tasks.queue import TaskQueue


def action_id_for(module_id: str, action_name: str) -> ActionId:
    """Build the canonical dot-separated action identifier for a module action.

    All routing, dispatch, and capability profile lookups use this format.
    Using this function instead of f-strings ensures consistency across module
    implementations.
    """
    return f"{module_id}.{action_name}"


@dataclass
class ModuleDataContext:
    """Typed service access replacing context.session for module workflow states.

    Per D-07: modules call context.data.reports.upsert_finding() instead of
    context.session.exec().

    Services are injected by the platform at workflow start.
    """

    storage: StorageService | None = None
    systems: SystemService | None = None
    reports: ReportService | None = None
    knowledge: KnowledgeService | None = None


@dataclass(frozen=True, slots=True)
class ModuleRouteSpec:
    """Declares the HTTP surface a module contributes to the platform API.

    Platform calls router_factory() at startup and mounts the returned
    APIRouter under the declared prefix. Modules must NOT embed the prefix
    in the router -- the platform applies it here via include_router(prefix=...).

    These routes are the frontend/API contract for the module. Keep them
    explicit and stable: typed request bodies, response_model on every route,
    router-boundary field mapping from internal names to public names, and no
    hidden read-side effects such as implicit scans or rescoring.

    Attributes:
        prefix: URL prefix for all routes in this spec (e.g. "/vulnerability").
        router_factory: Zero-argument callable that returns a FastAPI APIRouter.
        tool_keys: Tool keys this module registers; surfaced via GET /tools.
            Use a tuple (not list) because ModuleRouteSpec is frozen.
        config_namespace: Config namespace this module owns; surfaced via
            GET/PUT /config. None if the module has no config.
        payload_type: Name of the discriminated-union payload type (optional).
    """

    prefix: str
    router_factory: Callable[[], Any]  # () -> APIRouter
    tool_keys: tuple[str, ...] = field(default_factory=tuple)
    config_namespace: str | None = None
    payload_type: str | None = None
    auth_required: bool = True  # When False, skip global require_user_or_api_key dependency


UNROUTABLE_ACTION_ID: ActionId = action_id_for("platform", "unknown_request")


@dataclass(frozen=True, slots=True)
class ModuleHealthResult:
    """Return type for module health check callables (protocol layer).

    Distinct from schemas.health.HealthCheckResult (the Pydantic API response
    model). This dataclass is the lightweight contract between module
    implementations and the health router.

    Attributes:
        status: One of 'up', 'degraded', or 'down'.
        latency_ms: Optional round-trip latency in milliseconds.
        message: Optional human-readable status detail.
    """

    status: str  # "up" | "degraded" | "down"
    latency_ms: float | None = None
    message: str | None = None


@dataclass(frozen=True, slots=True)
class ModuleCapabilityProfile:
    """Describes one action that a module can handle.

    Published by each module via capability_profiles() and used by the routing
    agent to reason about which module.action best answers the user's query.
    The description and examples fields are embedded directly in the routing
    prompt, so they must be written for LLM consumption, not just developer docs.
    """

    module_id: str
    action_id: str
    description: str
    tools: list[str]
    examples: list[str]


@dataclass(frozen=True, slots=True)
class ModuleContext:
    """Build-time dependencies passed to ModuleProtocol.build_runtime().

    Carries everything a module needs to construct its runtime: settings,
    a tool scope restricted to declared required_tools(), the shared LLM
    model instance, and optional config/schema registries.
    """

    settings: ApplicationSettings
    tool_registry: ToolAccess
    runtime_model: AilaLLMClient
    config_registry: ConfigRegistry | None = None
    resolved_config: dict[str, dict[str, object]] | None = None


@dataclass(frozen=True, slots=True)
class ModuleExecutionContext:
    """Per-request runtime context passed to every module handle() call.

    Created once per AILAPlatform.handle() call and passed through
    ModuleRequest. Carries the memory store, report artifact store, and
    event emitter -- all request-scoped. The emitter is wired at the
    orchestrator level with audit_db, run_history, and progress destinations.

    task_queue is the platform TaskQueue instance bound to the calling module.
    Modules call context.task_queue.submit() to enqueue background work.
    None in environments where the task queue is not configured (MOD-06/D-23).
    """

    memory_store: PermanentMemoryStore
    report_artifact_store: ReportArtifactStore
    progress_callback: Callable[[ProgressUpdate], None] | None = None
    emitter: EventEmitter | None = field(default=None)
    task_queue: TaskQueue | None = field(default=None)


@dataclass(frozen=True, slots=True)
class ModuleRequest:
    """All inputs required to execute one module action.

    Assembled by the platform orchestrator and passed unchanged to
    ModuleRuntime.handle(). The session is the active SQLModel session for
    the current request; modules must not create new sessions inside handle().
    """

    session: Session
    run_id: str
    action_id: str
    run_state: RunState
    execution_context: ModuleExecutionContext
    payload: JsonObject = field(default_factory=dict)
    options: JsonObject = field(default_factory=dict)


@runtime_checkable
class ModuleRuntime(Protocol):
    """The execution interface for an instantiated module.

    Built by ModuleProtocol.build_runtime() after all tools and settings are
    resolved. handle() is the single dispatch point for every action the
    module supports.
    """

    module_id: str

    async def handle(self, request: ModuleRequest) -> PlatformResponse:
        """Execute the action identified by request.action_id and return the platform response."""
        ...


@runtime_checkable
class ModuleProtocol(Protocol):
    """The contract every feature module must satisfy to be registered with the platform.

    Modules declare their capabilities, required tools, and report filter keys
    at class level. The platform calls register_tools() once at startup and
    build_runtime() once per platform instance construction. handle() is never
    called directly on the protocol -- it lives on the ModuleRuntime returned
    by build_runtime().
    """

    module_id: str

    def capability_profiles(self) -> list[ModuleCapabilityProfile]:
        """Return all action capability profiles this module can handle.

        Each profile describes one action and is embedded in the routing prompt.
        Must return at least one profile; ModuleRegistry validates this at
        registration time.
        """
        ...

    def required_tools(self) -> list[str]:
        """Return the tool keys this module needs in its runtime tool scope.

        The platform merges these with PLATFORM_TOOL_KEYS when building runtimes,
        so only module-specific tools need to be declared here.
        Default implementation returns ["module_status"] -- every module has access
        to at least the platform-wide module_status tool without overriding.
        """
        return ["module_status"]

    def report_filter_keys(self) -> list[str]:
        """Return the filter field names this module supports for report row queries.

        Used by the platform to validate filter payloads before passing them to
        filter_report_rows(). Return an empty list if the module has no filterable reports.
        Default implementation returns [] -- modules without filterable reports need not
        override this.
        """
        return []

    async def register_tools(
        self,
        tool_registry: ToolRegistry,
        settings: ApplicationSettings,
        registry: ConfigRegistry | None = None,
        schema_registry: SchemaRegistry | None = None,
    ) -> None:
        """Register module-owned tools into the global tool registry at startup.

        Called once during platform initialization. Module tools are registered
        under module-specific keys that are not in PLATFORM_TOOL_KEYS. The
        platform's own tools (ssh.command, reports.query, etc.) are registered
        separately by build_platform_runtime().
        """
        ...

    def build_runtime(self, context: ModuleContext) -> ModuleRuntime:
        """Construct and return the module's runtime instance.

        Called once per platform construction with a tool scope restricted to
        required_tools() merged with PLATFORM_TOOL_KEYS. The returned runtime
        handles all subsequent handle() calls for this module's lifetime.
        """
        ...

    def filter_report_rows(
        self,
        rows: list[JsonObject],
        filters: JsonObject | None = None,
    ) -> list[JsonObject]:
        """Apply module-specific filters to a list of raw report rows.

        Called by module workflow stages when a query includes filter parameters.
        Platform enforces that only keys declared in report_filter_keys() are
        accepted; modules own the actual filtering semantics.
        Default implementation returns all rows unchanged -- modules without
        filterable reports need not override this.
        """
        if not rows:
            return []
        if filters is None:
            return rows.copy()
        return rows.copy()

    async def seed_data(self, session: Any) -> None:
        """Seed initial data for this module. Called once after create_all().

        Implementations MUST be idempotent: check SeedVersionRecord before
        inserting. If seed_version matches the installed version, return early.
        The AsyncSession is already open; do not create a new session_scope inside.
        Default implementation is a no-op -- modules without seed data need not
        override this.
        """
        return

    def evidence_validators(
        self, settings: Any,
    ) -> list[Any]:
        """Return EvidenceValidator instances this module contributes.

        Called by the platform runtime builder during pipeline assembly
        (see ``aila.platform.runtime.builder``). The platform then
        registers the validate step with the union of all module
        validators -- platform code never imports a specific module's
        validator class.

        Default returns an empty list. Modules that ship a validator
        (today: vulnerability) override this to return one instance.
        """
        del settings
        return []

    async def health_summary(
        self, *, session: Any, team_id: str | None,
    ) -> Any:
        """Return a ModuleHealthSummary for this module (optional).

        Called by the platform health probe at
        ``aila.platform.services.health_probes.probe_modules``. When a
        module does not override this, the probe falls back to a
        generic ``WorkflowRunRecord`` query keyed on the module's id.

        Override to expose richer health signal (e.g. fuzz campaigns
        active, advisory queue depth) without coupling the platform
        to module-specific tables.
        """
        del session, team_id
        raise NotImplementedError

    def route_specs(self) -> list[ModuleRouteSpec]:
        """Declare HTTP routes this module handles.

        Platform auto-generates FastAPI routes from these specs. If a module
        exposes a browser-consumed HTTP surface, keep the router factory in
        `api_router.py` and treat its routes as a stable public contract.
        Return an empty list if the module has no direct HTTP routes.
        Default implementation returns [].
        """
        return []

    async def system_summary(self, system_id: int, session: Any) -> dict[str, Any]:
        """Return module-contributed dashboard data for a system (optional).

        Called by GET /systems/{id} to enrich system detail with module-specific
        data. Platform merges all non-empty module summaries into the response.
        Default implementation returns an empty dict -- modules override as needed.

        Args:
            system_id: Primary key of the ManagedSystemRecord to summarize.
            session: Active AsyncSession.

        Returns:
            Dict of module-specific data (e.g. {"critical": 5, "kev_count": 2}).
        """
        return {}

    async def system_findings(
        self, system_id: int, system_name: str, session: Any,
        page: int = 1, page_size: int = 50,
    ) -> dict[str, Any]:
        """Return paginated findings for a system owned by this module (optional).

        Called by GET /systems/{id}/findings. The platform delegates to each
        registered module so platform routers never import module-internal models.
        Default returns empty result set.

        Args:
            system_id: ManagedSystemRecord primary key.
            system_name: ManagedSystemRecord.name (modules often key on name, not id).
            session: Active AsyncSession.
            page: 1-based page number.
            page_size: Items per page.

        Returns:
            Dict with 'items' (list of finding dicts), 'total' (int).
        """
        return {"items": [], "total": 0}

    async def report_count(self, run_id: str, session: Any) -> dict[str, Any]:
        """Return semantic count breakdown for a report owned by this module (optional).

        Called by GET /reports/{run_id}/count. The vulnerability module returns
        severity breakdown + kev_count. Modules that do not own this run_id
        should return {} without raising.

        Args:
            run_id: WorkflowRunRecord primary key.
            session: Active AsyncSession.

        Returns:
            Dict of count fields (e.g. {"total_findings": 55, "critical": 5}).
        """
        return {}

    def health_checks(self) -> dict[str, object]:
        """Return module-specific health check callables (D-13: optional extension).

        Called by GET /health to collect module-contributed checks. Each value
        is a zero-argument callable returning a ModuleHealthResult-compatible
        object with a 'status' attribute ('up', 'degraded', or 'down').

        This method is OPTIONAL on concrete module implementations. The health
        endpoint checks `hasattr(module, 'health_checks')` before calling.
        Platform-level code must never require this method.

        Returns:
            Dict mapping check name (e.g. 'llm_api', 'ssh_reachability') to
            a zero-argument callable. Example:
                {'llm_api': lambda: check_llm_reachability()}
        """
        return {}

    def search_entities(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        """Return module-registered searchable entities matching query (D-37/D-28).

        Called by GET /search. Each dict must contain at minimum:
        entity_type, entity_id, title, snippet.

        OPTIONAL -- platform checks hasattr() before calling.

        Args:
            query: Raw search string from the client.
            limit: Maximum number of results to return.

        Returns:
            List of entity dicts, e.g.:
                [{'entity_type': 'cve', 'entity_id': 'CVE-2023-0001',
                  'title': 'CVE-2023-0001', 'snippet': 'openssl 1.0.2'}]
        """
        return []

    def dashboard_providers(self) -> dict[str, Callable]:
        """Return dashboard data provider callables (D-37/D-34).

        Called by GET /dashboard. Each value is a zero-argument async callable
        returning a dict of module-specific stats.

        OPTIONAL -- platform checks hasattr() before calling.

        Returns:
            Dict mapping provider name to a callable, e.g.:
                {'vulnerability_summary': lambda: {'critical': 5, 'kev': 2}}
        """
        return {}

    def workflow_definitions(self) -> dict[str, dict]:
        """Return module-owned workflow state machine definitions (D-37/D-29).

        Called by GET /findings/workflow/states to list all registered workflows.
        Each key is a workflow identifier; each value has 'states' and 'transitions'.

        OPTIONAL -- platform checks hasattr() before calling.

        Returns:
            Dict mapping workflow_id to state machine definition, e.g.:
                {'vulnerability': {'states': ['new', 'mitigated'],
                                   'transitions': {'new': ['mitigated']}}}
        """
        return {}

    async def fleet_severity_summary(self, system_ids: list[int], session: Any) -> dict[int, str]:
        """Return top severity per system_id for the given fleet slice (optional, D-20).

        Called by GET /systems list endpoint to populate the top_severity field for
        each system without N+1 per-system calls. One call covers the entire page.

        Platform checks hasattr(module, 'fleet_severity_summary') before calling.
        Modules that do not implement this method are silently skipped.

        Args:
            system_ids: List of ManagedSystemRecord primary keys on the current list page.
            session: Active AsyncSession.

        Returns:
            Dict mapping system_id to top severity string (critical|high|medium|low).
            Omit a system_id if it has no findings. Return {} if the module has no data.
        """
        return {}
