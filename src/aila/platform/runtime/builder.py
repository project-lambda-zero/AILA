from __future__ import annotations

from ...storage.registry import ConfigRegistry, SchemaRegistry
from ...storage.secrets import SecretStore
from ..config import ApplicationSettings, PlatformConfigSchema, PlatformSettings
from ..llm import AilaLLMClient
from ..llm.classify import make_classify_step
from ..llm.cost import CostTracker
from ..llm.gate import make_gate_step
from ..llm.run_memory import RunMemory
from ..llm.seal import make_seal_step
from ..llm.validate import make_validate_step
from ..llm.verify import make_verify_step
from ..modules import ModuleContext, ModuleRegistry, register_builtin_modules
from ..tools import (
    ArtifactSearchTool,
    ArtifactStoreTool,
    AuditLogTool,
    DecisionCacheTool,
    HTTPFetchTool,
    KnowledgeRetrieveTool,
    KnowledgeStoreTool,
    PermanentMemoryTool,
    ReportsQueryTool,
    SecretsManageTool,
    SSHCommandTool,
    SystemRegistryTool,
)
from ..tools._common import Tool
from .platform import PlatformRuntime
from .tools import ToolRegistry

PLATFORM_TOOL_KEYS: frozenset[str] = frozenset({
    "registry.systems",
    "memory.permanent",
    "ssh.command",
    "reports.query",
    "artifacts.store",
    "artifacts.search",
    "secrets.manage",
    "audit.log",
    "http.fetch",
    "cache.decision",
    "knowledge.store",
    "knowledge.retrieve",
    "module_status",
})


class ModuleStatusTool(Tool):
    """Platform tool returning basic module status.

    Registered as 'module_status' in PLATFORM_TOOL_KEYS. Satisfies D-04: every
    module inherits at least this tool so required_tools() is never empty.
    Returns a lightweight status dict — no sensitive data, no state mutation.
    """

    name = "module_status"
    description = "Return a lightweight platform status payload for module health checks."
    inputs: dict[str, object] = {}
    output_type = "object"

    def __init__(self, settings: PlatformSettings) -> None:
        self._settings = settings

    def forward(self, **kwargs: object) -> dict[str, str]:
        return {"status": "ok", "tool": "module_status"}


async def build_platform_runtime(*, app_settings: ApplicationSettings, platform_settings: PlatformSettings) -> PlatformRuntime:
    """Assemble and return a fully initialized PlatformRuntime.

    Initialization order:
    1. Builds ConfigRegistry and AilaLLMClient from SecretStore
    2. Registers all 12 platform-level tools into the ToolRegistry
    3. Registers schema registry
    4. Discovers and registers all built-in modules (platform + feature modules)
    5. Calls module.register_tools() for each module
    6. Initializes the DB and runs seed_data() for each module
    7. Calls module.build_runtime() with per-module tool scopes
    """
    config_registry = ConfigRegistry()
    await config_registry.register("platform", PlatformConfigSchema)

    secret_store = SecretStore(platform_settings)
    runtime_model = AilaLLMClient(registry=config_registry, secret_store=secret_store)

    # Cost tracking (Phase 122): wire CostTracker into client
    run_memory = RunMemory()
    cost_tracker = CostTracker(run_memory=run_memory, registry=config_registry)
    runtime_model.cost_tracker = cost_tracker

    # Register classify pipeline step (Phase 117: Data Classification).
    # Emitter is None at startup -- the per-request ThreadSafeEventEmitter is
    # built at request time, not here.  The classify step handles None emitter
    # gracefully (skips audit event emission, still logs via Python logging).
    _classify_step = make_classify_step(registry=config_registry, emitter=None)
    runtime_model.pipeline.register("classify", _classify_step)

    # Validate pipeline step (Phase 118 — Evidence Validation). Modules
    # contribute validators via ModuleProtocol.evidence_validators() so
    # the platform stays module-agnostic; the step itself is registered
    # below after the module registry is built.

    # Register gate pipeline step (Phase 119: Confidence Gating).
    # call_fn is _single_call for consensus retry calls that bypass the pipeline.
    # Emitter is None at startup -- same reasoning as classify/validate steps above.
    _gate_step = make_gate_step(
        config_provider=runtime_model._config,
        call_fn=runtime_model._single_call,
        emitter=None,
    )
    runtime_model.pipeline.register("gate", _gate_step)

    # Register verify pipeline step (Phase 174: Second-Model Verification).
    # call_fn is _single_call for blind verification calls that bypass the pipeline.
    # Emitter is None at startup -- same reasoning as classify/validate/gate steps above.
    _verify_step = make_verify_step(
        config_provider=runtime_model._config,
        call_fn=runtime_model._single_call,
        emitter=None,
    )
    runtime_model.pipeline.register("verify", _verify_step)

    # Register seal pipeline step (Phase 120: Audit Sealing).
    # Purely observational -- computes HMAC-SHA256 seal and stores to DB.
    # Emitter is None at startup -- same reasoning as classify/validate/gate steps above.
    _seal_step = make_seal_step(
        config_provider=runtime_model._config,
        emitter=None,
    )
    runtime_model.pipeline.register("seal", _seal_step)

    tool_registry = ToolRegistry()
    for key, tool in (
        ("registry.systems", SystemRegistryTool(platform_settings)),
        ("memory.permanent", PermanentMemoryTool(platform_settings)),
        ("ssh.command", SSHCommandTool(platform_settings)),
        ("reports.query", ReportsQueryTool(platform_settings)),
        ("artifacts.store", ArtifactStoreTool(platform_settings)),
        ("artifacts.search", ArtifactSearchTool(platform_settings)),
        ("secrets.manage", SecretsManageTool(platform_settings)),
        ("audit.log", AuditLogTool(platform_settings)),
        ("http.fetch", HTTPFetchTool(platform_settings)),
        ("cache.decision", DecisionCacheTool(platform_settings)),
        # Knowledge tools — platform-level registration uses namespace="platform".
        # Agents that need isolated knowledge stores must construct their own instances:
        #   store_tool = KnowledgeStoreTool(namespace=self.__class__.__name__, settings=settings)
        # Namespace isolation is enforced at SQL level (WHERE namespace = ?) per D-06 and D-10.
        ("knowledge.store", KnowledgeStoreTool(namespace="platform", settings=platform_settings)),
        ("knowledge.retrieve", KnowledgeRetrieveTool(namespace="platform", settings=platform_settings)),
        ("module_status", ModuleStatusTool(platform_settings)),
    ):
        tool_registry.register(key, tool)

    schema_registry = SchemaRegistry()

    module_registry = ModuleRegistry()
    register_builtin_modules(module_registry)
    await module_registry.register_tools(tool_registry, app_settings, config_registry, schema_registry)

    # Now the registry is built, collect each module's evidence_validators()
    # and register the validate pipeline step (Phase 118). Modules that
    # ship no validator return [] from the default — the resulting step
    # is a no-op for them.
    _validators: list = []
    for _module in module_registry.modules:
        _validators.extend(_module.evidence_validators(settings=app_settings))
    _validate_step = make_validate_step(validators=_validators, emitter=None)
    runtime_model.pipeline.register("validate", _validate_step)

    from ...storage.database import async_session_scope, init_db
    await init_db(app_settings, schema_registry)

    # Call seed_data() for each registered module — idempotent, skips if already seeded.
    async with async_session_scope(app_settings) as _seed_session:
        for _module in module_registry.modules:
            await _module.seed_data(_seed_session)

    # Pre-resolve all config entries in async context so build_runtime() (sync)
    # can read them from a plain dict without hitting the DB.
    resolved_config = await config_registry.all_entries_by_namespace()

    module_runtimes = module_registry.build_runtimes(
        ModuleContext(
            settings=app_settings,
            tool_registry=tool_registry,
            runtime_model=runtime_model,
            config_registry=config_registry,
            resolved_config=resolved_config,
        ),
        tool_registry=tool_registry,
    )
    return PlatformRuntime(
        module_registry=module_registry,
        modules=module_runtimes,
        tool_registry=tool_registry,
        runtime_model=runtime_model,
        config_registry=config_registry,
    )
