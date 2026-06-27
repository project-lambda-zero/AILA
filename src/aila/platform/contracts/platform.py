from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from ._common import ActionId, utc_now

if TYPE_CHECKING:
    from aila.platform.modules.protocol import ModuleCapabilityProfile
    from aila.platform.tasks.models import TaskHandle


# ---------------------------------------------------------------------------
# Platform config constants -- public re-exports for modules
#
# Modules that need to look up platform config keys (e.g. redis_url) must
# obtain them via aila.platform.contracts.platform, NOT via
# aila.platform.tasks.constants which is a platform-internal module.
# ---------------------------------------------------------------------------

# Config registry namespace for platform-level config keys.
PLATFORM_CONFIG_NS: str = "platform"

# Config registry key for the Redis URL (used by SSE, task queue, etc.).
PLATFORM_CONFIG_KEY_REDIS_URL: str = "redis_url"


@runtime_checkable
class AsyncTaskQueue(Protocol):
    """Public Protocol for the platform async task queue.

    Modules annotate their task_queue parameters against this Protocol.
    The concrete TaskQueue is provided by the platform via dependency
    injection (Depends(get_task_queue) in FastAPI routes, or injected
    on TaskContext (via @platform_task handlers) in ARQ workers).

    Modules MUST NOT import TaskQueue from aila.platform.tasks.queue.
    Import this Protocol from aila.platform.contracts.platform instead.
    """

    async def submit(
        self,
        track: str,
        fn: Callable[..., Any],
        kwargs: dict[str, Any],
        depends_on: list[str] | None = None,
        user_id: str = "system",
        group_id: str = "system",
        team_id: str | None = None,
    ) -> TaskHandle:
        """Submit a background task; returns a TaskHandle for status polling."""
        ...


class RouteCandidate(BaseModel):
    """One evaluated action candidate produced by the routing agent.

    Included in RouteDecision.candidates to give callers full visibility into
    what the router considered, not just the winner.
    """

    module_id: str | None = Field(default=None, description="Module ID for this candidate.")
    action_id: ActionId = Field(description="Dot-separated action this candidate handles.")
    score: float = Field(description="Confidence score for this candidate.", ge=0.0)
    tools: list[str] = Field(default_factory=list, description="Tool keys required by this action.")


class RouteDecision(BaseModel):
    """The routing decision produced by ModuleRouter for a single query.

    Carried on RunState.route and echoed in PlatformResponse.route so every
    downstream system -- modules, CLI, API -- knows why a particular action was
    selected and how confident the router was.
    """

    action_id: ActionId = Field(description="Dot-separated module.action selected for this query.")
    selected_module: str | None = Field(default=None, description="Module ID that will handle this request.")
    confidence: float | None = Field(default=None, description="Routing confidence score between 0.0 and 1.0.", ge=0.0, le=1.0)
    rationale: str = Field(default="", description="Agent rationale for the routing decision.")
    decision_source: str = Field(default="model", description="How the decision was made: 'model', 'cache', or 'fallback'.", examples=["model", "cache", "fallback"])
    candidates: list[RouteCandidate] = Field(default_factory=list, description="All candidate routes evaluated before selection.")


class SSHIntegrationInput(BaseModel):
    """Validated input for registering or updating an SSH-connected managed system.

    Used as the write payload for SystemRegistryTool upsert. The password field
    is excluded from serialization and repr to prevent accidental leakage into
    logs or API responses.
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    host: str
    username: str
    port: int = 22
    distro: str = "unknown"
    description: str = ""
    private_key_path: str | None = None
    password: str | None = Field(default=None, exclude=True, repr=False)
    password_secret_id: str | None = None
    known_hosts_path: str | None = None
    host_key_fingerprint: str | None = None


class RegisteredSystem(SSHIntegrationInput):
    """A persisted SSH integration record as returned from the database.

    Extends SSHIntegrationInput with the database-assigned id and timestamps.
    Used as the read shape from SystemRegistryTool list/get actions.
    """

    id: int | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class WorkflowEvent(BaseModel):
    """A single workflow stage transition event recorded for a run.

    Appended to RunState.events as each pipeline stage completes. Surfaced in
    PlatformResponse.state_history when debug=True -- omitted in production to
    keep responses compact.
    """

    state: str = Field(description="Workflow stage name that emitted this event.", examples=["analysis_start", "scoring_complete"])
    note: str = Field(description="Human-readable description of what happened at this stage.")
    occurred_at: datetime = Field(default_factory=utc_now, description="UTC timestamp when this event occurred.")


class ProgressUpdate(BaseModel):
    """Real-time progress notification delivered to the caller's progress_callback.

    Carries the current stage name, a human-readable message, and optional
    current/total counters for displaying progress bars in CLI and API consumers.
    """

    stage: str
    message: str
    current: int | None = None
    total: int | None = None


class RegistryResponse(BaseModel):
    """The structured response from any SystemRegistryTool operation.

    Returned by upsert, list, get, and delete actions. Callers use
    missing_names and deleted_names to detect partial success when multiple
    names were requested in a single operation.
    """

    model_config = ConfigDict(extra="forbid")

    message: str = Field(description="Human-readable summary of the registry operation.")
    count: int = Field(default=0, description="Number of integrations affected or returned.")
    integrations: list[RegisteredSystem] = Field(default_factory=list, description="SSH integrations returned by a list or upsert operation.")
    deleted_names: list[str] = Field(default_factory=list, description="Names of integrations that were deleted.")
    requested_names: list[str] = Field(default_factory=list, description="Names requested in the operation.")
    resolved_names: list[str] = Field(default_factory=list, description="Names that were successfully resolved.")
    missing_names: list[str] = Field(default_factory=list, description="Names that were not found in the registry.")
    duplicate_requested_names: list[str] = Field(default_factory=list, description="Names requested more than once in a single call.")


class DeleteIntegrationsPayload(BaseModel):
    """Request payload for the platform.delete_integration action.

    Carries the list of system names to remove from the permanent registry.
    Validated at the module boundary before any DB operations begin.
    """

    model_config = ConfigDict(extra="forbid")

    target_names: list[str] = Field(default_factory=list)


class AddIntegrationPayload(BaseModel):
    """Request payload for the platform.add_integration action.

    Wraps the SSHIntegrationInput so the module handler can validate the full
    integration structure as a single unit before calling SystemRegistryTool.
    """

    model_config = ConfigDict(extra="forbid")

    integration: SSHIntegrationInput


class ExecuteRemoteCommandPayload(BaseModel):
    """Request payload for the platform.execute_remote_command action.

    When command and target_names are both populated the platform handler uses
    them directly without invoking the LLM selector. Empty fields cause the
    platform handler to delegate to the model for command and target resolution.
    """

    model_config = ConfigDict(extra="forbid")

    target_names: list[str] = Field(default_factory=list)
    command: str | None = None
    run_all_targets: bool = False


class RemoteCommandSelection(BaseModel):
    """The resolved command and target selection produced by the platform command selector.

    Either provided directly by a structured payload or resolved by the LLM from
    the user query. The rationale field records why the model chose these targets,
    preserved for audit trail.
    """

    model_config = ConfigDict(extra="forbid")

    command: str
    target_names: list[str] = Field(default_factory=list)
    run_all_targets: bool = False
    rationale: str = ""


class RoutedCandidate(BaseModel):
    """An alternate routing candidate returned by the model alongside the primary selection.

    Accepts both 'confidence' and 'score' field names via AliasChoices so the
    router model output is accepted regardless of which key the LLM uses.
    """

    module_id: str
    action_id: str
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        validation_alias=AliasChoices("confidence", "score"),
    )


class RoutingSelection(BaseModel):
    """The JSON structure the routing agent must return when called by ModuleRouter.

    Deserialized directly from the model's JSON output. The alternates list
    lets callers inspect runner-up candidates without a second model call.
    """

    module_id: str = Field(description="Module ID selected by the routing agent.")
    action_id: str = Field(description="Action within the module selected for this request.")
    confidence: float = Field(ge=0.0, le=1.0, description="Routing confidence score.")
    rationale: str = Field(default="", description="Agent rationale for selecting this module and action.")
    alternates: list[RoutedCandidate] = Field(default_factory=list, description="Other candidates considered but not selected.")


class RoutingCandidateProfile(BaseModel):
    """A module action profile serialized into the routing prompt as a candidate.

    Built from ModuleCapabilityProfile and passed to the routing model so it can
    reason about each action's intent, required tools, and example phrasings
    without accessing internal module state.
    """

    module_id: str
    action_id: str
    description: str
    tools: list[str] = Field(default_factory=list)
    examples: list[str] = Field(default_factory=list)

    @classmethod
    def from_profile(cls, profile: ModuleCapabilityProfile) -> RoutingCandidateProfile:
        """Build a prompt-safe routing profile from an internal ModuleCapabilityProfile.

        Converts the internal dataclass (which holds the actual module implementation
        reference) into a serializable Pydantic model safe to embed in an LLM prompt.
        Uses TYPE_CHECKING guard on ModuleCapabilityProfile to break the circular
        import between contracts and modules packages.
        """
        return cls(
            module_id=profile.module_id,
            action_id=profile.action_id,
            description=profile.description,
            tools=list(profile.tools),
            examples=list(profile.examples),
        )
