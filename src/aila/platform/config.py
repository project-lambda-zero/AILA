from __future__ import annotations

import importlib.metadata as _importlib_metadata
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Protocol, runtime_checkable

from pydantic import BaseModel

from ..storage.registry import DynamicKeyFamily

_AILA_VERSION: str = _importlib_metadata.version("aila")


__all__ = [
    "ApplicationSettings",
    "PlatformSettings",
    "PlatformSettingsSource",
    "PlatformConfigSchema",
    "build_platform_settings",
]


@runtime_checkable
class ApplicationSettings(Protocol):
    """Opaque application settings object passed through to module runtimes."""


class PlatformSettingsSource(Protocol):
    database_url: str
    report_dir: Path
    secret_keyring_path: Path
    secret_active_key_version: str
    request_timeout_seconds: float


@dataclass(frozen=True, slots=True)
class PlatformSettings:
    database_url: str
    report_dir: Path
    secret_keyring_path: Path
    secret_active_key_version: str
    request_timeout_seconds: float
    user_agent: str
    routing_min_confidence: float
    routing_decision_cache_ttl_hours: int


def _cfg_from_resolved(
    resolved_config: dict[str, dict[str, object]] | None,
    field_name: str,
    default: object,
) -> object:
    """Read platform config from pre-resolved dict; fall back to default.

    Does NOT call ConfigRegistry.get() (which is async). Reads from the
    resolved_config dict populated by build_platform_runtime() in async context.
    """
    if resolved_config is not None:
        val = resolved_config.get("platform", {}).get(field_name)
        if val is not None:
            return type(default)(val)  # type: ignore[call-arg]
    return default


def build_platform_settings(
    source: PlatformSettingsSource,
    resolved_config: dict[str, dict[str, object]] | None = None,
) -> PlatformSettings:
    schema_defaults = PlatformConfigSchema()
    user_agent = _cfg_from_resolved(resolved_config, "user_agent", schema_defaults.user_agent)
    routing_min_confidence = _cfg_from_resolved(resolved_config, "routing_min_confidence", schema_defaults.routing_min_confidence)
    routing_decision_cache_ttl_hours = _cfg_from_resolved(resolved_config, "routing_decision_cache_ttl_hours", schema_defaults.routing_decision_cache_ttl_hours)
    # Pure factory -- no side effects.  init_directories() in config.py is the sole
    # directory creation point (STD-09).  Callers must invoke init_directories() before
    # writing to report_dir or secret_keyring_path.
    return PlatformSettings(
        database_url=source.database_url,
        report_dir=source.report_dir,
        secret_keyring_path=source.secret_keyring_path,
        secret_active_key_version=source.secret_active_key_version,
        request_timeout_seconds=source.request_timeout_seconds,
        user_agent=str(user_agent),
        routing_min_confidence=float(routing_min_confidence),  # type: ignore[arg-type]
        routing_decision_cache_ttl_hours=int(routing_decision_cache_ttl_hours),  # type: ignore[arg-type]
    )


_PLATFORM_DYNAMIC_FAMILIES: tuple[DynamicKeyFamily, ...] = (
    # Per-task-type routing overrides (fall back to the llm_default_* statics).
    DynamicKeyFamily("llm_model_", str, description="Per-task-type model id."),
    DynamicKeyFamily("llm_max_tokens_", int, description="Per-task-type max output tokens."),
    DynamicKeyFamily("llm_temperature_", float, description="Per-task-type sampling temperature."),
    DynamicKeyFamily("llm_max_tool_steps_", int, description="Per-task-type tool-call loop cap."),
    DynamicKeyFamily("llm_tool_timeout_s_", float, description="Per-task-type per-tool timeout (s)."),
    DynamicKeyFamily("llm_data_direction_", str, description="Per-task-type data-direction constraint."),
    DynamicKeyFamily("llm_budget_max_total_tokens_", int, description="Per-task-type token budget ceiling."),
    # Per-team monthly budget ceiling (USD).
    DynamicKeyFamily("llm_monthly_budget_usd_", float, description="Per-team monthly budget ceiling (USD)."),
    # Pipeline gate thresholds and consensus (per task type).
    DynamicKeyFamily("llm_pipeline_gate_high_threshold_", float),
    DynamicKeyFamily("llm_pipeline_gate_medium_threshold_", float),
    DynamicKeyFamily("llm_pipeline_gate_reject_threshold_", float),
    DynamicKeyFamily("llm_pipeline_gate_consensus_strategy_", str),
    DynamicKeyFamily("llm_pipeline_gate_consensus_model_", str),
    DynamicKeyFamily("llm_pipeline_gate_consensus_retries_", int),
    # Pipeline verify (per task type).
    DynamicKeyFamily("llm_pipeline_verify_threshold_", float),
    DynamicKeyFamily("llm_pipeline_verify_model_", str),
    # Pipeline step-order overrides (comma-separated step lists).
    DynamicKeyFamily("llm_pipeline_pre_call_steps_", str),
    DynamicKeyFamily("llm_pipeline_post_call_steps_", str),
    # Generic pipeline step enable and fail-mode (bool or open/closed; callers coerce).
    DynamicKeyFamily("llm_pipeline_", str, description="Pipeline step enable or fail-mode override."),
)


class PlatformConfigSchema(BaseModel):
    """Runtime-editable platform settings -- registered under 'platform' namespace.

    Static fields below are the fixed platform keys. Per-task-type and per-team
    keys (llm_model_{task_type}, llm_monthly_budget_usd_{team_id}, ...) are
    declared as typed dynamic-key families so they are settable via PUT /config
    and cast on read, instead of being unvalidated free-form keys.
    """

    __dynamic_families__: ClassVar[tuple[DynamicKeyFamily, ...]] = _PLATFORM_DYNAMIC_FAMILIES

    request_timeout_seconds: float = 20.0
    user_agent: str = f"AILA/{_AILA_VERSION}"
    routing_min_confidence: float = 0.2
    routing_decision_cache_ttl_hours: int = 72

    # HTTP proxy (HTTP-01) -- empty string means no proxy
    http_proxy: str = ""
    https_proxy: str = ""

    # Redis connection URL for task queue (INFRA-02/D-23) -- empty string means not configured.
    # Set to redis://localhost:6379 or a Redis Cloud URL to enable async task execution.
    # When empty, TaskQueue falls back to synchronous in-process execution (TASK-11/D-19).
    redis_url: str = ""

    # JWT expiry -- configurable per deployment via PUT /config/platform/{key}
    jwt_access_expiry_s: int = 2_592_000   # 30 days
    jwt_refresh_expiry_s: int = 7_776_000  # 90 days

    # Task queue tuning -- configurable per deployment via PUT /config/platform/{key}
    heartbeat_interval_s: int = 30
    reaper_zombie_threshold_s: int = 3300
    reaper_heartbeat_threshold_s: int = 86400
    arq_job_timeout_s: int = 3600
    arq_max_tries: int = 3
    arq_keep_result_s: int = 3600
    progress_stream_maxlen: int = 1000

    # LLM routing global defaults (previously env-only ghost keys -- #45).
    # Declared so PUT /config can set them; defaults match the prior hardcoded
    # fallbacks in llm/config.py, so resolution behavior is unchanged.
    llm_default_model: str = "antigravity/claude-opus-4-6-thinking"
    llm_base_url: str = "https://openrouter.ai/api/v1"
    llm_default_max_tokens: int = 4096
    llm_default_temperature: float = 0.0
    llm_tool_timeout_s: float = 300.0
    llm_kill_switch: bool = False

    # LLM Pipeline step defaults (Phase 116)
    # Per-task-type overrides via PUT /config at runtime:
    #   llm_pipeline_{step}_{task_type} = true/false
    #   llm_pipeline_{step}_fail_mode_{task_type} = open/closed
    llm_pipeline_classify_default: bool = True
    llm_pipeline_validate_default: bool = True
    llm_pipeline_gate_default: bool = True
    llm_pipeline_seal_default: bool = True

    # Audit sealing (Phase 120)
    llm_seal_hmac_key: str = ""              # Empty = auto-generate on first use (D-04)
    llm_seal_retention_days: int = 90        # Default 90-day retention (D-12)

    # Budget ceiling per task_type (Phase 122). 0 = unlimited.
    # Per-task-type overrides via PUT /config: llm_budget_max_total_tokens_{task_type}
    llm_budget_max_total_tokens_default: int = 0

    # Data Posture Modes (Phase 173 -- DPM-01)
    data_posture_mode: str = "standard"  # transparent | standard | paranoid
    data_direction_default: str = "bidirectional"  # inbound | local_only | bidirectional

    # LLM Verification (Phase 174 -- LLM-SEC-01)
    llm_pipeline_verify_default: bool = False
    llm_pipeline_verify_threshold_default: float = 0.7
    llm_pipeline_verify_model_default: str = ""

    # LLM cost estimation fallback (Phase 175 / D-04)
    # Used when a team has no historical data for a task_type.
    # worst_case = target_count * fallback_max_tokens * (fallback_price_per_1k / 1000)
    llm_cost_estimate_fallback_max_tokens: int = 4096
    llm_cost_estimate_fallback_price_per_1k: float = 0.03

    # Human-equivalent hourly rate (Phase 175 / D-06a)
    # Operator sets their market rate; USD conversion = estimated_hours * rate.
    llm_human_consultant_hourly_rate: float = 150.0

    # Knowledge base embedding provider (#49). Selects the EmbeddingProvider
    # resolved by KnowledgeService: "bge-m3" (1024-dim, default) or
    # "all-MiniLM-L6-v2" (384-dim, zero-padded to the 1024 column). Read once
    # per process at service construction; a change needs a re-embed and a
    # worker/service restart to take effect.
    knowledge_embedding_model: str = "bge-m3"

    # RFC-12 pattern retrieval relevance floor. Hybrid retrieval hits with a
    # combined score (0.6*vec + 0.4*fts) below this value are dropped before
    # they can enter a researcher prompt so orthogonal top-k noise never
    # reaches the model. PatternStoreBase._resolve_relevance_floor reads this
    # via ConfigRegistry so operators can override per-deployment through the
    # env or PUT /config without a schema change.
    knowledge_pattern_relevance_floor: float = 0.3

    # SMTP delivery for scheduled reports (#45 -- ghost config keys).
    # report_tasks.py reads these through ConfigRegistry, but they were never
    # declared here, so the registry never seeded them and
    # PUT /config/platform/smtp_* was rejected as an unknown key -- email was
    # configurable only through env vars while the config API pretended it was
    # not. An empty smtp_host means delivery is skipped. smtp_password matches
    # the is_secret_config_key "password" token, so it is redacted for
    # non-admin readers (C6).
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_from: str = "aila@localhost"
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_ca_bundle_path: str = ""
    smtp_use_implicit_tls: bool = False

