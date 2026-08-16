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
    # Per-model pricing (USD per 1k tokens). Suffix is the normalized model
    # slug produced by ``aila.platform.llm.cost._normalize_model_id`` --
    # non-word chars fold to '_' so a provider-qualified id like
    # 'anthropic/claude-sonnet-4-6' registers as
    # 'llm_cost_per_1k_prompt_anthropic_claude-sonnet-4-6'. Declared here so
    # ``ConfigRegistry.set()`` accepts operator writes via PUT /config
    # (issue #38). Missing suffix => calculate_cost_usd returns (0.0, False)
    # and the caller warns; a non-numeric value is rejected at set-time by
    # the family's ``float`` cast.
    DynamicKeyFamily(
        "llm_cost_per_1k_prompt_", float,
        description="Per-model USD per 1k prompt/input tokens (normalized model slug).",
    ),
    DynamicKeyFamily(
        "llm_cost_per_1k_completion_", float,
        description="Per-model USD per 1k completion/output tokens (normalized model slug).",
    ),
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
    # RFC-08 Tier D per-outcome_kind live threshold. Written by
    # ``POST /admin/eval/calibration-proposals/{id}/promote`` when the
    # eval + quorum gate clears; read by module confidence gates as
    # ``calibration_threshold_{outcome_kind}``. Threshold-shaped so
    # honesty audit rule 57 recognises the .set() key as a versioned
    # promotion (the CalibrationProposalRecord reference in the same
    # function body is what discharges the rule).
    DynamicKeyFamily(
        "calibration_threshold_", float,
        description="Per-outcome_kind live confidence threshold promoted from a CalibrationProposalRecord.",
    ),
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
    # Persona -> model_role routing map (#151). JSON object literal
    # mapping :class:`PersonaVoice` string values (halvar / maddie /
    # yuki / renzo / noor / wei, plus module-supplied specialist
    # voices) to a task_type / model_role string the LLM config layer
    # already resolves via ``llm_model_{model_role}``. Consumed by
    # :func:`aila.platform.routing.persona_model.resolve_effective_task_type`
    # on the turn-runner LLM path. Empty string is the
    # behavior-preserving default: no persona carries an override, so
    # every LLM call routes to the same task_type each sibling would
    # have used pre-#151. Populate to give distinct personas distinct
    # base models and unlock cross-error rejection during debate.
    # Malformed JSON or a non-object payload logs a warning and
    # collapses to the empty-map default rather than failing the
    # turn.
    persona_model_role_map: str = ""
    # 32768: a reasoning decision (reasoning + hypotheses + command +
    # observables) under extended-thinking needs a generous output ceiling;
    # 4096 risked truncating large decisions. Existing deployments already
    # carry 32768 as the seeded value -- this aligns the schema default so a
    # fresh install matches. Per-task overrides via llm_max_tokens_{task}.
    llm_default_max_tokens: int = 32768
    llm_default_temperature: float = 0.0
    llm_tool_timeout_s: float = 300.0
    llm_kill_switch: bool = False

    # ENHANCEMENT #142 -- share model-health-router state across workers.
    # When True (default) AND a Redis URL is configured (see ``redis_url``
    # above / ``AILA_PLATFORM_REDIS_URL`` env), one worker's discovery of
    # a down LLM gateway is visible to every peer through a Redis-backed
    # L2 cache keyed by endpoint URL with TTL == the router's cooldown.
    # The process-local singleton stays as the L1 cache so the hot path
    # never pays a round-trip on a warm-unhealthy entry, and a Redis
    # outage silently degrades to the pre-#142 per-process behaviour
    # (a Redis MISS is treated as HEALTHY -- fail-open). Set to False to
    # force the pre-#142 in-process-only path even with a Redis URL
    # configured (e.g. to isolate a worker for debugging).
    llm_health_router_redis_shared: bool = True

    # fix #132 -- in-call LLM retry loop knobs. Previously read as
    # module-level constants at ``client.py`` import time via
    # ``os.environ.get("AILA_LLM_MAX_RETRIES"|"AILA_LLM_RETRY_BASE_DELAY_S"
    # |"AILA_LLM_RETRY_MAX_DELAY_S"|"AILA_LLM_STRUCTURED_JSON_MAX_ATTEMPTS")``,
    # which froze the value at process start and bypassed PUT /config.
    # Now resolved through ConfigRegistry so operators can tune the
    # fast-fail budget at runtime. Env form is
    # ``AILA_PLATFORM_LLM_MAX_RETRIES`` (etc), which participates in the
    # env > DB > default chain like every other platform key. Defaults
    # match the historical fast-fail budget: 3 attempts, 1.0s base, 30s
    # ceiling, 3 structured-JSON correction attempts.
    llm_max_retries: int = 3
    llm_retry_base_delay_s: float = 1.0
    llm_retry_max_delay_s: float = 30.0
    llm_structured_json_max_attempts: int = 3

    # Per-call OpenAI/OmniRoute HTTP timeout in seconds. Previously read
    # via ``os.environ.get("AILA_LLM_TIMEOUT_SECONDS")`` at each call;
    # now resolved through ConfigRegistry so ops can widen the ceiling
    # for slow providers without a worker restart.
    llm_timeout_seconds: float = 180.0

    # fix #132 -- platform reaper cron knobs (previously read via
    # module-level ``os.environ.get("PLATFORM_WORKER_HEARTBEAT_GRACE_S"
    # |"PLATFORM_REAPER_ZOMBIE_HEARTBEAT_MIN"
    # |"PLATFORM_REAPER_CURSOR_BATCH_CAP")`` in ``tasks/worker.py`` at
    # import time). Renamed env form (still env-first): the layered
    # lookup accepts ``AILA_PLATFORM_REAPER_CRON_GRACE_S`` etc, and the
    # DB value can be overridden via PUT /config/platform. Defaults
    # match the historical values -- 600s cron grace, 10-min zombie
    # heartbeat threshold, 5000 cursor rows per reaper tick.
    reaper_cron_grace_s: int = 600
    reaper_zombie_heartbeat_min: int = 10
    reaper_cursor_batch_cap: int = 5000

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

    # RFC-08 memory-poisoning negative-prior penalty. Applied by
    # PatternStoreBase.applicable to each returned positive whose
    # applicability overlaps a filtered-out NEGATIVE pattern, and once to
    # every positive whose trust_tier is UNREVIEWED. The score is
    # multiplied by this factor per overlapping NEGATIVE and once for
    # UNREVIEWED, so a positive collocated with two overlapping
    # NEGATIVEs at penalty 0.5 emerges at 0.25 * base score. A value of
    # 1.0 disables the down-weight (the pattern-poisoning defense stays
    # informational only). RFC-08 explicitly forbids hard-blocking on a
    # NEGATIVE -- always a prior, never a gate.
    knowledge_negative_prior_penalty: float = 0.5

    # RFC-12 Phase 5 ranking controls, applied unconditionally by
    # KnowledgeService.retrieve_routed AFTER the relevance gate as a
    # post-rank (the post-rank always runs; operators tune the values
    # via env / PUT /config and validate any change against the
    # retrieval eval, aila eval-retrieval).
    #
    # knowledge_target_derived_weight multiplies the score of every hit
    # whose namespace resolves to the target-derived trust tier (burned
    # off untrusted tool output, e.g. *.observation.*). Below 1.0
    # down-weights untrusted memory so quorum/promotion-gated verified
    # entries win ties (RFC-12 ASI06 poisoning defense); 1.0 leaves the
    # score unchanged. A hit pushed below
    # knowledge_pattern_relevance_floor by the weight is dropped.
    knowledge_target_derived_weight: float = 0.5

    # knowledge_decay_half_life_hours applies exponential temporal decay
    # to every hit that carries a provenance timestamp: score is scaled
    # by 0.5 ** (age_hours / half_life). A positive value favors fresh
    # memory; a hit decayed below the relevance floor is dropped. A
    # value <= 0 disables decay. Default 2160h (90 days) so a
    # quarter-old pattern is halved.
    knowledge_decay_half_life_hours: float = 2160.0

    # RFC-14 platform graph retrieval (Personalized PageRank). The graph
    # route in KnowledgeService.retrieve_routed and the pattern retrieval
    # in PatternStoreBase.applicable rank by PPR over the
    # knowledge_entry_edges graph seeded from the hybrid lookup. These are
    # tuning knobs, not an on/off switch: PPR is the graph route's ranking
    # mechanism by construction, and PPR with no edges degenerates to the
    # seed (hybrid) ranking, so it is always safe to run. damping is the
    # restart probability weight (higher = spread farther from the seeds;
    # 0.5 keeps mass near the query-relevant seeds). max_nodes bounds the
    # induced subgraph so a pathological fan-out cannot stall a query.
    # entity_edge_weight is the weight of the shares_entity edges
    # KnowledgeService.link_entity_neighbors writes between entries that
    # share an extracted security identifier (CVE / CWE / ATT&CK / MASVS).
    knowledge_graph_ppr_damping: float = 0.5
    knowledge_graph_ppr_max_iter: int = 30
    knowledge_graph_ppr_max_nodes: int = 128
    knowledge_graph_entity_edge_weight: float = 0.8

    # RFC-10 promotion quorum. The lifecycle controller counts DISTINCT
    # actor strings on ``approved`` transitions for a (key, version) pair
    # and refuses to flip the production alias until that count meets or
    # exceeds this threshold, on top of the eval-pass gate. Default 1 =
    # one explicit human approval on top of the passing eval; operators
    # tune it upward per deployment via PUT /config/platform. A value of
    # 0 keeps the eval-only gate (no approval required) for teams that
    # want the RFC-08 auto-promote fast path routed through the
    # controller; the RFC-08 auto-promote path itself stays admin-opt-in
    # and skips the quorum gate by construction.
    agent_promotion_quorum: int = 1

    # RFC-10 canary drift + cost ceilings. record_canary_signal reads
    # both via ConfigRegistry and holds an active canary when the
    # observed drift score or observed per-turn cost breaches the
    # matching ceiling. A ceiling of 0.0 disables that half of the
    # gate (a signal on that axis never trips a hold). Drift is the
    # normalized confidence-drift score the RFC-07 tracker emits
    # (0.0 = flat, higher = worse); cost is USD per turn.
    agent_canary_drift_ceiling: float = 0.2
    agent_canary_cost_ceiling_usd: float = 5.0

    # RFC-10 canary minimum observed-signal count. promote_from_canary
    # blocks a candidate flip until at least this many drift + cost
    # samples have been recorded on the active canary assignment
    # (record_canary_signal bumps the counter on every call, whether
    # the signal was within ceilings or fired a hold). Default 5
    # enforces "no promotion on empty history" so a candidate that
    # never observed traffic cannot be promoted through an empty
    # signal chain; a value <= 0 disables the check. The promote()
    # eval + quorum gate still runs regardless.
    agent_canary_min_sample: int = 5

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

    # Reasoning / observable storage caps (platform-owned data structures).
    # Live under the platform namespace because ``CyberReasoningEngine`` and
    # the shared ``ToolExecutorHelpersBase`` are platform code; a module never
    # names these keys. Defaults preserve the pre-config-ification behaviour
    # (agent scratchpad ceiling 150, per-branch observables ceiling 400,
    # recall-pin working set 8) so an operator with no override sees no drift.
    # The caps only trim the LIVE case_state window -- the recall action
    # rehydrates evicted keys from the durable message history, so shrinking
    # them is safe.
    reasoning_max_agent_keys_total: int = 150
    reasoning_max_observables: int = 400
    reasoning_recall_pinned_max: int = 8

    # RFC-24 per-turn user-prompt token budget applied by
    # ``CyberReasoningEngine.build_user_prompt``. Sized against a 200K
    # context-window baseline (Claude 3.5 / 4.x) so that the assembled
    # user prompt, the caller's system prompt (typically 5-10K), the
    # tool-catalogue payload the LLM gateway may append, and the
    # completion (~8K) all fit without hitting the model window.
    # NEVER treated as unbounded: when a caller (VR / forensics /
    # malware) sets ``ReasoningPromptContext.context_budget_tokens`` to
    # 0 the engine resolves this cap and applies it, so removing the
    # historical render_case_model display caps cannot regress into an
    # unbounded prompt. Operator can widen or narrow via
    # ``PUT /config/platform/reasoning_context_budget_tokens`` without
    # a redeploy; a value <= 0 disables the safety net (the prompt
    # runs unbounded again) and is intended for tests only.
    reasoning_context_budget_tokens: int = 180_000

    # Age (in turns) at which a live hypothesis becomes stale and
    # ``CyberReasoningEngine.absorb`` writes the
    # ``_directive.stale_hypotheses`` observable naming the offending
    # ids so the agent resolves, rejects, or explicitly defers them
    # instead of letting them linger and block convergence. Read via
    # ``_resolve_platform_int`` (env AILA_PLATFORM_REASONING_HYP_STALE_TURNS
    # -> DB -> this default) so an operator override lands on the next
    # absorb without a worker restart. A value <= 0 disables the
    # directive (no staleness nudge) and matches the render-side
    # STALE age heuristic in ``render_case_model`` at 10; the default
    # here fires slightly earlier (8) so the directive nudges before
    # the render marker flips to STALE.
    reasoning_hyp_stale_turns: int = 8

    # #60 global SSE connection ceiling. The platform emits SSE from at
    # least seven endpoints (events, tasks, scans, sessions, forensics
    # investigation + readiness, vr investigation + messages, malware
    # messages). ACTIVE_SSE is a shared process-wide gauge tracking the
    # live count across all of them. When the observed count is at or
    # above this ceiling every new SSE-opening request short-circuits
    # with HTTP 503 + Retry-After -- preserving the ability of already
    # connected clients to keep streaming while stopping unbounded
    # connection growth from an infinite reconnect loop. Read once at
    # request time via ConfigRegistry.get_sync so an operator can
    # widen or narrow the ceiling with PUT /config/platform without a
    # restart. Value <= 0 disables the cap (unbounded) -- intended for
    # tests only.
    sse_max_connections: int = 500

    # Bounded retention for platform-owned tool storage tables (#56).
    # ``permanentmemoryrecord`` (backing ``PermanentMemoryTool`` +
    # ``DecisionCacheTool``) and ``artifactrecord`` (backing
    # ``ArtifactStoreTool``) both accumulate rows indefinitely because
    # every writer path uses upsert / append without an eviction pass.
    # A periodic pruner (``platform.tool_storage_prune``, registered by
    # ``aila.platform.automation.maintenance``) walks each table and
    # applies the age + per-scope row-count caps below. A value <= 0
    # on any knob disables that half of the prune (age-only, cap-only,
    # or fully disabled if both are zero) without a code change.
    #
    # Age caps compare against the row ``updated_at`` so a rewritten
    # entry (upsert of a cached decision, refresh of an artifact)
    # resets the clock. Row-count caps keep the newest N rows per
    # scope (namespace for memory, module_id for artifacts) and delete
    # the tail. Decision-cache entries already fail closed at read
    # against ``routing_decision_cache_ttl_hours`` above; the age cap
    # here is the actual eviction that turns those stale rows into
    # freed storage. Defaults are deliberately generous so an operator
    # that has never tuned retention sees no surprise data loss.
    tool_storage_memory_max_age_days: int = 90
    tool_storage_memory_max_rows_per_namespace: int = 10_000
    tool_storage_artifact_max_age_days: int = 180
    tool_storage_artifact_max_rows_per_module: int = 10_000

    # RFC-13 #68 dispatch-hub stall escalation window.
    # ``phase_graph.make_dispatch_router._handle_stall`` raises one
    # ``replan`` request per distinct visited-set the first time the hub
    # cannot activate any next phase. Within this window the branch simply
    # emits ``hub_stalled`` (existing behavior); if the earliest unratified
    # replan request has been sitting in the ledger for longer than
    # ``dispatch_replan_timeout_s`` seconds without a sibling ratifying it,
    # the hub emits the distinct ``hub_stalled_timeout`` exit_reason,
    # posts an operator-steering escalation via
    # ``post_dispatch_stall_escalation``, and the emit state flips the
    # investigation to ``InvestigationStatus.STALLED`` instead of silently
    # completing.
    #
    # Default of 1800s (30 minutes) is the point at which a panel that
    # has NOT gotten sibling quorum on a replan is almost certainly stuck
    # -- confirmed-trust chains take one or two full agent turns to
    # ratify, each capped at ~5-10 minutes by the phase timeout. Beyond
    # that we are wasting worker cycles and the operator needs to see it.
    # Operators can widen or narrow via
    # ``PUT /config/platform/dispatch_replan_timeout_s`` (or env
    # ``AILA_PLATFORM_DISPATCH_REPLAN_TIMEOUT_S``); a value <= 0 disables
    # the escalation entirely and keeps the pre-RFC-13-#68 behavior where
    # a stalled hub always emits ``hub_stalled`` -> COMPLETED.
    dispatch_replan_timeout_s: float = 1800.0

    # Issue #95, Wave 2 -- curiosity-driven lateral discovery LLM gate.
    # When True, ``aila.platform.agents.auto_steering`` runs one cheap
    # LLM call per audit_mcp source-surfacing tool result (after the
    # Wave-1 regex scan) that proposes additional lateral vulnerability
    # targets in the returned body; each proposal is appended to the
    # investigation ledger as a ``discovery`` entry with
    # ``source="lateral_llm"``, mirroring the Wave-1 posting shape.
    # Defaults False so the path is byte-identical to today's Wave-1-only
    # behavior; operator flips it on via ``PUT /config/platform/
    # vr_lateral_llm_enabled`` (env ``AILA_PLATFORM_VR_LATERAL_LLM_ENABLED``)
    # once the corpus of Wave-1 hits has been validated and the incremental
    # per-read LLM cost is worth paying. The model is resolved by the
    # standard LLM routing chain under task type
    # ``vulnerability_research.lateral_observation`` (schema-registered
    # via ``llm_model_vulnerability_research.lateral_observation`` when
    # an operator pins a specific model; falls back to the platform
    # default otherwise). Wave 3 (full explorer/planner persona split)
    # is intentionally out of scope for this flag and is tracked as a
    # separate follow-up in issue #95.
    vr_lateral_llm_enabled: bool = False

    # ------------------------------------------------------------------
    # Platform sandbox service (issue #147). See
    # ``aila.platform.services.sandbox`` for the executor implementation.
    #
    # The sandbox is a platform-owned, one-VM-per-run isolation primitive
    # every module reaches through ``SandboxService.run``. Backends run
    # over SSH on a Linux host (Firecracker needs KVM; nsjail needs the
    # nsjail binary). When no host is provisioned, callers see
    # ``SandboxUnavailableError`` -- there is no local un-isolated
    # fallback by design.
    #
    # sandbox_backend:
    #   ``none``          -- no backend; every ``run`` raises Unavailable.
    #   ``nsjail``        -- namespace + seccomp sandbox on the host.
    #   ``firecracker``   -- microVM (KVM required); needs rootfs + kernel.
    # sandbox_ssh_host / _user / _port:
    #   SSH target for the sandbox host. Empty ``sandbox_ssh_host`` also
    #   trips Unavailable so the operator cannot forget the wiring.
    # sandbox_default_timeout_s / _max_timeout_s:
    #   Service clamps every ``spec.timeout_s`` to ``max_timeout_s`` so
    #   an over-eager caller cannot ask for a multi-hour run.
    # sandbox_allow_network:
    #   Master switch. When False the service forces every ``spec.network``
    #   to False regardless of the caller's request.
    # sandbox_vcpu / _mem_mb:
    #   Per-run defaults when the caller left them at the SandboxSpec
    #   defaults (1 vCPU, 512 MiB). Callers that pass explicit non-default
    #   values are honoured up to the policy ceiling the backend enforces.
    # sandbox_output_max_bytes:
    #   Byte cap applied to stdout, stderr, and every collected output
    #   file. Hitting the cap sets ``SandboxResult.truncated = True``.
    # sandbox_nsjail_bin / _firecracker_bin / _jailer_bin:
    #   Binary names or absolute paths on the sandbox host. Resolved via
    #   ``command -v`` before every run; a missing binary raises
    #   ``SandboxExecutionError`` with an actionable message.
    # sandbox_rootfs_path / _kernel_path:
    #   Required for the Firecracker backend. Point at the ext4 rootfs
    #   image + Firecracker-compatible vmlinux on the sandbox host. The
    #   rootfs MUST implement the guest-runner contract documented in
    #   ``aila.platform.services.sandbox.backends.firecracker``.
    # ------------------------------------------------------------------
    # Trajectory-mined SFT/DPO corpus + LoRA fine-tune pipeline (issue #158).
    #
    # The nightly ``run_corpus_export`` platform task walks the last N
    # days of module outcome-review rows, reconstructs each CHOSEN
    # branch's turn history from platform_journal, and writes
    # ``sft.jsonl`` + ``dpo.jsonl`` + ``manifest.json`` to
    # ``corpus_output_dir``. The training script under
    # :mod:`aila.platform.eval.training.train_lora` consumes the same
    # files -- SFT then DPO then merge-and-unload -- behind the
    # ``[training]`` optional extra.
    #
    # corpus_output_dir:
    #   Absolute or project-relative directory the corpus files live
    #   in. Empty string resolves to ``<PROJECT_ROOT>/data/eval_corpus``
    #   -- the same ``data/`` tree ``secret_keyring_path`` claims by
    #   default, so a fresh install has a usable path with no operator
    #   setup.
    # corpus_modules:
    #   Comma-separated list of module ids whose outcome tables the
    #   builder should scan (``<module_id>_investigation_outcomes``).
    # corpus_min_turns:
    #   Drop CHOSEN branches with fewer recorded turns than this
    #   threshold. Typical fine-tune runs need a couple of turns of
    #   context to be useful; 2 is the smallest defensible floor.
    # corpus_max_field_chars:
    #   Per-message soft cap applied at record construction time so a
    #   single runaway tool result cannot dominate a SFT example.
    # corpus_sft_states:
    #   Outcome states treated as CHOSEN / expert. Rejected trajectories
    #   are always ``rejected`` (hard-coded on the DPO side).
    # training_base_model:
    #   HuggingFace model id the LoRA pipeline fine-tunes. Empty ->
    #   :mod:`aila.platform.eval.training.train_lora` refuses with a
    #   clear ValueError so a GPU host cannot silently pick a random
    #   base.
    # training_lora_r / _alpha / _dropout:
    #   Standard LoRA rank + alpha + dropout, wired straight into
    #   ``peft.LoraConfig`` on the SFT step and reused on the DPO step.
    # training_output_dir:
    #   Absolute or project-relative directory the merged checkpoint
    #   lands in. Empty -> ``<PROJECT_ROOT>/data/lora_out``.
    corpus_output_dir: str = ""
    corpus_modules: str = "vr,malware,forensics"
    corpus_min_turns: int = 2
    corpus_max_field_chars: int = 24_000
    corpus_sft_states: str = "approved,dispatched"
    training_base_model: str = ""
    training_lora_r: int = 32
    training_lora_alpha: int = 16
    training_lora_dropout: float = 0.05
    training_output_dir: str = ""

    sandbox_backend: str = "none"
    sandbox_ssh_host: str = ""
    sandbox_ssh_user: str = ""
    sandbox_ssh_port: int = 22
    sandbox_default_timeout_s: float = 30.0
    sandbox_max_timeout_s: float = 300.0
    sandbox_allow_network: bool = False
    sandbox_vcpu: int = 1
    sandbox_mem_mb: int = 512
    sandbox_output_max_bytes: int = 1_048_576
    sandbox_nsjail_bin: str = "nsjail"
    sandbox_firecracker_bin: str = "firecracker"
    sandbox_jailer_bin: str = "jailer"
    sandbox_rootfs_path: str = ""
    sandbox_kernel_path: str = ""

    # #159 part 1 -- MCP tool-description hash pin (supply-chain guard).
    # When True, the platform bridge refuses to serve a projected tool
    # catalogue whose sha256 differs from the first-sight pin,
    # raising :class:`aila.platform.mcp.tool_hash.ToolDescriptionMismatchError`
    # to the caller (prompt builder / tool_executor.registered_tools).
    # Default False emits a WARNING and rotates the pin so legitimate
    # rolling upgrades ("added new tool", "reworded description") do
    # not ground every worker until an operator intervenes. Flip to
    # True on hardened deployments where a poisoned tool description
    # is a higher-severity outcome than a five-minute deploy stall.
    mcp_tool_hash_strict: bool = False

