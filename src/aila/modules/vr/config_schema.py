"""Configuration schema for the VR (vulnerability research) module.

Registered with ConfigRegistry under the ``vr`` namespace.
Operators can tune these values via PUT /config without code changes.

NOTE: These defaults are used as fallbacks. Per-request overrides on the
API layer take priority when explicitly set. Timeout values here define
the upper bounds for PoC execution and SSH operations on remote analysis
hosts. Changing config at runtime does NOT hot-reload into running
workflows; only new workflow runs pick up updated values.
"""
from __future__ import annotations

from pydantic import Field

from aila.platform.config_base import ModuleConfigBase

__all__ = ["VRConfigSchema", "VR_DEFAULTS"]


VR_LLM_MODEL = "antigravity/claude-opus-4-6-thinking"


class VRConfigSchema(ModuleConfigBase):
    """Operator-tunable settings for the VR module."""

    llm_model: str = Field(
        default=VR_LLM_MODEL,
        description=(
            "LLM model for all VR agents (n-day, patch-diff, advisory, triage). "
            "Set to empty string to fall back to the platform default."
        ),
    )
    nday_max_turns: int = Field(
        default=30,
        ge=5,
        le=100,
        description="Maximum agent turns per N-day PoC investigation loop.",
    )
    nday_tool_time_seconds: float = Field(
        default=14400.0,
        ge=300.0,
        description=(
            "Wall-clock budget for the N-day agent's tool-use phase, in seconds. "
            "Default 4 hours accommodates long IDA analysis and PoC iteration."
        ),
    )
    poc_max_attempts: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum PoC build/run iterations before giving up.",
    )
    poc_reliability_target: str = Field(
        default="5/5",
        description=(
            "Required PoC reliability ratio (successful_runs/total_runs) before "
            "the PoC is considered acceptance-ready."
        ),
    )
    poc_timeout_seconds: float = Field(
        default=30.0,
        ge=5.0,
        le=300.0,
        description="Per-execution timeout for PoC binary runs.",
    )
    poc_memory_limit_mb: int = Field(
        default=2048,
        ge=256,
        le=16384,
        description="Memory cap for sandboxed PoC execution, in megabytes.",
    )
    ssh_command_timeout_seconds: float = Field(
        default=300.0,
        ge=10.0,
        description="Timeout for individual SSH commands on remote analysis hosts.",
    )
    audit_mcp_url: str = Field(
        default="http://127.0.0.1:18822",
        description=(
            "Base URL for the audit-mcp source-code MCP server. The platform "
            "delegates ALL clone/index/graph work to this server (D-33). Point "
            "at a dedicated Linux workstation for production."
        ),
    )
    ida_headless_url: str = Field(
        default="http://127.0.0.1:18821",
        description=(
            "Base URL for the IDA headless MCP server. The platform delegates "
            "ALL binary upload/analysis to this server (D-33). Point at the "
            "workstation that owns the IDA license + GPU."
        ),
    )
    android_mcp_url: str = Field(
        default="http://127.0.0.1:18823",
        description=(
            "Base URL for the android-mcp Android APK audit server. The "
            "platform delegates ALL apktool/jadx/androguard/MobSF work to "
            "this server (D-33). Point at the workstation that owns the "
            "Android SDK build-tools + MobSF instance."
        ),
    )

    # Investigation lifecycle caps (operator-tunable). Previously read
    # via VR_* env vars scattered across branch_manager / claim_verifier /
    # parent_reconciler / investigation_finalizers / target_analysis /
    # investigation_loop; those reads ignored PUT /config overrides.
    max_branches_per_investigation: int = Field(
        default=24,
        ge=1,
        le=256,
        description=(
            "Per-investigation ACTIVE-branch cap. Enforced inside the fork "
            "UoW so concurrent forks racing on the same investigation see "
            "each other's inserts. 24 = 6 personas * 4 fork generations."
        ),
    )
    claim_verifier_auto_promote_floor: float = Field(
        default=0.70,
        ge=0.0,
        le=1.0,
        description=(
            "Confidence floor for auto-promoting a verifier-confirmed "
            "ASSESSMENT_REPORT to DIRECT_FINDING. 0.70 matches the "
            "synthesis pipeline's medium/high threshold."
        ),
    )
    investigation_total_turn_cap: int = Field(
        default=200,
        ge=50,
        description=(
            "Total turn cap per audit child investigation (sum across "
            "branches). Children whose sum exceeds this are force-closed "
            "by the parent reconciler."
        ),
    )
    zombie_task_heartbeat_min: int = Field(
        default=10,
        ge=1,
        description=(
            "Minutes of missed heartbeat before a running vr-track task is "
            "reaped as a zombie by parent_reconciler."
        ),
    )
    cursor_cleanup_batch: int = Field(
        default=5000,
        ge=1,
        description=(
            "Max workflow_state_cursor rows deleted per reaper tick "
            "(parent_reconciler cleanup batch cap)."
        ),
    )
    stale_branch_frozen_min: int = Field(
        default=30,
        ge=1,
        description=(
            "Minutes of inactivity before an ACTIVE branch with "
            "turn_count < 5 is abandoned as dead-from-birth."
        ),
    )
    stale_branch_halted_min: int = Field(
        default=120,
        ge=1,
        description=(
            "Minutes of inactivity before an ACTIVE branch with "
            "turn_count >= 5 is abandoned as halted mid-run."
        ),
    )
    ingestion_poll_timeout_s: float = Field(
        default=14400.0,
        ge=60.0,
        description=(
            "Wall-clock timeout for ingestion polling (IDA analysis + "
            "audit_mcp index build). Default 4h fits chromium / firefox / "
            "large monorepos; smaller targets finish long before."
        ),
    )
    max_turns_per_task: int = Field(
        default=70,
        ge=1,
        description=(
            "Per-ARQ-task turn budget for state_investigation_loop. Loop "
            "returns on this cap; investigation_emit re-enqueues another "
            "task until the investigation-level turn cap is reached."
        ),
    )

    # --- Cap-exceeded reaper (operator-tunable) --------------------------
    # The four caps below drive aila.modules.vr.services.investigation_reaper
    # (which now routes through ConfigRegistry so PUT /config overrides land
    # on the next tick without a worker restart). The prior code read raw
    # VR_* env vars and ignored operator overrides; those names are
    # retired, replaced by the standard AILA_VR_<KEY> env form.
    overall_turn_cap: int = Field(
        default=500,
        ge=10,
        le=10000,
        description=(
            "Per-branch cap on cumulative turns across task boundaries. "
            "The emit auto-continue stops re-enqueuing a branch once its "
            "turn_count reaches this. Read live via ConfigRegistry "
            "(env AILA_VR_OVERALL_TURN_CAP -> DB -> this default), "
            "replacing the retired module-load VR_OVERALL_TURN_CAP env."
        ),
    )
    investigation_turn_cap: int = Field(
        default=300,
        ge=10,
        le=10000,
        description=(
            "Investigation-wide cap on cumulative reasoning turns "
            "(sum across branches). Trips the cap-exceeded path in the "
            "periodic reaper + workflow finalize chokepoint."
        ),
    )
    investigation_message_cap: int = Field(
        default=1000,
        ge=10,
        le=100000,
        description=(
            "Investigation-wide hard cap on messages emitted across all "
            "branches. Trips the cap-exceeded path in workflow finalize."
        ),
    )
    investigation_wall_clock_hours: float = Field(
        default=6.0,
        ge=0.5,
        le=72.0,
        description=(
            "Investigation-wide wall-clock budget in hours before the "
            "finalize chokepoint flips the investigation to a cap-exceeded "
            "terminal."
        ),
    )
    wall_clock_idle_grace_s: float = Field(
        default=900.0,
        ge=30.0,
        le=86400.0,
        description=(
            "Idle-grace window in seconds the finalize chokepoint waits "
            "after the wall-clock cap is hit before terminating, so an "
            "investigation that is actively producing work doesn't get "
            "killed for a slow turn."
        ),
    )


VR_DEFAULTS = VRConfigSchema()
