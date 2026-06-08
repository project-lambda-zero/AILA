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

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["VRConfigSchema", "VR_DEFAULTS"]


VR_LLM_MODEL = "antigravity/claude-opus-4-6-thinking"


class VRConfigSchema(BaseModel):
    """Operator-tunable settings for the VR module."""

    model_config = ConfigDict(extra="forbid")

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


VR_DEFAULTS = VRConfigSchema()
