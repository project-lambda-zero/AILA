"""Configuration schema for the forensics module.

Registered with ConfigRegistry under the ``forensics`` namespace.
Operators can tune these values via PUT /config without code changes.

NOTE: These defaults are used as fallbacks. The API-layer ``max_attempts``
parameter on InvestigationRequest takes priority when explicitly set.
The timeout values here define the upper bounds for SSH and collection
operations — the workflow states in definitions.py reference these same
defaults. Changing config at runtime does NOT hot-reload into running
workflows, only new workflow runs pick up updated values.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["ForensicsConfigSchema", "FORENSICS_DEFAULTS"]


FORENSICS_LLM_MODEL = "antigravity/claude-opus-4-6-thinking"


class ForensicsConfigSchema(BaseModel):
    """Operator-tunable settings for the forensics module."""

    model_config = ConfigDict(extra="forbid")

    llm_model: str = Field(
        default=FORENSICS_LLM_MODEL,
        description=(
            "LLM model for all forensics agents (freeflow, resolver, writeup, network). "
            "Set to empty string to fall back to the platform default."
        ),
    )
    freeflow_max_attempts: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum script execution attempts per free-flow investigation.",
    )
    ssh_command_timeout_seconds: float = Field(
        default=300.0,
        ge=10.0,
        description="Timeout for individual SSH commands on the analyzer machine.",
    )
    script_execution_timeout_seconds: float = Field(
        default=600.0,
        ge=30.0,
        description="Timeout for agent-generated script execution.",
    )
    collection_timeout_seconds: float = Field(
        default=3600.0,
        ge=60.0,
        description="Timeout for the full artifact collection pipeline.",
    )


FORENSICS_DEFAULTS = ForensicsConfigSchema()
