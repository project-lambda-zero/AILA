"""Analyzer machine readiness contract models."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "MachineReadinessResult",
    "ToolCheckResult",
]


class ToolCheckResult(BaseModel):
    """Status of a single tool on the analyzer machine."""

    model_config = ConfigDict(extra="forbid")

    tool_name: str
    required: bool = True
    status: str = Field(
        description=(
            "One of: installed, missing, install_failed, skipped, "
            "installed_online, installed_offline."
        ),
    )
    version: str | None = None
    message: str | None = None
    install_method: str | None = Field(
        default=None,
        description="How the tool was installed: online, offline_pip, offline_apt, offline_bundle, pre_installed.",
    )


class MachineReadinessResult(BaseModel):
    """Overall readiness status of the analyzer machine."""

    model_config = ConfigDict(extra="forbid")

    ready: bool
    system_id: int
    system_name: str
    analyzer_os: str = "linux"
    tools: list[ToolCheckResult] = Field(default_factory=list)
    message: str = ""
