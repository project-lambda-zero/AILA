"""Machine readiness checker for VR analyzer workstations.

Verifies IDA Headless MCP reachability and probes research tooling
(gcc, gdb, pwntools, ...) over SSH. v0.1 reports only — no auto-install.
``integration=None`` skips SSH and checks MCP only (local workstation).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from aila.config import Settings
from aila.modules.vr.tools.ida_bridge import IDABridgeTool
from aila.platform.config import build_platform_settings
from aila.platform.exceptions import AILAError
from aila.platform.services import SSHService

__all__ = ["ToolCheckResult", "VRMachineReadinessService", "VRReadinessResult"]

_REQUIREMENTS_PATH = Path(__file__).parent.parent / "data" / "tool_requirements.json"
_OS_PROBE_TIMEOUT = 10.0
_TOOL_CHECK_TIMEOUT = 30.0
_OUTPUT_TRUNCATE = 300
_SSH_ERRORS = (OSError, TimeoutError, RuntimeError, AILAError)


class ToolCheckResult(BaseModel):
    name: str
    required: bool
    available: bool
    check_output: str = ""


class VRReadinessResult(BaseModel):
    all_required_ok: bool
    ida_mcp_reachable: bool
    tools: list[ToolCheckResult] = Field(default_factory=list)


def _load_requirements() -> dict[str, list[dict[str, Any]]]:
    return json.loads(_REQUIREMENTS_PATH.read_text(encoding="utf-8"))


class VRMachineReadinessService:
    """Verify IDA MCP + research tooling for the active VR workstation."""

    def __init__(self, ida_bridge: IDABridgeTool, settings: Settings) -> None:
        self._ida_bridge = ida_bridge
        self._settings = settings

    async def check(self, integration: dict | None = None) -> VRReadinessResult:
        mcp_ok = await self._check_mcp()
        if not integration:
            return VRReadinessResult(
                all_required_ok=mcp_ok, ida_mcp_reachable=mcp_ok, tools=[]
            )

        ssh = SSHService(build_platform_settings(self._settings))
        analyzer_os = await self._detect_os(ssh, integration)
        requirements = _load_requirements()
        tool_defs = requirements.get(analyzer_os) or requirements.get("linux", [])

        tool_results = [
            await self._check_tool(ssh, integration, td) for td in tool_defs
        ]
        required_ok = all(t.available for t in tool_results if t.required)
        return VRReadinessResult(
            all_required_ok=mcp_ok and required_ok,
            ida_mcp_reachable=mcp_ok,
            tools=tool_results,
        )

    async def _check_mcp(self) -> bool:
        result = await self._ida_bridge.health()
        return result.get("status") != "error"

    async def _detect_os(self, ssh: SSHService, integration: dict) -> str:
        try:
            out = await ssh.run_command(integration, "uname -s", timeout_seconds=_OS_PROBE_TIMEOUT)
            if "linux" in out.lower() or "darwin" in out.lower():
                return "linux"
        except _SSH_ERRORS:
            pass
        try:
            out = await ssh.run_command(integration, "ver", timeout_seconds=_OS_PROBE_TIMEOUT)
            if "windows" in out.lower():
                return "windows"
        except _SSH_ERRORS:
            pass
        return "linux"

    async def _check_tool(self, ssh: SSHService, integration: dict, tool_def: dict[str, Any]) -> ToolCheckResult:
        name = str(tool_def["name"])
        required = bool(tool_def.get("required", False))
        check_cmd = str(tool_def["check"])
        try:
            output = await ssh.run_command(integration, check_cmd, timeout_seconds=_TOOL_CHECK_TIMEOUT)
            stripped = output.strip()
            head = stripped.splitlines()[0] if stripped else ""
            return ToolCheckResult(
                name=name, required=required, available=True,
                check_output=head[:_OUTPUT_TRUNCATE],
            )
        except _SSH_ERRORS as exc:
            return ToolCheckResult(
                name=name, required=required, available=False,
                check_output=str(exc)[:_OUTPUT_TRUNCATE],
            )
