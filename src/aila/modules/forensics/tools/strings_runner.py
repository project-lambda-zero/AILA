"""Strings, FLOSS, and capa malware analysis runner -- over SSH."""
from __future__ import annotations

from aila.config import Settings
from aila.platform.tools._common import Tool

TOOL_ALIAS = "strings_runner"
CAPABILITY = "Run strings, FLOSS (obfuscated string extraction), and capa (capability detection) via SSH."

__all__ = ["StringsRunnerTool"]


class StringsRunnerTool(Tool):
    """Execute strings/FLOSS/capa commands on the analyzer machine."""

    name = "strings_runner"
    description = CAPABILITY
    inputs = {
        "action": {"type": "string", "description": "One of: strings, floss, capa."},
        "file_path": {"type": "string", "description": "Path to binary/file on analyzer."},
        "extra_args": {"type": "string", "description": "Additional arguments.", "nullable": True},
        "integration": {"type": "object", "description": "SSH integration fields."},
    }
    output_type = "string"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def forward(
        self,
        action: str = "strings",
        file_path: str = "",
        extra_args: str | None = None,
        integration: dict | None = None,
        analyzer_os: str = "linux",
    ) -> str:
        """Execute a strings/FLOSS/capa command on the analyzer machine.

        Args:
            action: Tool to run (strings, floss, or capa).
            file_path: Target file path on the analyzer.
            extra_args: Additional command-line arguments.
            integration: SSH connection fields.
            analyzer_os: Target OS -- ``"linux"`` or ``"windows"``.

        Returns:
            Command stdout as a string.
        """
        if not file_path:
            raise ValueError("file_path is required.")
        if not integration:
            raise ValueError("integration (SSH fields) is required.")

        if analyzer_os == "windows":
            exe = {"strings": "strings.exe", "floss": "floss.exe", "capa": "capa.exe"}
            cmd_map = {
                "strings": f'{exe["strings"]} "{file_path}"',
                "floss": f'{exe["floss"]} "{file_path}"',
                "capa": f'{exe["capa"]} "{file_path}"',
            }
        else:
            cmd_map = {
                "strings": f"strings {file_path}",
                "floss": f"floss {file_path}",
                "capa": f"capa {file_path}",
            }
        if action not in cmd_map:
            raise ValueError(f"Unknown action '{action}'. Supported: {', '.join(cmd_map)}.")

        cmd = cmd_map[action]
        if extra_args:
            cmd += f" {extra_args}"

        from aila.modules.forensics.tools._ssh_helper import get_ssh_service

        ssh = await get_ssh_service(self.settings)
        return await ssh.run_command(integration, cmd, timeout_seconds=300.0)


def create_tool(settings: Settings) -> StringsRunnerTool:
    """Construct a StringsRunnerTool with the given settings."""
    return StringsRunnerTool(settings)
