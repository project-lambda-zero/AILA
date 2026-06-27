"""Dissect forensic framework runner -- executes dissect commands over SSH."""
from __future__ import annotations

from aila.config import Settings
from aila.platform.tools._common import Tool

TOOL_ALIAS = "dissect_runner"
CAPABILITY = "Run Dissect target-info, target-query, and target-fs commands on evidence via SSH."

__all__ = ["DissectRunnerTool"]


class DissectRunnerTool(Tool):
    """Execute Dissect framework commands on the analyzer machine."""

    name = "dissect_runner"
    description = CAPABILITY
    inputs = {
        "action": {"type": "string", "description": "One of: target_info, target_query, target_fs."},
        "evidence_path": {"type": "string", "description": "Path to disk image or target on analyzer."},
        "query_function": {"type": "string", "description": "Dissect query function name.", "nullable": True},
        "integration": {"type": "object", "description": "SSH integration fields."},
    }
    output_type = "string"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def forward(
        self,
        action: str = "target_info",
        evidence_path: str = "",
        query_function: str | None = None,
        integration: dict | None = None,
        analyzer_os: str = "linux",
    ) -> str:
        """Execute a Dissect command on the analyzer machine via SSH.

        Args:
            action: Dissect subcommand to run.
            evidence_path: Path to the evidence file on the analyzer.
            query_function: For target_query, the Dissect function name.
            integration: SSH connection fields.
            analyzer_os: Target OS -- ``"linux"`` or ``"windows"``.

        Returns:
            Command stdout as a string.
        """
        if not evidence_path:
            raise ValueError("evidence_path is required.")
        if not integration:
            raise ValueError("integration (SSH fields) is required.")

        from aila.modules.forensics.tools._ssh_helper import get_ssh_service, python_cmd

        py = python_cmd(analyzer_os)
        cmd_map = {
            "target_info": f"{py} -m dissect.target.tools.info {evidence_path}",
            "target_query": f"{py} -m dissect.target.tools.query -f {query_function or 'hostname'} {evidence_path}",
            "target_fs": f"{py} -m dissect.target.tools.fs {evidence_path}",
        }
        if action not in cmd_map:
            raise ValueError(f"Unknown dissect action '{action}'. Supported: {', '.join(cmd_map)}.")

        ssh = await get_ssh_service(self.settings)
        return await ssh.run_command(integration, cmd_map[action], timeout_seconds=300.0)


def create_tool(settings: Settings) -> DissectRunnerTool:
    """Construct a DissectRunnerTool with the given settings."""
    return DissectRunnerTool(settings)
