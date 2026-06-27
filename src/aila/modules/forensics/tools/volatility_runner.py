"""Volatility 3 memory analysis runner -- executes vol commands over SSH."""
from __future__ import annotations

from aila.config import Settings
from aila.platform.tools._common import Tool

TOOL_ALIAS = "volatility_runner"
CAPABILITY = "Run Volatility 3 plugins (pslist, netscan, cmdline, malfind, etc.) on memory dumps via SSH."

__all__ = ["VolatilityRunnerTool"]


class VolatilityRunnerTool(Tool):
    """Execute Volatility 3 plugins on the analyzer machine."""

    name = "volatility_runner"
    description = CAPABILITY
    inputs = {
        "plugin": {"type": "string", "description": "Volatility plugin name (e.g. windows.pslist, linux.pslist)."},
        "evidence_path": {"type": "string", "description": "Path to memory dump on analyzer."},
        "extra_args": {"type": "string", "description": "Additional plugin arguments.", "nullable": True},
        "integration": {"type": "object", "description": "SSH integration fields."},
    }
    output_type = "string"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def forward(
        self,
        plugin: str = "windows.pslist",
        evidence_path: str = "",
        extra_args: str | None = None,
        integration: dict | None = None,
        analyzer_os: str = "linux",
    ) -> str:
        """Execute a Volatility 3 plugin on the analyzer machine via SSH.

        Args:
            plugin: Volatility plugin name.
            evidence_path: Path to the memory dump on the analyzer.
            extra_args: Additional command-line arguments for the plugin.
            integration: SSH connection fields.
            analyzer_os: Target OS -- ``"linux"`` or ``"windows"``.

        Returns:
            Plugin stdout as a string.
        """
        if not evidence_path:
            raise ValueError("evidence_path is required.")
        if not integration:
            raise ValueError("integration (SSH fields) is required.")

        # Rewrite sys.argv[0] to 'vol' so Vol3's argparse displays a
        # sane prog name and we avoid every PATH / module / quoting
        # collision (see collectors/_helpers.py::vol_cmd for the full
        # rationale).
        snippet = (
            "import sys;sys.argv=['vol']+sys.argv[1:];"
            "from volatility3.cli import main;main()"
        )
        if analyzer_os == "windows":
            cmd = f'python -c "{snippet}" -f "{evidence_path}" {plugin}'
        else:
            cmd = f"python3 -c \"{snippet}\" -f {evidence_path} {plugin}"
        if extra_args:
            cmd += f" {extra_args}"

        from aila.modules.forensics.tools._ssh_helper import get_ssh_service

        ssh = await get_ssh_service(self.settings)
        return await ssh.run_command(integration, cmd, timeout_seconds=600.0)


def create_tool(settings: Settings) -> VolatilityRunnerTool:
    """Construct a VolatilityRunnerTool with the given settings."""
    return VolatilityRunnerTool(settings)
