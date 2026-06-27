"""YARA rule scanner -- executes yara scans over SSH."""
from __future__ import annotations

from aila.config import Settings
from aila.platform.tools._common import Tool

TOOL_ALIAS = "yara_runner"
CAPABILITY = (
    "Run YARA rules against files and directories for malware signature matching, "
    "IOC detection, and threat classification via SSH."
)

__all__ = ["YaraRunnerTool"]


class YaraRunnerTool(Tool):
    """Execute YARA scans on the analyzer machine."""

    name = "yara_runner"
    description = CAPABILITY
    inputs = {
        "action": {"type": "string", "description": "One of: scan, compile, match_tags."},
        "rules_path": {"type": "string", "description": "Path to .yar rules file or rules directory."},
        "target_path": {"type": "string", "description": "File or directory to scan."},
        "tags": {"type": "string", "description": "Comma-separated tag filter for match_tags.", "nullable": True},
        "extra_args": {"type": "string", "description": "Additional yara arguments.", "nullable": True},
        "integration": {"type": "object", "description": "SSH integration fields."},
    }
    output_type = "string"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def forward(
        self,
        action: str = "scan",
        rules_path: str = "",
        target_path: str = "",
        tags: str | None = None,
        extra_args: str | None = None,
        integration: dict | None = None,
        analyzer_os: str = "linux",
    ) -> str:
        if not rules_path or not target_path:
            raise ValueError("Both rules_path and target_path are required.")
        if not integration:
            raise ValueError("integration (SSH fields) is required.")

        yara_bin = "yara64.exe" if analyzer_os == "windows" else "yara"

        if action == "scan":
            cmd = f"{yara_bin} -s -m {rules_path} {target_path}"
        elif action == "compile":
            yarac_bin = "yarac64.exe" if analyzer_os == "windows" else "yarac"
            compiled = target_path.rsplit(".", 1)[0] + ".yarc"
            cmd = f"{yarac_bin} {rules_path} {compiled}"
        elif action == "match_tags" and tags:
            cmd = f"{yara_bin} -s -m -t {tags} {rules_path} {target_path}"
        else:
            raise ValueError(f"Unknown yara action '{action}'. Supported: scan, compile, match_tags.")

        if extra_args:
            cmd += f" {extra_args}"

        from aila.modules.forensics.tools._ssh_helper import get_ssh_service

        ssh = await get_ssh_service(self.settings)
        return await ssh.run_command(integration, cmd, timeout_seconds=600.0)


def create_tool(settings: Settings) -> YaraRunnerTool:
    """Construct a YaraRunnerTool with the given settings."""
    return YaraRunnerTool(settings)
