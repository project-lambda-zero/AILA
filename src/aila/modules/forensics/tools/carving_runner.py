"""File carving and embedded content extraction runner -- over SSH.

Supports binwalk (firmware/binary analysis), foremost (file carving from
raw images), and bulk_extractor (PII/credential/IOC extraction).
"""
from __future__ import annotations

from aila.config import Settings
from aila.platform.tools._common import Tool

TOOL_ALIAS = "carving_runner"
CAPABILITY = (
    "Extract embedded files, carve data from images, and bulk-extract IOCs/credentials "
    "using binwalk, foremost, and bulk_extractor via SSH."
)

__all__ = ["CarvingRunnerTool"]


class CarvingRunnerTool(Tool):
    """Execute file carving and extraction on the analyzer machine."""

    name = "carving_runner"
    description = CAPABILITY
    inputs = {
        "action": {"type": "string", "description": "One of: binwalk_scan, binwalk_extract, foremost, bulk_extractor."},
        "file_path": {"type": "string", "description": "Path to target file on analyzer."},
        "output_dir": {"type": "string", "description": "Output directory for extracted files.", "nullable": True},
        "extra_args": {"type": "string", "description": "Additional arguments.", "nullable": True},
        "integration": {"type": "object", "description": "SSH integration fields."},
    }
    output_type = "string"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def forward(
        self,
        action: str = "binwalk_scan",
        file_path: str = "",
        output_dir: str | None = None,
        extra_args: str | None = None,
        integration: dict | None = None,
        analyzer_os: str = "linux",
    ) -> str:
        if not file_path:
            raise ValueError("file_path is required.")
        if not integration:
            raise ValueError("integration (SSH fields) is required.")

        from aila.modules.forensics.tools._ssh_helper import get_ssh_service, temp_dir

        out = output_dir or f"{temp_dir(analyzer_os)}/carved_output"

        if analyzer_os == "windows":
            q = f'"{file_path}"'
        else:
            q = file_path

        cmd_map: dict[str, str] = {
            "binwalk_scan": f"binwalk {q}",
            "binwalk_extract": f"binwalk -e -C {out} {q}",
            "foremost": f"foremost -i {q} -o {out}",
            "bulk_extractor": f"bulk_extractor -o {out} {q}",
        }

        if action not in cmd_map:
            raise ValueError(f"Unknown carving action '{action}'. Supported: {', '.join(cmd_map)}.")

        cmd = cmd_map[action]
        if extra_args:
            cmd += f" {extra_args}"

        ssh = await get_ssh_service(self.settings)
        return await ssh.run_command(integration, cmd, timeout_seconds=900.0)


def create_tool(settings: Settings) -> CarvingRunnerTool:
    """Construct a CarvingRunnerTool with the given settings."""
    return CarvingRunnerTool(settings)
