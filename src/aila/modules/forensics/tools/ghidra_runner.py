"""Ghidra headless analyzer runner -- executes decompilation/analysis over SSH.

Requires Ghidra to be installed on the analyzer machine. The Java analysis
scripts (``ExportDecompilation.java``, ``ListFunctions.java``,
``DecompileFunction.java``) are shipped with this module under
``scripts/ghidra/`` and are uploaded to the analyzer machine's temp
directory before execution if not already present.
"""
from __future__ import annotations

import logging

from aila.config import Settings
from aila.platform.tools import Tool

_log = logging.getLogger(__name__)

TOOL_ALIAS = "ghidra_runner"
CAPABILITY = "Run Ghidra headless analyzer for binary decompilation and function analysis via SSH."

__all__ = ["GhidraRunnerTool"]


class GhidraRunnerTool(Tool):
    """Execute Ghidra headless analysis on the analyzer machine."""

    name = "ghidra_runner"
    description = CAPABILITY
    inputs = {
        "action": {"type": "string", "description": "One of: analyze, decompile_function, list_functions."},
        "binary_path": {"type": "string", "description": "Path to binary on analyzer."},
        "function_name": {"type": "string", "description": "Function to decompile.", "nullable": True},
        "ghidra_project_dir": {"type": "string", "description": "Ghidra project directory.", "nullable": True},
        "integration": {"type": "object", "description": "SSH integration fields."},
    }
    output_type = "string"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def forward(
        self,
        action: str = "analyze",
        binary_path: str = "",
        function_name: str | None = None,
        ghidra_project_dir: str | None = None,
        integration: dict | None = None,
        analyzer_os: str = "linux",
    ) -> str:
        """Execute Ghidra headless analysis on the analyzer machine.

        Args:
            action: Analysis action to perform.
            binary_path: Path to the binary file.
            function_name: For decompile_function, the target function.
            ghidra_project_dir: Project directory for Ghidra analysis.
            integration: SSH connection fields.
            analyzer_os: Target OS -- ``"linux"`` or ``"windows"``.

        Returns:
            Analysis output as a string.
        """
        if not binary_path:
            raise ValueError("binary_path is required.")
        if not integration:
            raise ValueError("integration (SSH fields) is required.")

        from aila.modules.forensics.tools._ssh_helper import get_ssh_service, temp_dir

        default_proj = f"{temp_dir(analyzer_os)}\\ghidra_projects" if analyzer_os == "windows" else "/tmp/ghidra_projects"
        project_dir = ghidra_project_dir or default_proj
        project_name = "aila_forensics"
        # Use the stable install path from the readiness installer (C:\Tools\ghidra on
        # Windows, /opt/ghidra on Linux) rather than trusting PATH -- SSH sessions do not
        # refresh PATH after installs, and Ghidra's headless launcher is never on PATH
        # by default.
        if analyzer_os == "windows":
            headless = r'"C:\Tools\ghidra\support\analyzeHeadless.bat"'
        else:
            headless = "/opt/ghidra/support/analyzeHeadless"
        remote_script_dir = f"{temp_dir(analyzer_os)}\\aila_ghidra_scripts" if analyzer_os == "windows" else "/tmp/aila_ghidra_scripts"

        ssh = await get_ssh_service(self.settings)

        await _ensure_ghidra_scripts_uploaded(ssh, integration, remote_script_dir, analyzer_os)

        mkdir_cmd = (
            f'if not exist "{project_dir}" mkdir "{project_dir}"'
            if analyzer_os == "windows"
            else f"mkdir -p {project_dir}"
        )
        await ssh.run_command(integration, mkdir_cmd, timeout_seconds=10.0)

        if action == "analyze":
            cmd = (
                f"{headless} {project_dir} {project_name} "
                f"-import {binary_path} -overwrite -scriptPath {remote_script_dir} "
                f"-postScript ExportDecompilation.java"
            )
        elif action == "list_functions":
            cmd = (
                f"{headless} {project_dir} {project_name} "
                f"-import {binary_path} -overwrite -scriptPath {remote_script_dir} "
                f"-postScript ListFunctions.java"
            )
        elif action == "decompile_function":
            if not function_name:
                raise ValueError("function_name is required for decompile_function.")
            cmd = (
                f"{headless} {project_dir} {project_name} "
                f"-import {binary_path} -overwrite -scriptPath {remote_script_dir} "
                f"-postScript DecompileFunction.java {function_name}"
            )
        else:
            raise ValueError(f"Unknown ghidra action '{action}'.")

        return await ssh.run_command(integration, cmd, timeout_seconds=900.0)


_GHIDRA_SCRIPTS = (
    "ListFunctions.java",
    "ExportDecompilation.java",
    "ExportDecompilationJson.java",
    "DecompileFunction.java",
)


async def _ensure_ghidra_scripts_uploaded(
    ssh: object,
    integration: dict,
    remote_dir: str,
    analyzer_os: str,
) -> None:
    """Upload bundled Ghidra Java scripts to the analyzer machine if missing."""
    import pathlib

    local_scripts_dir = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "ghidra"

    mkdir_cmd = (
        f'if not exist "{remote_dir}" mkdir "{remote_dir}"'
        if analyzer_os == "windows"
        else f"mkdir -p {remote_dir}"
    )
    await ssh.run_command(integration, mkdir_cmd, timeout_seconds=10.0)  # type: ignore[attr-defined]

    sep = "\\" if analyzer_os == "windows" else "/"
    for script_name in _GHIDRA_SCRIPTS:
        local_path = local_scripts_dir / script_name
        if not local_path.exists():
            continue
        content = local_path.read_text(encoding="utf-8")
        remote_path = f"{remote_dir}{sep}{script_name}"

        if analyzer_os == "windows":
            escaped = content.replace('"', '`"').replace("\n", "`n")
            write_cmd = f'powershell -NoProfile -Command "Set-Content -Path \'{remote_path}\' -Value \\"{escaped}\\""'
        else:
            write_cmd = f"cat > {remote_path} << 'AILA_GHIDRA_EOF'\n{content}\nAILA_GHIDRA_EOF"

        try:
            await ssh.run_command(integration, write_cmd, timeout_seconds=15.0)  # type: ignore[attr-defined]
        except (OSError, TimeoutError, RuntimeError) as exc:
            _log.debug("Script upload failed for %s to %s: %s", script_name, remote_path, exc, exc_info=True)


def create_tool(settings: Settings) -> GhidraRunnerTool:
    """Construct a GhidraRunnerTool with the given settings."""
    return GhidraRunnerTool(settings)
