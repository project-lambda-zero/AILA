"""Agent-generated script executor -- uploads and runs Python scripts over SSH."""
from __future__ import annotations

import hashlib
import os
import tempfile

from aila.config import Settings
from aila.platform.exceptions import AILAError
from aila.platform.tools import Tool

TOOL_ALIAS = "script_executor"
CAPABILITY = "Upload and execute agent-generated Python scripts on the analyzer machine via SSH."

__all__ = ["ScriptExecutorTool"]


class ScriptExecutorTool(Tool):
    """Upload a Python script to the analyzer machine and execute it."""

    name = "script_executor"
    description = CAPABILITY
    inputs = {
        "script_content": {"type": "string", "description": "Python script source code to execute."},
        "working_directory": {"type": "string", "description": "Working directory on the analyzer.", "nullable": True},
        "timeout_seconds": {"type": "number", "description": "Execution timeout.", "nullable": True},
        "integration": {"type": "object", "description": "SSH integration fields."},
        "analyzer_os": {"type": "string", "description": "Target OS: linux or windows.", "nullable": True},
    }
    output_type = "object"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def forward(
        self,
        script_content: str = "",
        working_directory: str | None = None,
        timeout_seconds: float | None = None,
        integration: dict | None = None,
        analyzer_os: str = "linux",
    ) -> dict:
        """Upload and execute a Python script on the analyzer machine.

        The script body is uploaded via SFTP (so it is never passed on a
        command line and never hits the Windows 8191-char cmd.exe limit).
        Temp paths and Python invocation adapt to the target OS.

        Args:
            script_content: Python source code to execute.
            working_directory: Optional cwd for execution.
            timeout_seconds: Optional execution timeout.
            integration: SSH connection fields.
            analyzer_os: Target OS -- ``"linux"`` or ``"windows"``.

        Returns:
            Dict with 'stdout', 'stderr', 'exit_code', 'script_hash'. The
            ``exit_code`` is the real remote exit status; a script that
            calls ``sys.exit(3)`` yields ``exit_code=3`` (previously the
            success branch hard-coded ``0`` and the failure branch
            hard-coded ``1``).

        Raises:
            AILAError: Connection-level failures propagate --
                :class:`aila.platform.exceptions.AuthenticationError` for
                credential rejection, :class:`UpstreamError` for host-key
                or transport failures, and the platform
                :class:`TimeoutError` for an idle command. These mean
                "the script never ran", not "the script exited nonzero",
                so surfacing them lets the caller emit the right 4xx/5xx
                mapping instead of a fake ``exit_code=1``.
        """
        if not script_content.strip():
            raise ValueError("script_content must be non-empty.")
        if not integration:
            raise ValueError("integration (SSH fields) is required.")

        from aila.modules.forensics.tools._ssh_helper import get_ssh_service, python_cmd

        script_hash = hashlib.sha256(script_content.encode()).hexdigest()[:16]
        py = python_cmd(analyzer_os)

        if analyzer_os == "windows":
            # Resolve %TEMP% up-front. Leaving the env var in the path
            # forces us to quote through cmd.exe for every subsequent
            # command; resolving it once keeps invocations literal.
            ssh = await get_ssh_service(self.settings)
            temp_dir_raw = await ssh.run_command(
                integration, "echo %TEMP%", timeout_seconds=10.0,
            )
            temp_dir = temp_dir_raw.strip().splitlines()[-1].strip() if temp_dir_raw.strip() else "C:\\Windows\\Temp"
            remote_path = f"{temp_dir}\\aila_forensics_{script_hash}.py"
            exec_cmd = f'{py} "{remote_path}"'
            if working_directory:
                exec_cmd = f'cd /d "{working_directory}" && {exec_cmd}'
            cleanup_cmd = f'del /f /q "{remote_path}" 2>nul'
        else:
            remote_path = f"/tmp/aila_forensics_{script_hash}.py"
            exec_cmd = f"{py} {remote_path}"
            if working_directory:
                exec_cmd = f"cd {working_directory} && {exec_cmd}"
            cleanup_cmd = f"rm -f {remote_path}"
            ssh = await get_ssh_service(self.settings)

        effective_timeout = timeout_seconds or 600.0

        # Upload the script via SFTP. This avoids the cmd.exe 8191-char
        # command-line limit on Windows -- previously we base64-encoded
        # the script into a single ``powershell -Command "..."`` string
        # which blew past the limit for scripts > ~5 KB and failed with
        # "The command line is too long."
        fd, local_tmp = tempfile.mkstemp(prefix="aila_script_", suffix=".py")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(script_content)
            await ssh.upload_file(
                integration, local_tmp, remote_path, timeout_seconds=60.0,
            )
        finally:
            try:
                os.unlink(local_tmp)
            except OSError:
                pass

        # Use run_command_full so a non-zero remote exit surfaces through
        # the returned triple instead of being converted to UpstreamError.
        # The prior ``run_command`` path unconditionally reported
        # ``exit_code=0`` on the success branch and mapped any raised
        # exception (including the UpstreamError that ``run_command``
        # itself raises on non-zero exit) to ``exit_code=1`` with a
        # generic string, so a script that ran and exited ``sys.exit(3)``
        # was indistinguishable from clean success in file_retriever's
        # ``exit_code != 0`` guard.
        #
        # Connection-level failures (AuthenticationError, UpstreamError,
        # platform TimeoutError) now propagate to the caller by design --
        # they mean "the script never ran", not "the script exited
        # nonzero", and the callers (investigator._execute_script,
        # file_retriever._run_script_and_pull) surface them as 5xx.
        try:
            stdout, stderr, exit_code = await ssh.run_command_full(
                integration, exec_cmd, timeout_seconds=effective_timeout,
            )
            return {
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "script_hash": script_hash,
            }
        finally:
            # Cleanup must not mask a real failure from the run above.
            # Broaden the swallowed set to include AILAError (which
            # covers UpstreamError from a cleanup non-zero exit and
            # AuthenticationError if the connection went away between
            # calls) so a finally-branch exception cannot suppress an
            # AuthenticationError or UpstreamError produced by
            # run_command_full.
            try:
                await ssh.run_command(integration, cleanup_cmd, timeout_seconds=10.0)
            except (OSError, TimeoutError, ConnectionError, RuntimeError, AILAError):
                import logging as _logging
                _logging.getLogger(__name__).debug("Script cleanup failed for %s", remote_path, exc_info=True)


def create_tool(settings: Settings) -> ScriptExecutorTool:
    """Construct a ScriptExecutorTool with the given settings."""
    return ScriptExecutorTool(settings)
