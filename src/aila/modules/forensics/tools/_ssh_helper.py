"""Shared SSH service factory and OS-aware helpers for forensics tool runners."""
from __future__ import annotations

import os
import tempfile
import uuid
from typing import Any

from aila.config import Settings
from aila.platform.config import build_platform_settings
from aila.platform.exceptions import AILAError
from aila.platform.services.ssh import SSHService

__all__ = [
    "get_ssh_service", "python_cmd", "temp_dir", "path_sep", "hash_cmd",
    "run_command_via_file",
]


async def get_ssh_service(settings: Settings) -> SSHService:
    """Return an SSHService bound to the given settings.

    SSHService is stateless (each run_command opens/closes a connection),
    so we construct a fresh instance on each call. Any caching or pooling
    belongs inside the platform SSHService, not at the module boundary.
    """
    platform_settings = build_platform_settings(settings)
    return SSHService(platform_settings)


def python_cmd(analyzer_os: str) -> str:
    """Return the Python interpreter command for the target OS."""
    return "python" if analyzer_os == "windows" else "python3"


def temp_dir(analyzer_os: str) -> str:
    """Return the temp directory path for the target OS."""
    return "%TEMP%" if analyzer_os == "windows" else "/tmp"


def path_sep(analyzer_os: str) -> str:
    """Return the path separator for the target OS."""
    return "\\" if analyzer_os == "windows" else "/"


def hash_cmd(file_path: str, analyzer_os: str) -> str:
    """Return a SHA-256 hash command for the target OS."""
    if analyzer_os == "windows":
        return f'certutil -hashfile "{file_path}" SHA256'
    return f"sha256sum -- {_posix_quote(file_path)}"


def _posix_quote(s: str) -> str:
    """Shell-escape a string for POSIX sh (like shlex.quote)."""
    import shlex
    return shlex.quote(s)


async def run_command_via_file(
    ssh: SSHService,
    integration: Any,
    command: str,
    analyzer_os: str,
    timeout_seconds: float | None = 300.0,
) -> str:
    """Run ``command`` on the analyzer with stdout redirected to a remote temp file,
    then SFTP the file back and return its contents as a UTF-8 string.

    Bypasses the ~2 MB paramiko stdout-window deadlock that happens when a
    remote command (dissect on a big disk, vol plugin on a large dump) writes
    more than the channel can buffer before the reader drains it. Writing to
    a file on the analyzer + SFTP download uses proper flow control and can
    transfer arbitrary-size output.

    The remote temp file is cleaned up in a ``finally`` branch -- if the run
    crashes mid-flight, the orphan file lives in the analyzer temp dir until
    the OS cleans its temp folder.
    """
    # Wrapping with `cmd /d /c "..."` plus escaped inner quotes mangles under
    # paramiko+Windows OpenSSH (verified via test: "The filename, directory
    # name, or volume label syntax is incorrect"). Top-level redirect works
    # cleanly because Windows OpenSSH default shell is cmd.exe and cmd parses
    # `... > "path" 2>&1` correctly at the outermost level. We use a fixed
    # absolute path that needs no env expansion so the behavior is identical
    # whether the default shell is cmd or (less commonly) powershell.
    uid = uuid.uuid4().hex
    if analyzer_os == "windows":
        remote_tmp = f"C:\\Windows\\Temp\\aila_{uid}.out"
        redirected = f'{command} > "{remote_tmp}" 2>&1'
    else:
        remote_tmp = f"/tmp/aila_{uid}.out"
        redirected = f"{command} > {_posix_quote(remote_tmp)} 2>&1"

    local_tmp_fd, local_tmp_path = tempfile.mkstemp(prefix="aila_forensics_", suffix=".out")
    os.close(local_tmp_fd)

    try:
        # The command itself emits no stdout (everything went to the file),
        # so the SSH channel stays well below the 2 MB window. Exit code
        # carries the command's real status -- we ignore non-zero and still
        # try to fetch so the file has partial/error output.
        try:
            await ssh.run_command(integration, redirected, timeout_seconds=timeout_seconds)
        except (OSError, TimeoutError, RuntimeError, AILAError):
            pass

        # Download via SFTP -- handles GB-sized outputs cleanly.
        await ssh.download_file(integration, remote_tmp, local_tmp_path, timeout_seconds=timeout_seconds)

        with open(local_tmp_path, encoding="utf-8", errors="ignore") as f:
            return f.read()
    finally:
        try:
            os.unlink(local_tmp_path)
        except OSError:
            pass
        # Fire-and-forget remote cleanup. `del` is a cmd builtin that
        # Windows OpenSSH (default cmd.exe shell) executes directly.
        try:
            cleanup = (
                f'del /q /f "{remote_tmp}"' if analyzer_os == "windows"
                else f"rm -f {_posix_quote(remote_tmp)}"
            )
            await ssh.run_command(integration, cleanup, timeout_seconds=15.0)
        except (OSError, TimeoutError, RuntimeError, AILAError):
            pass
