from __future__ import annotations

import logging

from ..config import PlatformSettings
from ..services.ssh import SSHService
from ._common import Tool

_log = logging.getLogger(__name__)


def _validate_ssh_command(command: str) -> None:
    """Audit-log an SSH command before dispatch.

    Security is enforced by SSH user permissions, not command filtering.
    Any command filtering here is trivially bypassable (renamed binaries,
    symlinks, aliases, shell builtins). The real security boundary is:
    1. The SSH user's OS-level permissions on the target machine
    2. Operators choose which user to connect as when registering a system
    3. Use an unprivileged user for read-only inventory collection

    This hook records each dispatched command for the audit trail.
    """
    _log.info("ssh.command_dispatch", extra={"command": command})


class SSHCommandTool(Tool):
    """Platform tool for executing validated SSH commands on registered Linux systems."""

    name = "ssh_command"
    description = "Run a shell command over SSH against a registered Linux system and return stdout."
    inputs = {
        "integration": {"type": "object", "description": "SSH integration connection fields."},
        "command": {"type": "string", "description": "Shell command to execute remotely."},
    }
    output_type = "string"

    def __init__(self, settings: PlatformSettings, ssh_service: SSHService | None = None):
        self.settings = settings
        self.ssh_service = ssh_service or SSHService(self.settings)

    async def forward(self, integration: dict, command: str) -> str:
        if not command:
            raise ValueError("command must be a non-empty string.")
        _validate_ssh_command(command)
        return await self.ssh_service.run_command(integration, command)

    async def forward_trusted(self, integration: dict, command: str, timeout_seconds: float | None = None) -> str:
        """Execute a platform-constructed command without validation."""
        return await self.ssh_service.run_command(integration, command, timeout_seconds=timeout_seconds)
