"""Platform ``sandbox_exec`` tool.

Thin wrapper around :class:`SandboxService` exposed to module agents
through the tool registry so they can run untrusted commands inside a
real isolation boundary without knowing about SSH, nsjail, or
Firecracker. Mirrors the shape of :class:`SSHCommandTool` -- inputs
declared as a JSON-schema-lite dict, one ``forward`` coroutine that
returns a plain dict for the agent runtime.
"""
from __future__ import annotations

import logging
from typing import Any

from ..config import PlatformSettings
from ..services.sandbox import (
    SandboxService,
    SandboxSpec,
    SandboxUnavailableError,
)
from ._common import Tool

__all__ = ["SandboxExecTool"]

_log = logging.getLogger(__name__)


class SandboxExecTool(Tool):
    """Agent-facing tool that runs one command in the platform sandbox.

    Callers pass ``argv``, an optional ``stdin`` string, a
    ``input_files`` map, a per-run ``timeout_s`` override, and an
    explicit ``network`` bit. Every field is clamped by the platform
    policy inside :class:`SandboxService`; there is no way for an agent
    to widen the policy from here.
    """

    name = "sandbox_exec"
    description = (
        "Execute a shell command inside the platform sandbox (nsjail or "
        "Firecracker microVM, per operator config). Returns the exit "
        "code, stdout, stderr, and any collected output files."
    )
    inputs = {
        "argv": {
            "type": "array",
            "description": "Command + arguments to execute inside the sandbox. Must contain at least one entry.",
            "items": {"type": "string"},
        },
        "stdin": {
            "type": "string",
            "description": "Optional UTF-8 text to feed the program on stdin.",
            "nullable": True,
        },
        "input_files": {
            "type": "object",
            "description": (
                "Optional map of workdir-relative path -> UTF-8 content. "
                "Each entry is written into the sandbox workdir before "
                "the program runs. Paths must be relative and free of "
                "'..' segments."
            ),
            "nullable": True,
        },
        "timeout_s": {
            "type": "number",
            "description": "Optional wall-clock ceiling (seconds). Clamped by the platform sandbox policy.",
            "nullable": True,
        },
        "network": {
            "type": "boolean",
            "description": "Grant network access inside the sandbox. Forced False unless the operator allows it.",
            "nullable": True,
        },
        "output_globs": {
            "type": "array",
            "description": "Optional workdir-relative glob patterns to collect back after the program exits.",
            "items": {"type": "string"},
            "nullable": True,
        },
    }
    output_type = "object"

    def __init__(
        self,
        settings: PlatformSettings,
        sandbox_service: SandboxService | None = None,
    ) -> None:
        self._settings = settings
        self._service = sandbox_service or SandboxService(settings)

    async def forward(
        self,
        argv: list[str],
        stdin: str | None = None,
        input_files: dict[str, str] | None = None,
        timeout_s: float | None = None,
        network: bool | None = None,
        output_globs: list[str] | None = None,
    ) -> dict[str, Any]:
        spec_kwargs: dict[str, Any] = {"argv": list(argv)}
        if stdin is not None:
            spec_kwargs["stdin"] = stdin
        if input_files:
            spec_kwargs["input_files"] = dict(input_files)
        if timeout_s is not None:
            spec_kwargs["timeout_s"] = float(timeout_s)
        if network is not None:
            spec_kwargs["network"] = bool(network)
        if output_globs:
            spec_kwargs["output_globs"] = list(output_globs)
        spec = SandboxSpec(**spec_kwargs)
        _log.info(
            "sandbox_exec dispatch argv0=%s timeout_s=%.1f network=%s",
            spec.argv[0], spec.timeout_s, spec.network,
        )
        try:
            result = await self._service.run(spec)
        except SandboxUnavailableError:
            # Surface unchanged so the caller can differentiate
            # "unavailable" from "backend failed". The tool executor
            # renders both cleanly, but the taxonomy stays intact.
            raise
        return result.model_dump(mode="json")
