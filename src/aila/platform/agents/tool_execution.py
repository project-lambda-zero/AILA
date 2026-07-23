"""Shared tool-execution primitives (RFC-03 Phase 4a).

The genuinely-shared, module-agnostic kernel of the two module tool
executors: the dispatch result shape, the tool-command parser, and the
contract-error classifier taxonomy. These were byte-identical copies in
both executors. The full dispatch consolidation (bridge routing,
circuit breakers, observation recording, audit index correction) stays
per-module pending a revised plan -- see the RFC-03 Phase 4 note.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

__all__ = [
    "ToolExecutionResult",
    "classify_contract_error",
    "parse_command",
]

_log = logging.getLogger(__name__)

# Max bytes for a single tool_run command payload; oversized commands are
# rejected by parse_command before any JSON decode.
_MAX_TOOL_CMD_BYTES = 65536


@dataclass(slots=True)
class ToolExecutionResult:
    """Outcome of one tool_run dispatch."""

    server_id: str
    tool_name: str
    message_id: str | None
    success: bool
    error: str = ""


def parse_command(raw: str) -> tuple[str, dict[str, Any]] | None:
    """Parse a tool_run command string into (tool_id, args).

    Expected JSON shape:
        {"tool": "<server>.<tool>", "args": {<kwargs>}}
    Returns None on any parse failure so the executor can report the
    error back to the engine via a TEXT message.
    """
    if not raw or not raw.strip():
        return None
    # fix §261 -- bail before json.loads on oversize input.
    if len(raw) > _MAX_TOOL_CMD_BYTES:
        _log.warning(
            "tool_execution.parse_command: command_raw exceeds cap "
            "(%d > %d bytes); rejecting before JSON parse",
            len(raw), _MAX_TOOL_CMD_BYTES,
        )
        return None
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        _log.warning(
            "tool_execution.parse_command: JSON decode failed (raw len=%d): %s",
            len(raw), exc,
        )
        return None
    if not isinstance(decoded, dict):
        return None
    tool_id = decoded.get("tool")
    # fix §260 -- `args` explicitly set to None (e.g. by an agent that
    # remembered list_indexes takes no kwargs) used to fail the dict
    # isinstance check and force-stop. Coerce missing-OR-None to {}.
    args = decoded.get("args") or {}
    if not isinstance(tool_id, str) or not isinstance(args, dict):
        return None
    return tool_id, args


def classify_contract_error(text: str) -> str | None:
    """Return a coarse class key for contract-violation errors, or
    None when ``text`` doesn't look like one.

    Classes:
      - "unknown_kwarg"  -- bridge validator OR upstream Python
                          TypeError about an unexpected keyword
      - "missing_kwarg"  -- required kwarg not provided
      - "type_mismatch"  -- wrong type passed
      - "resource_not_found" -- agent is passing a path / id /
                          identifier the tool cannot resolve. Once
                          an APK / index / file lookup misses, the
                          same lookup with slightly different bytes
                          keeps missing -- the agent typo-drifts the
                          identifier (LLM transcription error on
                          long SHA-derived paths) and the
                          args-identical breaker never matches
                          because each typo is "fresh". Treating
                          this as a contract class so the
                          error-class breaker fires after N misses
                          regardless of which specific path was
                          passed.
    """
    low = text.lower()
    if (
        "unknown kwarg" in low
        or "unexpected keyword argument" in low
        or "got an unexpected keyword" in low
    ):
        return "unknown_kwarg"
    if "missing required" in low or "missing 1 required" in low:
        return "missing_kwarg"
    if "type mismatch" in low or "argument of type" in low:
        return "type_mismatch"
    if (
        "filenotfounderror" in low
        or "no such file or directory" in low
        or "apk not found" in low
        or "path not found" in low
        or "unknown index" in low
        or "index not found" in low
        or "index_id not found" in low
        or "does not exist" in low and ("path" in low or "file" in low or "apk" in low or "index" in low)
    ):
        return "resource_not_found"
    return None
