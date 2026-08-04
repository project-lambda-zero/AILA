"""Template tool executor -- thin subclass of the platform base.

Every dispatch primitive (parse, allowlist, HARD-BLOCK counting,
observable merge, result-message persistence, LRU circuit breakers)
lives on :class:`ToolExecutorHelpersBase`. The template ships an
EMPTY bridge dict + EMPTY server allowlist: the platform base refuses
every tool_run before adapter lookup and writes an ENGINE error
message the researcher sees on the next turn.

A real module constructs the executor with its MCP bridges
(``audit_mcp``, ``ida_headless``, ``android_mcp``, ``knowledge`` -- vr's
shape) and widens ``_AGENT_ALLOWED_SERVERS`` to match. See
:mod:`aila.modules.vr.agents.tool_executor` for the production
reference.
"""
from __future__ import annotations

import logging
from typing import Any

from aila.modules._template.db_models import (
    TemplateInvestigationBranchRecord,
    TemplateInvestigationMessageRecord,
)
from aila.modules._template.services.config_helpers import get_int
from aila.platform.agents.tool_execution import ToolExecutionResult
from aila.platform.agents.tool_executor import ToolExecutorHelpersBase

__all__ = [
    "ToolExecutionResult",
    "ToolExecutor",
]

_log = logging.getLogger(__name__)


class ToolExecutor(ToolExecutorHelpersBase):
    """Template per-investigation tool dispatcher scaffold.

    Ships zero bridges and an empty server allowlist so every
    tool_run is rejected before dispatch. Copiers wire real bridges
    into ``_bridges`` and add their server names to
    ``_AGENT_ALLOWED_SERVERS``.
    """

    # Empty server allowlist -- the platform base rejects EVERY server
    # BEFORE adapter lookup and writes a clear "not exposed to this
    # agent" error message the researcher sees on the next turn.
    _AGENT_ALLOWED_SERVERS: frozenset[str] = frozenset()

    _TOOLRUN_EXAMPLE_JSON = (
        '{"tool": "<server>.<tool>", "args": {}}'
    )
    _TOOLRUN_ACTIONS = (
        "tool_run / reasoning / submit / submit_outcome_review / script_execute"
    )

    def __init__(self) -> None:
        self._message_model = TemplateInvestigationMessageRecord
        self._branch_model = TemplateInvestigationBranchRecord
        # Empty bridge map -- the allowlist guard rejects every server
        # id before the platform base reaches into this dict, so no
        # real MCP client construction is required in the scaffold.
        self._bridges: dict[str, Any] = {}

    async def _hard_block_repeat_limit(self) -> int | None:
        """Return the operator-tunable repeat-block cap."""
        return await get_int("tool_executor_hard_block_repeat")

    def _router_module_scope(self) -> str | None:
        """RFC-07 router scope -- template rows land under ``template``."""
        return "template"
