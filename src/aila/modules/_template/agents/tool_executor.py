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

from aila.modules._template.db_models import (
    TemplateInvestigationBranchRecord,
    TemplateInvestigationMessageRecord,
)
from aila.platform.agents.tool_execution import ToolExecutionResult
from aila.platform.agents.tool_executor import ToolExecutorHelpersBase
from aila.platform.config_base import ModuleConfigReader

# Module-scoped typed config reader. Resolves the ``template`` namespace
# through :class:`ConfigRegistry` (env -> DB -> schema default) and
# replaces the deleted ``services.config_helpers`` shim (RFC-04).
_config = ModuleConfigReader("template")

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
        # RFC-11 Tier C: bridges are built on demand by the base
        # _bridge_for() through the catalog-driven factory. This scaffold
        # exposes no servers (_AGENT_ALLOWED_SERVERS is empty), so the
        # base's allowlist guard rejects every dispatch before any bridge
        # is constructed. A real module sets ``_bridge_module_id`` +
        # ``_bridge_recorder_fn`` and lists its servers in
        # ``_AGENT_ALLOWED_SERVERS``.

    async def _hard_block_repeat_limit(self) -> int | None:
        """Return the operator-tunable repeat-block cap."""
        return await _config.get_int("tool_executor_hard_block_repeat")

    def _router_module_scope(self) -> str | None:
        """RFC-07 router scope -- template rows land under ``template``."""
        return "template"
