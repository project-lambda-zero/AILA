"""Tool executor -- dispatches tool_run decisions through MCP bridges (M3.R-3).

The reasoning agent (``HonestVulnResearcher``) emits a tool_run decision
with ``command`` set to a JSON string describing which MCP tool to call.
The executor:
  1. Parses ``command`` as JSON: ``{"tool": "<server>.<tool>", "args": {...}}``
  2. Looks up the adapter via ``mcp_adapters.get_adapter``
  3. Dispatches to the matching bridge (IDABridgeTool / AuditMcpBridgeTool)
  4. Invokes the adapter on the raw response to get an AdapterResult
  5. Writes a new ENGINE message with the typed payload
  6. Merges the observables delta into the branch's ReasoningCaseState
     so the next reasoning turn sees the result

Unknown tools / malformed commands / MCP errors all write an
informative ENGINE message (PayloadKind.TEXT) and do NOT mutate
observables -- the engine sees the error in the next turn and can
recover.
"""
from __future__ import annotations

import json
import logging
from collections import OrderedDict
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select as _select

from aila.modules.vr.contracts import PayloadKind
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationRecord,
    VRTargetRecord,
)
from aila.modules.vr.services.config_helpers import get_int
from aila.platform.agents.tool_execution import (
    ToolExecutionResult,
)
from aila.platform.agents.tool_executor import ToolExecutorHelpersBase
from aila.platform.mcp.bridges.android_mcp import AndroidMcpBridgeTool
from aila.platform.mcp.bridges.audit_mcp import AuditMcpBridgeTool
from aila.platform.mcp.bridges.ida_headless import IDABridgeTool
from aila.platform.uow import UnitOfWork

__all__ = [
    "ToolExecutionResult",
    "ToolExecutor",
]

_log = logging.getLogger(__name__)


class ToolExecutor(ToolExecutorHelpersBase):
    """Per-investigation tool dispatcher. Injects the three MCP bridges
    (ida_headless, audit_mcp, android_mcp).

    Tests can construct with fake bridges that have a ``.forward(action, **kwargs)``
    method returning a canned dict.
    """

    # fix §252 -- bounded LRU cap. Was an unbounded `dict[str, str]`
    # leaking ~16 bytes per investigation forever; 100K investigations
    # = several MB of permanent worker-process residency. 2048 covers
    # every active investigation in flight comfortably (production
    # peak observed: 47 concurrent) with LRU eviction for the long
    # tail of finished/stale ids.
    _INV_INDEX_CACHE_MAX: int = 2048

    _BAD_INDEX_PLACEHOLDERS: frozenset[str] = frozenset({
        "main", "master", "head", "trunk", "current", "latest",
        "default", "tip", "primary", "this", "auto",
    })

    # Merged-dispatch config (ToolExecutorHelpersBase.execute reads these).
    _TOOLRUN_EXAMPLE_JSON = (
        '{"tool": "audit_mcp.read_function", "args": {"name": "..."}}'
    )
    _TOOLRUN_ACTIONS = (
        "tool_run / reasoning / submit / submit_outcome_review / script_execute"
    )

    def __init__(
        self,
        ida: IDABridgeTool | Any,
        audit_mcp: AuditMcpBridgeTool | Any,
        android_mcp: AndroidMcpBridgeTool | Any,
    ) -> None:
        self._message_model = VRInvestigationMessageRecord
        self._branch_model = VRInvestigationBranchRecord
        self._bridges: dict[str, Any] = {
            "ida_headless": ida,
            "audit_mcp": audit_mcp,
            "android_mcp": android_mcp,
        }
        # Per-process LRU: investigation_id -> resolved audit_mcp
        # index_id (or empty string when the investigation's target has
        # no source repo). Filled lazily on first use per investigation.
        # fix §252 -- bounded LRU. OrderedDict.move_to_end on hit +
        # popitem(last=False) on overflow gives true LRU semantics
        # without functools.lru_cache (which can't wrap async methods
        # AND can't share state across instances). Cache lives on the
        # executor instance; created once per investigation loop.
        self._inv_index_id_cache: OrderedDict[str, str] = OrderedDict()

    async def _hard_block_repeat_limit(self) -> int | None:
        return await get_int("tool_executor_hard_block_repeat")

    async def _pre_dispatch_correct_args(
        self, investigation_id: str, server_id: str, args: dict[str, Any],
    ) -> dict[str, Any]:
        # Auto-correct an audit_mcp index_id placeholder (saves a 30s+ LLM
        # round-trip that would return "Unknown index" / a missing kwarg).
        if server_id == "audit_mcp":
            return await self._maybe_correct_index_id(investigation_id, args)
        return args

    def _augment_tool_error(
        self, server_id: str, tool_name: str, args: dict[str, Any],
        raw_err: Any, err: str,
    ) -> str:
        # An audit_mcp.read_function "not indexed" result is often a #define
        # macro, so point the agent at search_macros.
        if (
            server_id == "audit_mcp"
            and tool_name == "read_function"
            and isinstance(raw_err, str)
            and "not indexed" in raw_err.lower()
        ):
            requested = args.get("name") or args.get("function") or "<symbol>"
            err += (
                f"\n\nHINT: '{requested}' may be a macro (#define), not a function. "
                f"Try audit_mcp.search_macros(name={requested!r}) BEFORE giving up -- "
                f"identifiers that look like function calls (e.g. ngx_http_v2_write_*) "
                f"are often macros that read_function can't see."
            )
        return err

    def _pivot_alternatives(
        self, server_id: str, tool_name: str, ident: str,
    ) -> list[str]:
        alternatives: list[str] = []
        if server_id == "audit_mcp" and tool_name == "read_function":
            alternatives.extend([
                f"  - audit_mcp.search_functions(query={ident!r})  # find similar function names",
                f"  - audit_mcp.search_source(pattern={ident!r}, limit=30)  # find any mention in source",
                f"  - audit_mcp.search_macros(name={ident!r})  # check if it's a #define",
            ])
        elif server_id == "audit_mcp" and tool_name == "search_source":
            alternatives.extend([
                f"  - audit_mcp.search_macros(name={ident!r})  # if checking for a symbol, try macros",
                f"  - audit_mcp.search_constants(name={ident!r})  # if checking for a constant",
                "  - try a shorter / broader pattern",
            ])
        return alternatives

    async def _resolve_bridge_base_url(self) -> str:
        # bridge_base_url comes from the audit_mcp bridge instance, not a
        # hardcoded literal; falls back to the default when the bridge stub
        # lacks the accessor.
        audit_mcp_bridge = self._bridges.get("audit_mcp")
        if hasattr(audit_mcp_bridge, "base_url"):
            try:
                return await audit_mcp_bridge.base_url()
            except (AttributeError, RuntimeError, OSError, ValueError, TypeError) as exc:
                _log.info(
                    "tool_executor: bridge.base_url() failed (%s: %s); "
                    "falling back to default",
                    type(exc).__name__, exc, exc_info=True,
                )
        return "http://127.0.0.1:18822"




    async def _maybe_correct_index_id(
        self,
        investigation_id: str,
        args: dict[str, Any],
    ) -> dict[str, Any]:
        """Auto-correct ``index_id`` for audit_mcp calls.

        Returns args unchanged when:
          - the agent passed a non-placeholder string; OR
          - the investigation has no resolvable index_id (caller's
            target is a binary, an empty placeholder, or ingestion
            never landed); OR
          - the args.index_id already matches the resolved id.

        Returns args with ``index_id`` substituted when the agent
        passed a known placeholder ('main', 'master', 'head', etc.)
        or omitted it entirely. Logs INFO so the operator can audit
        every auto-fix in the worker log.

        Cache key: investigation_id. The mapping investigation -> index
        id never changes for the lifetime of an investigation, so a
        plain dict cache is safe (no TTL needed).
        """
        resolved = await self._resolve_index_id(investigation_id)
        if not resolved:
            return args
        current = args.get("index_id")
        if isinstance(current, str) and current and current.lower() not in self._BAD_INDEX_PLACEHOLDERS:
            return args
        if current == resolved:
            return args
        new_args = dict(args)
        new_args["index_id"] = resolved
        _log.info(
            "tool_executor: auto-corrected index_id inv=%s "
            "from %r to %r (saves an LLM round-trip)",
            investigation_id, current, resolved,
        )
        return new_args

    def _cache_index_id(self, investigation_id: str, resolved: str) -> str:
        """Insert or refresh ``investigation_id`` in the LRU index cache.

        fix §252 -- moves an existing entry to the MRU end and evicts the
        LRU entry when the cap is exceeded. Returns ``resolved`` so the
        caller can ``return self._cache_index_id(inv, value)`` directly.
        """
        cache = self._inv_index_id_cache
        if investigation_id in cache:
            cache.move_to_end(investigation_id)
        cache[investigation_id] = resolved
        while len(cache) > self._INV_INDEX_CACHE_MAX:
            cache.popitem(last=False)
        return resolved

    async def _resolve_index_id(self, investigation_id: str) -> str:
        """Resolve investigation -> primary target -> audit_mcp_index_id.

        Returns empty string when no source-repo target / no audit-mcp
        index for this investigation.
        """
        cache = self._inv_index_id_cache
        if investigation_id in cache:
            # fix §252 -- LRU touch.
            cache.move_to_end(investigation_id)
            return cache[investigation_id]
        try:
            async with UnitOfWork() as uow:
                inv = (await uow.session.exec(
                    _select(VRInvestigationRecord).where(
                        VRInvestigationRecord.id == investigation_id,
                    ),
                )).first()
                if inv is None or not inv.target_id:
                    return self._cache_index_id(investigation_id, "")
                target = (await uow.session.exec(
                    _select(VRTargetRecord).where(
                        VRTargetRecord.id == inv.target_id,
                    ),
                )).first()
                if target is None or not target.mcp_handles_json:
                    return self._cache_index_id(investigation_id, "")
            try:
                handles = json.loads(target.mcp_handles_json or "{}")
            except (ValueError, TypeError):
                handles = {}
            resolved = str(handles.get("audit_mcp_index_id") or "")
            return self._cache_index_id(investigation_id, resolved)
        except (SQLAlchemyError, OSError, RuntimeError, ImportError, AttributeError, ValueError, TypeError) as exc:
            # fix §253 -- broadened from (OSError, RuntimeError, ImportError,
            # AttributeError). The auto-correct path must NEVER block the
            # underlying tool dispatch, so any failure here (SQLAlchemy
            # OperationalError, DataError, JSON corruption, schema drift,
            # arbitrary upstream raise) is logged at INFO and falls through
            # to "use args as-is".
            # fix §350 -- surface traceback on the fallback so SQLAlchemy /
            # schema drift / JSON corruption is grep-able instead of just
            # the class + truncated message.
            _log.info(
                "tool_executor._resolve_index_id: failed for inv=%s (%s: %s); "
                "falling back to caller-supplied args",
                investigation_id, type(exc).__name__, exc,
                exc_info=True,
            )
            return ""





    async def _load_pivot_history(
        self, branch_id: str,
    ) -> list[dict[str, Any]]:
        """Return the existing ``_directive.pivot_history`` array for
        this branch (or an empty list when absent / corrupted).

        fix §199 -- used by the survey-streak pivot path to append new
        entries without losing prior nudges. A separate read because
        the observables merge happens atomically inside
        :meth:`_merge_observables`; the pivot site only owns the
        composition of the new delta.
        """
        async with UnitOfWork() as uow:
            branch = (await uow.session.exec(
                _select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.id == branch_id,
                )
            )).first()
        if branch is None:
            return []
        try:
            case_state = json.loads(branch.case_state_json or "{}")
        except (json.JSONDecodeError, TypeError) as exc:
            _log.warning(
                "_load_pivot_history FAILED branch=%s reason=%s",
                branch_id, exc,
            )
            return []
        observables = case_state.get("observables")
        if not isinstance(observables, dict):
            return []
        history = observables.get("_directive.pivot_history")
        if not isinstance(history, list):
            return []
        # Defensive copy so the caller can append without aliasing
        # the DB-side dict.
        return [dict(entry) for entry in history if isinstance(entry, dict)]

    # Tools that present aggregated/ranked metadata over a codebase
    # without revealing function bodies. Calling these repeatedly
    # without a follow-up read_function / read_class / taint_paths_to
    # means the agent is debating which lead to pursue instead of
    # actually looking at code.
    _SURVEY_TOOLS: frozenset[tuple[str, str]] = frozenset({
        ("audit_mcp", "attack_surface"),
        ("audit_mcp", "complexity_hotspots"),
        ("audit_mcp", "fuzzing_targets"),
        ("audit_mcp", "summary"),
        ("audit_mcp", "preanalysis"),
        ("audit_mcp", "list_indexes"),
        ("audit_mcp", "memory_usage"),
        ("audit_mcp", "cache_stats"),
        ("ida_headless", "binary_survey"),
        ("ida_headless", "binary_metadata"),
        ("ida_headless", "list_functions"),
        ("ida_headless", "imports"),
        ("ida_headless", "exports"),
        ("ida_headless", "segments"),
    })

    # fix §200 -- was a hardcoded class attribute. Now sourced from
    # ``mcp_adapters.get_read_tools()`` which is populated at import
    # time by the ``@is_read_tool`` decorator on each specialised
    # adapter (plus a small imperative list in
    # ``mcp_adapters.registry`` for the generic-adapter-backed read
    # tools ``extract_class`` and ``entrypoint_paths_to``).
    #
    # This fallback is used only when the adapter modules have never
    # been imported in the current process (e.g. a narrow unit test
    # that constructs a ToolExecutor with stub bridges and never
    # exercises the dispatch path). Production code paths always
    # pull in the adapters first via ``get_adapter`` at line 218.
    _READ_TOOLS_FALLBACK: frozenset[tuple[str, str]] = frozenset({
        ("audit_mcp", "read_function"),
        ("audit_mcp", "read_lines"),         # bridge-side verbatim slice
        ("audit_mcp", "semantic_search"),    # returns full code chunks
        ("audit_mcp", "extract_class"),
        ("audit_mcp", "taint_paths_to"),
        ("audit_mcp", "callers_of"),
        ("audit_mcp", "callees_of"),
        ("audit_mcp", "entrypoint_paths_to"),
        ("audit_mcp", "paths_between"),
        ("audit_mcp", "def_use"),
        ("audit_mcp", "find_related"),
        ("ida_headless", "decompile"),
        ("ida_headless", "disassemble_function"),
        ("ida_headless", "pseudocode_slice_view"),
        ("ida_headless", "interprocedural_taint"),
        ("ida_headless", "trace_dataflow"),
        ("ida_headless", "xrefs_to"),
        ("ida_headless", "xrefs_from"),
    })


    async def _survey_streak_hint(
        self,
        branch_id: str,
        server_id: str,
        tool_name: str,
    ) -> str | None:
        """Return a pivot directive when the current call AND the prior
        two successful tool_calls on this branch are all SURVEY tools.

        Returns None unless the streak fires -- non-survey calls reset
        the counter immediately. The hint is intentionally short and
        actionable so it lands at the top of the agent's next-turn
        attention without crowding out the actual tool output.
        """
        if (server_id, tool_name) not in self._SURVEY_TOOLS:
            return None
        # Walk back the last 4 tool_call payloads on this branch and
        # count consecutive surveys (excluding the current one -- it's
        # already counted as #3 if the prior 2 match).
        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                _select(VRInvestigationMessageRecord)
                .where(VRInvestigationMessageRecord.branch_id == branch_id)
                .where(VRInvestigationMessageRecord.payload_kind == PayloadKind.TOOL_CALL.value)
                .order_by(VRInvestigationMessageRecord.created_at.desc())
                .limit(4)
            )).all()
        prior_surveys = 0
        for r in rows:
            try:
                payload = json.loads(r.payload_json or "{}")
                cmd = json.loads(payload.get("command") or "{}")
            except (ValueError, TypeError):
                break
            # fix §257 -- keep "server is leftmost segment, tool is the
            # rest" semantics for multi-segment tool names (e.g. a future
            # `audit_mcp.utils.read_lines` would split to
            # ("audit_mcp", "utils.read_lines")). `partition`'s tail
            # already preserved this, but using split(".", 1) makes the
            # intent explicit and matches the dispatch site convention.
            parts = (cmd.get("tool") or "").split(".", 1)
            key = (parts[0], parts[1] if len(parts) == 2 else "")
            if key in self._SURVEY_TOOLS:
                prior_surveys += 1
            else:
                break  # non-survey call → streak broken
        # Current call + prior_surveys gives the streak length. Fire
        # when total >= 3 (current call is #3, two priors were also
        # surveys).
        total = prior_surveys + 1
        if total < 3:
            return None
        return (
            f"*** PIVOT REQUIRED: {total} CONSECUTIVE SURVEY CALLS ***\n"
            f"You have called {total} survey tools in a row on this "
            f"branch without reading any source code. STOP SURVEYING. "
            f"You already have enough ranking data. Your next tool_run "
            f"MUST be one of:\n"
            f"  - audit_mcp.read_function(name=<top candidate>, file_path=<path>) -- read the actual body\n"
            f"  - audit_mcp.taint_paths_to(name=<sink>) -- trace user input to the candidate\n"
            f"  - audit_mcp.callers_of(name=<candidate>) -- who reaches this function\n"
            f"  - audit_mcp.entrypoint_paths_to(name=<candidate>) -- what untrusted-input entrypoints reach it\n"
            f"  - OR submit a finding/AssessmentReport if no candidate is concrete enough to read\n"
            f"Adversarial deliberation is consuming turns without acquiring evidence. Read source NOW."
        )


    # Cap on case_state.observables size. Each tool call typically
    # adds 1-2 keys; long investigations accumulate observable entries
    # fast and an unbounded map balloons the case_state_json blob into
    # megabytes. ``_directive.*`` and ``_recall.*`` keys are reserved
    # namespaces kept regardless of count -- steering directives and
    # recall-pinned entries must survive eviction.
    _MAX_OBSERVABLES: int = 400


