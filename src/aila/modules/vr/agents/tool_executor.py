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
import re
from collections import OrderedDict
from typing import Any, ClassVar

from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select as _select

from aila.modules.vr.contracts import PayloadKind
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationRecord,
    VRTargetRecord,
)
from aila.modules.vr.services.knowledge_scope import vr_knowledge_namespaces
from aila.modules.vr.services.mcp_call_logger import record_call
from aila.platform.agents.observation import (
    ObservationKind,
    ObservationPolarity,
    PlatformObservation,
    record_observation,
)
from aila.platform.agents.tool_execution import (
    ToolExecutionResult,
)
from aila.platform.agents.tool_executor import ToolExecutorHelpersBase
from aila.platform.config_base import ModuleConfigReader
from aila.platform.mcp.bridges.knowledge import KnowledgeBridgeTool
from aila.platform.services.knowledge import KnowledgeService
from aila.platform.uow import UnitOfWork

__all__ = [
    "ToolExecutionResult",
    "ToolExecutor",
]

_log = logging.getLogger(__name__)
_cfg = ModuleConfigReader("vr")


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

    # Hard allowlist of MCP servers the AGENT may dispatch against -- the
    # exact set wired in ``__init__``'s ``_bridges`` map. Matches the
    # server catalog vr exposes to the researcher via ``_fetch_tool_specs``:
    #   - audit_mcp:   source-code audit (source_repo + android_apk source tree)
    #   - ida_headless: binary analysis (native_binary / kernel / hypervisor /
    #                   android_apk native libs)
    #   - android_mcp: APK-facet tools (manifest / signing / permissions)
    #   - knowledge:   RFC-12 read-only knowledge retrieval (available on
    #                  every target kind)
    # The base check (ToolExecutorHelpersBase._dispatch) rejects any other
    # server_id BEFORE adapter lookup with a clear "not exposed to this
    # agent" error. Adding a new bridge requires wiring it in ``__init__``
    # AND appending it here.
    _AGENT_ALLOWED_SERVERS: frozenset[str] = frozenset(
        {"audit_mcp", "ida_headless", "android_mcp", "knowledge"},
    )

    # ---- Lateral-vulnerability discovery patterns (issue #95, #136) ----
    # Passive tells the platform's auto-steering rule 5 scans over
    # ``read_function`` / ``read_lines`` / ``semantic_search`` bodies.
    # Migrated out of ``platform/agents/auto_steering.py`` so the
    # platform reasoning layer never carries FFmpeg / codec-shaped
    # regex vocabulary. Empty on other modules -- the platform base's
    # default -- turns the scan into a no-op for them.
    lateral_patterns: ClassVar[list[tuple[re.Pattern[str], str]]] = [
        # ``else if (av_strstart(proto, "http", NULL)) ;`` -- protocol
        # dispatch that recognises a name and then does nothing with it.
        # Also catches empty ``{}`` bodies. Typical FFmpeg protocol.c /
        # muxer registration bug shape.
        (
            re.compile(
                # Balanced one-level paren nesting so ``strcmp(a, b)`` /
                # ``av_strstart(p, "x", NULL)`` inside the if-condition
                # doesn't fool the outer ``\)`` anchor.
                r"(?:else\s+if|elif)\s*\("
                r"(?:[^()]|\([^()]*\))*"
                r"(?:strstart|strcmp|strncmp|strcasecmp|strncasecmp)"
                r"(?:[^()]|\([^()]*\))*"
                r"\)\s*(?:;|\{\s*\})",
            ),
            "protocol_passthrough_no_check",
        ),
        # ``int size = w * h;`` / ``unsigned len = a * b;`` -- integer
        # multiply into a narrow type with no overflow guard. Anchored
        # to a statement boundary so we don't match ``if (a * b > c)``.
        (
            re.compile(
                # Accept ``int|long|...`` as the type, OR bare
                # ``unsigned|signed`` with an optional
                # ``int|long|short|char`` suffix (``unsigned len`` is
                # legal C shorthand for ``unsigned int len``). Anchored
                # to a statement boundary so ``if (a * b > c)`` never
                # matches.
                r"(?:^|[;{\n])\s*"
                r"(?:(?:unsigned|signed)(?:\s+(?:int|long|short|char))?"
                r"|int|long|short|size_t|ssize_t"
                r"|uint(?:8|16|32|64)_t|int(?:8|16|32|64)_t)"
                r"\s+[A-Za-z_]\w*\s*=\s*[^;\n]*\*[^;\n]*;",
                re.MULTILINE,
            ),
            "unchecked_int_multiply",
        ),
        # ``memcpy(dst, src, len)`` where the length is a bare identifier
        # rather than a literal constant. The identifier could be
        # untrusted-input-derived; worth surfacing for review.
        (
            re.compile(
                r"\b(?:memcpy|memmove|memset)\s*\("
                r"\s*[^,]+,\s*[^,]+,\s*"
                r"[A-Za-z_]\w*\s*\)",
            ),
            "memop_variable_length",
        ),
        # ``width >>= chroma;`` / ``h >>= vsub;`` -- dimension halving
        # by a subsampling factor. Common truncation site in codec
        # dimension math.
        (
            re.compile(
                r">>=\s*[A-Za-z_]*(?:chroma|sub|shift|vsub)[A-Za-z_0-9]*",
            ),
            "truncating_dimension_shift",
        ),
        # ``avio_r*(...); ... av_malloc(...)`` -- input-derived value
        # flows into an allocation size within a small window. DOTALL
        # + bounded gap so we don't cross file-scope boundaries.
        (
            re.compile(
                r"(?:avio_r[a-z0-9_]+|bytestream2?_get[a-z0-9_]+|get_bits\d*)\b"
                r"[^;]*;.{0,300}?"
                r"\b(?:av_mallocz?|av_realloc|av_mallocz_array|av_calloc|"
                r"malloc|calloc|realloc|av_frame_get_buffer|ff_get_buffer|"
                r"av_new_packet|av_image_alloc)\b",
                re.DOTALL,
            ),
            "input_to_allocation",
        ),
    ]

    # Merged-dispatch config (ToolExecutorHelpersBase.execute reads these).
    _TOOLRUN_EXAMPLE_JSON = (
        '{"tool": "audit_mcp.read_function", "args": {"name": "..."}}'
    )
    _TOOLRUN_ACTIONS = (
        "tool_run / reasoning / submit / submit_outcome_review / script_execute"
    )

    def __init__(
        self,
        ida: Any = None,
        audit_mcp: Any = None,
        android_mcp: Any = None,
        knowledge: Any | None = None,
    ) -> None:
        self._message_model = VRInvestigationMessageRecord
        self._branch_model = VRInvestigationBranchRecord
        # RFC-11 Tier C: HTTP bridges are built on demand by the base
        # _bridge_for() through the generic factory. Only explicitly
        # injected bridges (tests / DI) and the in-process knowledge
        # bridge are pre-seeded as overrides; production constructs
        # ToolExecutor() with no bridges and lets the catalog + factory
        # drive dispatch.
        self._bridge_module_id = "vr"
        self._bridge_recorder_fn = record_call
        self._bridge_overrides: dict[str, Any] = {
            server_id: bridge
            for server_id, bridge in {
                "ida_headless": ida,
                "audit_mcp": audit_mcp,
                "android_mcp": android_mcp,
                # RFC-12 agentic path: read-only knowledge retrieval,
                # scoped server-side in _pre_dispatch_correct_args.
                "knowledge": knowledge or KnowledgeBridgeTool(),
            }.items()
            if bridge is not None
        }
        self._bridge_cache: dict[str, Any] = {}
        # Per-process LRU: investigation_id -> (workspace_id, team_id) for
        # server-side knowledge-retrieval scoping.
        self._inv_workspace_cache: OrderedDict[str, tuple[str, str | None]] = OrderedDict()
        # RFC-12 evicted-observation burn writer. Constructed lazily on the
        # first eviction so unit tests that never trip the cap pay nothing.
        # Tests may substitute a fake here before invoking the hook.
        self._obs_knowledge_writer: KnowledgeService | None = None
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
        return await _cfg.get_int("tool_executor_hard_block_repeat")

    def _router_module_scope(self) -> str | None:
        """RFC-07 router scope -- routes across VR catalog rows and
        applies the disable-after-N-failures policy per the VR-scoped
        RFC-11 descriptors published in :mod:`aila.modules.vr.services.mcp_registry`.
        """
        return "vr"

    async def _pre_dispatch_correct_args(
        self, investigation_id: str, server_id: str, args: dict[str, Any],
    ) -> dict[str, Any]:
        # Auto-correct an audit_mcp index_id placeholder (saves a 30s+ LLM
        # round-trip that would return "Unknown index" / a missing kwarg).
        if server_id == "audit_mcp":
            return await self._maybe_correct_index_id(investigation_id, args)
        # RFC-12: inject the workspace-scoped knowledge namespaces SERVER-SIDE
        # so the agent can never widen retrieval beyond its own workspace.
        # Any agent-supplied _namespaces is dropped and replaced.
        if server_id == "knowledge":
            workspace_id, team_id = await self._resolve_workspace_scope(
                investigation_id,
            )
            scoped = {
                k: v for k, v in args.items()
                if k not in ("_namespaces", "_journal_context")
            }
            if workspace_id:
                scoped["_namespaces"] = vr_knowledge_namespaces(
                    workspace_id, team_id,
                )
                scoped["_journal_context"] = {
                    "investigation_id": investigation_id,
                    "team_id": team_id,
                }
            return scoped
        return args

    async def _resolve_workspace_scope(
        self, investigation_id: str,
    ) -> tuple[str, str | None]:
        """Resolve investigation -> (workspace_id, team_id) for knowledge
        retrieval scoping. Returns ``("", None)`` when unresolvable; the
        knowledge bridge refuses an unscoped call in that case.
        """
        cache = self._inv_workspace_cache
        if investigation_id in cache:
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
                    return self._cache_workspace_scope(investigation_id, "", None)
                target = (await uow.session.exec(
                    _select(VRTargetRecord).where(
                        VRTargetRecord.id == inv.target_id,
                    ),
                )).first()
                workspace_id = (
                    str(target.workspace_id)
                    if target and target.workspace_id else ""
                )
                return self._cache_workspace_scope(
                    investigation_id, workspace_id,
                    getattr(inv, "team_id", None),
                )
        except (SQLAlchemyError, OSError, RuntimeError, AttributeError, ValueError, TypeError) as exc:
            _log.info(
                "tool_executor._resolve_workspace_scope: failed for inv=%s "
                "(%s: %s); knowledge retrieval will be refused",
                investigation_id, type(exc).__name__, exc, exc_info=True,
            )
            return ("", None)

    def _cache_workspace_scope(
        self, investigation_id: str, workspace_id: str, team_id: str | None,
    ) -> tuple[str, str | None]:
        cache = self._inv_workspace_cache
        cache[investigation_id] = (workspace_id, team_id)
        cache.move_to_end(investigation_id)
        while len(cache) > self._INV_INDEX_CACHE_MAX:
            cache.popitem(last=False)
        return (workspace_id, team_id)

    # RFC-12: when the live observables cap drops readings this turn, burn
    # each string-valued observation into the workspace-scoped semantic
    # store so a later branch turn can still recall it by query. Best
    # effort by base-class contract -- a store failure logs and returns;
    # it MUST NOT propagate because the tool result has already committed.
    # #128: extract_entities and link_neighbors are enabled so observation
    # entries carry graph edges (semantic neighbours + entity edges) --
    # otherwise the graph retrieval route cannot traverse observations
    # and the RFC-12 semantic-neighbour promise silently excludes the
    # highest-volume KB writes. Matches pattern_store's write shape.
    async def _on_observables_evicted(
        self,
        investigation_id: str,
        branch_id: str,
        at_turn: int | None,
        evicted: dict[str, Any],
    ) -> None:
        burnable = {
            k: v for k, v in evicted.items()
            if isinstance(v, str) and v.strip()
        }
        if not burnable:
            return
        workspace_id, _team_id = await self._resolve_workspace_scope(
            investigation_id,
        )
        if not workspace_id:
            return
        writer = self._obs_knowledge_writer
        if writer is None:
            writer = KnowledgeService()
            self._obs_knowledge_writer = writer
        for key, value in burnable.items():
            try:
                await writer.store(
                    namespace=f"vr.observation.workspace.{workspace_id}",
                    content=str(value),
                    metadata={
                        "investigation_id": investigation_id,
                        "branch_id": branch_id,
                        "turn_number": at_turn,
                        "observable_key": key,
                        "workspace_id": workspace_id,
                        "source": "evicted_observation",
                    },
                    dedup_key=f"obs:{investigation_id}:{branch_id}:{key}",
                    extract_entities=True,
                    link_neighbors=True,
                )
            except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError) as exc:
                _log.warning(
                    "evicted-observation burn failed inv=%s branch=%s key=%s: %s",
                    investigation_id, branch_id, key, exc, exc_info=True,
                )

    # ---- RFC #137: platform observation-memory hooks -------------------
    # Routes tool-dispatch outcomes through the platform observation
    # writer so a NEGATIVE observation ("we already looked for X in
    # this workspace and it isn't there") lands in the workspace-scoped
    # ``vr.observation.workspace.{workspace_id}`` knowledge bucket the
    # VR retrieval scope already reads. Positive READ_HIT rows record
    # confirming reads so a sibling branch retrieves "X exists and
    # here is its shape" instead of re-reading. All writes are
    # supersedable: :func:`observation_dedup_key` upserts on
    # ``(module, workspace, subject, kind)``.
    #
    # Filtering: this is the reasoning agent's dead-end memory. Recording
    # every survey / list-metadata call would flood the retrieval floor
    # with low-signal rows the agent will never benefit from re-reading.
    # The hook opts IN on:
    #   * successful READ tools (real body returned) -> READ_HIT
    #   * empty search / lookup results              -> DEAD_END
    #   * semantic tool failures                      -> DEAD_END / TOOL_FAILURE
    # and opts OUT on: successful non-read tools with a non-empty body
    # (surveys, listings, complexity_hotspots-style ranking output). Those
    # are still available in the live case_state / durable message row for
    # the next turn; they just don't earn a cross-investigation memory.

    _OBSERVATION_SUBJECT_KEYS: ClassVar[tuple[str, ...]] = (
        "name",
        "function",
        "symbol",
        "file_path",
        "path",
        "pattern",
        "query",
        "regex",
    )

    def _observation_subject(
        self, tool_name: str, args: dict[str, Any],
    ) -> str:
        """Extract a stable subject string from ``args``.

        Walks a fixed key list in priority order and returns the first
        non-empty string value trimmed to 200 chars. Falls back to
        ``tool_name`` when no known identifier arg is present so
        supersession still keys off SOMETHING coherent per tool.
        """
        for key in self._OBSERVATION_SUBJECT_KEYS:
            value = args.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()[:200]
        return tool_name

    @staticmethod
    def _raw_body_is_empty(raw: dict[str, Any]) -> bool:
        """True when the bridge response carries no result payload.

        Mirrors the empty-result shape the auto-steering skip block
        already uses: after stripping the envelope fields (status,
        action, kwargs) the response has no data keys.
        """
        if not isinstance(raw, dict) or not raw:
            return True
        for key in raw.keys():
            if key not in {"status", "action", "kwargs"}:
                return False
        return True

    async def _ensure_obs_writer(self) -> KnowledgeService:
        """Lazily construct + cache the observation writer."""
        writer = self._obs_knowledge_writer
        if writer is None:
            writer = KnowledgeService()
            self._obs_knowledge_writer = writer
        return writer

    async def _on_tool_success(
        self,
        *,
        investigation_id: str,
        branch_id: str,
        server_id: str,
        tool_name: str,
        args: dict[str, Any],
        raw: dict[str, Any],
        at_turn: int | None,
    ) -> None:
        workspace_id, _team_id = await self._resolve_workspace_scope(
            investigation_id,
        )
        if not workspace_id:
            return
        is_read = (server_id, tool_name) in self._read_tools()
        empty = self._raw_body_is_empty(raw)
        subject = self._observation_subject(tool_name, args)
        if is_read and not empty:
            polarity = ObservationPolarity.POSITIVE
            kind = ObservationKind.READ_HIT.value
            content = (
                f"{server_id}.{tool_name} returned a body for {subject!r} "
                f"in workspace {workspace_id[:8]}."
            )
        elif empty:
            polarity = ObservationPolarity.NEGATIVE
            kind = ObservationKind.DEAD_END.value
            content = (
                f"{server_id}.{tool_name} for {subject!r} returned no results "
                f"in workspace {workspace_id[:8]} -- looked, nothing there."
            )
        else:
            # Non-read successful call with a body (survey, listing,
            # ranking). Skip: these are not dead-end memory.
            return
        writer = await self._ensure_obs_writer()
        await record_observation(
            PlatformObservation(
                module="vr",
                workspace_id=workspace_id,
                subject=f"{server_id}.{tool_name}:{subject}",
                kind=kind,
                polarity=polarity,
                content=content,
                investigation_id=investigation_id,
                branch_id=branch_id,
                turn_number=at_turn,
                extra={"server_id": server_id, "tool_name": tool_name},
            ),
            writer=writer,
        )

    async def _on_tool_failure(
        self,
        *,
        investigation_id: str,
        branch_id: str,
        server_id: str,
        tool_name: str,
        args: dict[str, Any],
        error: str,
        at_turn: int | None,
    ) -> None:
        workspace_id, _team_id = await self._resolve_workspace_scope(
            investigation_id,
        )
        if not workspace_id:
            return
        subject = self._observation_subject(tool_name, args)
        lc = error.lower()
        # Dead-end error classes -- the resource itself is confirmed
        # absent from the target (not indexed, not found, unknown
        # index). Recording these lets a sibling branch / later turn
        # retrieve "identifier X is not present in this workspace's
        # index" without re-issuing the failing call.
        dead_end = any(
            marker in lc
            for marker in (
                "not indexed",
                "not found",
                "no such",
                "unknown index",
                "does not exist",
            )
        )
        if dead_end:
            polarity = ObservationPolarity.NEGATIVE
            kind = ObservationKind.DEAD_END.value
            content = (
                f"{server_id}.{tool_name} confirmed {subject!r} is absent "
                f"from workspace {workspace_id[:8]}: "
                f"{error.strip().splitlines()[0][:400]}"
            )
        else:
            polarity = ObservationPolarity.NEGATIVE
            kind = ObservationKind.TOOL_FAILURE.value
            content = (
                f"{server_id}.{tool_name} failed for {subject!r} in "
                f"workspace {workspace_id[:8]}: "
                f"{error.strip().splitlines()[0][:400]}"
            )
        writer = await self._ensure_obs_writer()
        await record_observation(
            PlatformObservation(
                module="vr",
                workspace_id=workspace_id,
                subject=f"{server_id}.{tool_name}:{subject}",
                kind=kind,
                polarity=polarity,
                content=content,
                investigation_id=investigation_id,
                branch_id=branch_id,
                turn_number=at_turn,
                extra={"server_id": server_id, "tool_name": tool_name},
            ),
            writer=writer,
        )

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
        audit_mcp_bridge = self._bridge_for("audit_mcp")
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
        """Force ``index_id`` to the investigation's one resolved index.

        A VR investigation is bound to exactly ONE audit_mcp index (its
        primary source-repo target). The model has no way to know the
        opaque index id (a hash) and routinely improvises placeholders
        ('main', 'primary') or invents names ('code_graph') that bounce
        back as ``Unknown index`` / ``not indexed`` -- a wasted turn. A
        blocklist of known-bad placeholders was whack-a-mole against an
        open set of hallucinations. Since the correct index is
        deterministic per investigation, the executor ignores whatever the
        model passed and substitutes the resolved id on every audit_mcp
        call.

        Returns args unchanged only when:
          - the investigation has no resolvable index_id (target is a
            binary, an empty placeholder, or ingestion never landed); OR
          - the model already passed exactly the resolved id.

        Logs INFO on every substitution so the operator can audit it.

        Cache key: investigation_id. The mapping investigation -> index
        id never changes for the lifetime of an investigation, so a
        plain dict cache is safe (no TTL needed).
        """
        resolved = await self._resolve_index_id(investigation_id)
        if not resolved:
            return args
        current = args.get("index_id")
        if current == resolved:
            return args
        new_args = dict(args)
        new_args["index_id"] = resolved
        _log.info(
            "tool_executor: forced audit_mcp index_id inv=%s from %r to %r "
            "(investigation is bound to one index; model value ignored)",
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
        """Resolve investigation -> primary target -> audit-mcp index id.

        A source_repo target stores the index under
        ``audit_mcp_index_id``; an android_apk target stores the unified
        jadx/React index under ``audit_mcp_decompiled_index_id`` (see
        target_analysis._android_index_decompiled). Both are checked so the
        auto-inject safety net also fires for APK audits -- otherwise the
        model's omitted / placeholder index_id is never corrected and the
        audit_mcp bridge blocks every call as ``missing required
        ['index_id']``.

        Returns empty string when no analyzed target / no audit-mcp index
        exists for this investigation.
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
            resolved = str(
                handles.get("audit_mcp_index_id")
                or handles.get("audit_mcp_decompiled_index_id")
                or ""
            )
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


    # ``_MAX_OBSERVABLES`` is not overridden here: the base class reads
    # the live value from ConfigRegistry under the ``platform`` namespace
    # (``reasoning_max_observables``, schema default 400 matches the
    # historical VR value). An operator override via PUT /config lands
    # on the next merge without a worker restart, and drift between the
    # platform default and the module override is eliminated.


