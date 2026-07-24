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
from uuid import uuid4

import httpx
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select as _select

from aila.modules.vr.contracts import PayloadKind
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationRecord,
    VRTargetRecord,
)
from aila.platform.agents.auto_steering import maybe_post_auto_steering
from aila.platform.agents.tool_execution import (
    ToolExecutionResult,
    classify_contract_error,
    parse_command,
)
from aila.platform.agents.tool_executor import ToolExecutorHelpersBase
from aila.platform.contracts import utc_now
from aila.platform.mcp.adapters import (
    AdapterContext,
    get_adapter,
)
from aila.platform.mcp.bridges.android_mcp import AndroidMcpBridgeTool
from aila.platform.mcp.bridges.audit_mcp import AuditMcpBridgeTool
from aila.platform.mcp.bridges.ida_headless import IDABridgeTool
from aila.platform.uow import UnitOfWork

__all__ = [
    "ToolExecutionResult",
    "ToolExecutor",
]

_log = logging.getLogger(__name__)

# fix §202 -- bridge writer-side whitelist contract (cross-ref W1 §214
# ida_bridge, §215 android_mcp_bridge): success statuses are normalised
# to exactly one of {"ready", "completed", "ok"}. The async progression
# values {"pending", "queued", "running"} mean the bridge returned
# without a final result -- the executor treats those identically
# to an error because there is no payload to render. Any other value
# (unknown / malformed) is coerced to error here so the engine sees a
# loud message on the next turn instead of an empty rendering.
_SUCCESS_STATUSES: frozenset[str] = frozenset({"ready", "completed", "ok"})

# Hard cap on identical-call retries within one branch. When the same
# (server.tool, canonical args) has failed this many times consecutively
# on the SAME branch, the executor refuses to dispatch any further
# attempt and returns a synthetic 'HARD-BLOCKED' error. Limit is
# generous (3) so legitimately-transient errors (httpx pool exhaustion,
# audit-mcp cold rebuild) still get retried. Tunable via env without
# code change.
_HARD_BLOCK_REPEAT_LIMIT: int = int(
    __import__("os").environ.get("VR_TOOL_EXECUTOR_HARD_BLOCK_REPEAT", "3"),
)

# fix §254 -- single source of truth for the malformed-command marker.
# Emitted by the executor (see line 159) and matched by the consecutive-
# malformed counter (see _count_consecutive_malformed). Drift between
# the two halves used to silently break the STOP-circuit-breaker.
_MALFORMED_TOOL_RUN_MARKER: str = "Malformed tool_run"

# fix §261 -- DoS guard. _parse_command runs json.loads on agent-supplied
# strings; a runaway agent that emits a multi-megabyte command_raw would
# pin a worker thread on the parse for seconds and bloat the resulting
# error message that gets persisted. 64KB is well above any legitimate
# tool call (the largest known shape is a script_execute body capped
# elsewhere at ~16KB).
_MAX_TOOL_CMD_BYTES: int = 65536




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

    async def execute(
        self,
        investigation_id: str,
        branch_id: str,
        command_raw: str,
        at_turn: int | None = None,
    ) -> ToolExecutionResult:
        """Dispatch one tool call. Writes a result message + updates observables."""
        call_id = str(uuid4())

        parsed = parse_command(command_raw)
        if parsed is None:
            # fix §201 -- count TOTAL malformed-command errors on the
            # last 50 engine messages from this branch (was: consecutive
            # starting at the tail). Alternating empty→good→empty→good→empty
            # legitimately means the agent cannot stabilise on a valid
            # tool_run shape and should be force-stopped; the prior
            # consecutive-only counter reset on every single good call
            # in between, so a branch could produce 8 empty commands
            # interleaved with 1-shot reasoning blocks and never trip
            # the breaker. STOP fires when total >= 5 (this call would
            # make the 6th).
            malformed_count = await self._count_total_malformed(
                branch_id,
            )
            if malformed_count >= 5:
                err = (
                    "STOP -- you have produced 6 or more empty or "
                    "malformed tool_run commands on this branch (last "
                    "50 messages). The engine cannot dispatch an empty "
                    "command. Your next turn MUST be one of:\n"
                    "  (a) action=tool_run with valid JSON command: "
                    '{\"tool\": \"audit_mcp.read_function\", \"args\": {\"name\": \"...\"}}\n'
                    "  (b) action=submit if you have enough evidence to "
                    "submit your findings.\n"
                    "  (c) action=reasoning to think without a tool call.\n\n"
                    "Pick (c) if you are unsure -- reasoning is always safe "
                    "and lets you think before dispatching another tool. "
                    "(There is NO 'observe' action -- only tool_run / "
                    "reasoning / submit / submit_outcome_review / "
                    "script_execute.)"
                )
            else:
                err = (
                    f"{_MALFORMED_TOOL_RUN_MARKER} command -- expected JSON with "
                    "'tool' (e.g. 'server.tool_name') and 'args' dict. "
                    f"Got: {command_raw[:200]!r}. "
                    "If you don't have a specific tool query to make this "
                    "turn, pick action=reasoning instead of action=tool_run."
                )
            msg_id = await self._write_error_message(
                investigation_id, branch_id, err, at_turn,
            )
            return ToolExecutionResult(
                server_id="", tool_name="",
                message_id=msg_id, success=False, error=err,
            )

        tool_id, args = parsed
        server_id, _, tool_name = tool_id.partition(".")
        if not tool_name:
            err = (
                "tool_run command 'tool' field must be '<server>.<tool>' "
                f"(see the # Available tools section). Got: {tool_id!r}."
            )
            msg_id = await self._write_error_message(
                investigation_id, branch_id, err, at_turn,
            )
            return ToolExecutionResult(
                server_id=server_id, tool_name="",
                message_id=msg_id, success=False, error=err,
            )

        adapter = get_adapter(server_id, tool_name)
        if adapter is None:
            err = (
                f"No tool '{server_id}.{tool_name}' is available for this "
                f"target. Re-read the # Available tools section in the "
                f"prompt -- only tools listed there will execute."
            )
            msg_id = await self._write_error_message(
                investigation_id, branch_id, err, at_turn,
            )
            return ToolExecutionResult(
                server_id=server_id, tool_name=tool_name,
                message_id=msg_id, success=False, error=err,
            )

        bridge = self._bridges.get(server_id)
        if bridge is None:
            err = f"No bridge configured for MCP server {server_id!r}"
            msg_id = await self._write_error_message(
                investigation_id, branch_id, err, at_turn,
            )
            return ToolExecutionResult(
                server_id=server_id, tool_name=tool_name,
                message_id=msg_id, success=False, error=err,
            )
        # Pre-call: auto-correct audit_mcp index_id if the agent passed
        # a known placeholder or omitted it entirely. Saves a 30s+ LLM
        # round-trip per call that would otherwise come back as
        # "Unknown index: 'main'" or "missing required kwarg(s)
        # ['index_id']".
        if server_id == "audit_mcp":
            args = await self._maybe_correct_index_id(investigation_id, args)
        # fix: HARD-BLOCK identical retries BEFORE the bridge call.
        # The circuit-breaker text (line 314+) augments the error
        # message after the call lands, but agents still issue the
        # same call up to 51 times per branch (observed live on
        # one branch, 63x read_function('init')). The
        # augmented warning is no deterrent because each retry
        # produces a new turn worth of LLM thinking that re-derives
        # 'this might work this time'.
        #
        # New rule: when the SAME (server.tool, canonical args)
        # has failed in this branch ≥ _HARD_BLOCK_REPEAT_LIMIT
        # times consecutively, refuse the dispatch entirely and
        # hand back a synthetic error response WITHOUT making the
        # network call. The agent burns one LLM turn reading the
        # block notice; the bridge / upstream MCP roundtrip is
        # saved. Limit is intentionally generous (3) so legitimately-
        # transient errors (httpx pool exhaustion, audit-mcp cold
        # rebuild) still get retried.
        hard_block_count = await self._count_prior_failures(
            branch_id, server_id, tool_name, args,
        )
        if hard_block_count >= _HARD_BLOCK_REPEAT_LIMIT:
            err = (
                f"{server_id}.{tool_name} HARD-BLOCKED: this exact call "
                f"(args={sorted(args)}) has failed {hard_block_count} "
                f"times in this branch. The bridge will NOT execute "
                f"this call again -- every retry produces the same "
                f"failure pattern. Choose a different tool OR a "
                f"different args shape OR submit terminal_submit "
                f"declaring you cannot proceed on this lead."
            )
            msg_id = await self._write_error_message(
                investigation_id, branch_id, err, at_turn,
            )
            _log.warning(
                "tool_executor HARD-BLOCK %s.%s after %d prior failures "
                "(branch=%s args=%s)",
                server_id, tool_name, hard_block_count, branch_id[:8],
                sorted(args),
            )
            return ToolExecutionResult(
                server_id=server_id, tool_name=tool_name,
                message_id=msg_id, success=False, error=err,
            )

        try:
            raw = await bridge.forward(action=tool_name, **args)
        except (httpx.HTTPError, OSError, RuntimeError, ValueError, TypeError) as exc:
            # fix §197 -- broadened from (OSError, TimeoutError,
            # RuntimeError). `bridge.forward` reaches into httpx
            # (httpx.HTTPError, httpx.PoolTimeout -- neither one is
            # an OSError subclass on every platform), pydantic.ValidationError
            # covering malformed bridge response envelopes, and arbitrary
            # provider errors from sync→async wrappers. A miss here
            # used to crash the worker turn instead of writing the
            # error envelope the engine expects.
            _log.exception(
                "tool_executor: bridge.forward raised for %s.%s",
                server_id, tool_name,
            )
            err = f"{server_id}.{tool_name} bridge call raised: {exc}"
            msg_id = await self._write_error_message(
                investigation_id, branch_id, err, at_turn,
            )
            return ToolExecutionResult(
                server_id=server_id, tool_name=tool_name,
                message_id=msg_id, success=False, error=err,
            )

        # fix §202 -- positive whitelist (writer contract closure for W1
        # §214/§215). Treat anything outside _SUCCESS_STATUSES as an
        # executor-visible error: includes legitimate `error` envelopes,
        # the async in-progress values (pending/queued/running) that mean
        # "no payload yet", and any unknown/malformed status string the
        # bridge let slip through.
        _status = raw.get("status")
        if _status not in _SUCCESS_STATUSES:
            raw_err = raw.get("error") or ""
            if not raw_err and _status:
                raw_err = (
                    f"unexpected status {_status!r} (success requires "
                    f"one of {sorted(_SUCCESS_STATUSES)})"
                )
            err = f"{server_id}.{tool_name} returned error: {raw_err!r}"
            # Common false-negative: audit_mcp.read_function says
            # 'Function X not indexed' -- but the identifier is a
            # #define macro, not a function. Append a hint so the
            # agent's next turn calls audit_mcp.search_macros instead
            # of grinding on more search_source attempts.
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
            # Repeat-failure circuit breaker. Two complementary triggers:
            #
            # (1) Args-identical: same (server, tool, args) call has
            #     already failed N times on this branch. Catches the
            #     classic "ngx_http_proxy_set_body doesn't exist, retry
            #     forever" pattern where the agent reissues the exact
            #     same call without varying anything.
            #
            # (2) Error-class match: same (server, tool) call failed
            #     sharing the SAME ERROR PREFIX N times on this branch
            #     regardless of args. Catches the "fuzzing_targets
            #     keeps getting unknown-kwarg 'threshold' / 'cutoff' /
            #     'min_score'" pattern where the agent varies the bad
            #     arg name but never realizes the param doesn't exist
            #     at all. Without this, breaker #1 never fires because
            #     each new bogus kwarg looks like a fresh call.
            #
            # Either trigger >= 2 (i.e. this is the 3rd offence) forces
            # the breaker hint. Error-class match takes priority when
            # both fire because its message is more actionable for the
            # contract-violation case.
            repeat_count = await self._count_prior_failures(
                branch_id, server_id, tool_name, args,
            )
            error_class_count = await self._count_prior_error_class(
                branch_id, server_id, tool_name, raw_err,
            )
            triggered_by_class = error_class_count >= 2
            triggered_by_args = repeat_count >= 2
            if triggered_by_class or triggered_by_args:
                ident = (
                    args.get("name") or args.get("function")
                    or args.get("pattern") or "<args>"
                )
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

                # Pick the breaker text based on which CLASS the error
                # falls into. Wrong-kwarg / missing-kwarg / type-mismatch
                # all share "the arg shape is wrong, re-read signature"
                # advice. resource_not_found is the opposite -- arg shape
                # is fine, the VALUE is wrong (typo, stale identifier,
                # path the agent copied from somewhere stale). Telling
                # the agent to "re-read the tool signature" in that case
                # sends them down the wrong rabbit hole.
                err_class = classify_contract_error(raw_err) if triggered_by_class else None
                if err_class == "resource_not_found":
                    err += (
                        f"\n\n*** REPEAT-FAILURE CIRCUIT BREAKER (resource-not-found) ***\n"
                        f"You have called {server_id}.{tool_name} {error_class_count + 1} times "
                        f"in this branch and EACH attempt failed because the resource "
                        f"identifier (path / id / file) you passed does not exist on disk "
                        f"or in the index. The arg NAMES are fine -- the VALUE is wrong. "
                        f"Typing a new typo of the same identifier will not help: every "
                        f"version you've tried so far has missed.\n\n"
                        f"Likely root cause: you are reconstructing a long identifier "
                        f"(SHA-derived APK path, hex index id, GUID) from memory and "
                        f"corrupting it each time. SHA-256 paths are 64 hex chars + extension; "
                        f"a single dropped char or stray space breaks the lookup.\n\n"
                        f"PIVOT -- do NOT call {server_id}.{tool_name} with another typed "
                        f"identifier. Pull the canonical value from an existing observable "
                        f"in this branch's case_state (a prior tool result, target metadata, "
                        f"or the initial-question text), copy it byte-for-byte, OR pivot to "
                        f"a different tool that takes a logical identifier (target_id, "
                        f"investigation_id) instead of a raw filesystem path."
                        + "\nOR submit a finding noting the obstacle."
                    )
                elif triggered_by_class:
                    # Contract-violation path: the error itself names
                    # the wrong kwarg / missing arg. The bridge
                    # validator (audit_mcp_bridge._validate_kwargs)
                    # already injected a 'did you mean' hint into the
                    # raw error -- reinforce the STOP signal at the
                    # breaker level so the agent realizes it's looping.
                    err += (
                        f"\n\n*** REPEAT-FAILURE CIRCUIT BREAKER (error-class match) ***\n"
                        f"You have called {server_id}.{tool_name} {error_class_count + 1} times "
                        f"in this branch and EACH attempt failed with the same error class. "
                        f"Varying the arg VALUE will not help -- the arg NAME or shape is "
                        f"wrong. Re-read the tool signature in the # Available tools section "
                        f"of the prompt above. The valid parameter list is named in the error.\n\n"
                        f"PIVOT -- do NOT call {server_id}.{tool_name} again until you have "
                        f"a different param NAME, or call a different tool entirely."
                        + ("\nTry one of:\n" + "\n".join(alternatives) if alternatives else "")
                        + "\nOR submit a finding noting the obstacle."
                    )
                else:
                    err += (
                        f"\n\n*** REPEAT-FAILURE CIRCUIT BREAKER ***\n"
                        f"You have already issued THIS EXACT CALL "
                        f"{repeat_count + 1} times in this branch -- all failed with the "
                        f"same error. STOP. The identifier {ident!r} does not exist "
                        f"in the form you expect. Possible reasons:\n"
                        f"  (a) it's a directive name, not a function (directives are\n"
                        f"      registered in a static array, not exported as a function\n"
                        f"      with that exact name);\n"
                        f"  (b) it's a macro / typedef / constant, not a function;\n"
                        f"  (c) it never existed and a sibling persona hallucinated it.\n\n"
                        f"PIVOT -- your next tool call MUST NOT be the same call again."
                        + ("\nTry one of:\n" + "\n".join(alternatives) if alternatives else "")
                        + "\nOR submit a finding noting 'identifier not present in tree'."
                    )
            msg_id = await self._write_error_message(
                investigation_id, branch_id, err, at_turn,
            )
            return ToolExecutionResult(
                server_id=server_id, tool_name=tool_name,
                message_id=msg_id, success=False, error=err,
            )

        ctx = AdapterContext(
            mcp_server_id=server_id,
            tool_name=tool_name,
            investigation_id=investigation_id,
            branch_id=branch_id,
            call_id=call_id,
            args=args,
        )
        adapter_result = adapter(raw, ctx)

        # Survey-streak pivot hint. The agent on variant_hunt /
        # discovery investigations tends to keep calling survey tools
        # (attack_surface, complexity_hotspots, fuzzing_targets,
        # search_functions) for 5-10 turns while debating in
        # "adversarial deliberation" reasoning blocks, and only reads
        # actual source bodies once near the end.
        #
        # The hint is appended to BOTH:
        #   (a) the rendered text payload -- so it shows up in the UI
        #       timeline next to the tool result, and
        #   (b) the observables_delta under the reserved key
        #       `_directive.pivot` -- so the next turn's
        #       render_case_model() surfaces it in the agent's prompt.
        # Without (b) the directive was written to a DB message but
        # never made it into the agent's next-turn context: case_state
        # only renders observables, not prior tool result text.
        pivot_hint = await self._survey_streak_hint(
            branch_id, server_id, tool_name,
        )
        if pivot_hint:
            if isinstance(adapter_result.payload, dict):
                existing = adapter_result.payload.get("text") or ""
                adapter_result.payload["text"] = (
                    existing.rstrip() + "\n\n" + pivot_hint
                )
            # fix §199 -- keep the single-string `_directive.pivot` for
            # the prompt renderer (which filters non-string directive
            # values), AND append a structured entry to the
            # `_directive.pivot_history` array so the operator (and
            # forensics) can audit every nudge the agent received on
            # this branch. Capped to the last 20 entries to keep the
            # observables blob bounded.
            existing_history = await self._load_pivot_history(branch_id)
            existing_history.append({
                "at_ts": utc_now().isoformat(),
                "server_id": server_id,
                "tool_name": tool_name,
                "hint": pivot_hint,
            })
            adapter_result.observables_delta = {
                **(adapter_result.observables_delta or {}),
                "_directive.pivot": pivot_hint,
                "_directive.pivot_history": existing_history[-20:],
            }
        else:
            # Clear the pivot directive ONLY when the agent satisfied
            # it by calling an actual read/trace tool. Surveys obviously
            # don't satisfy a pivot, but neither does search_functions
            # / search_macros / semantic_search -- those find candidates
            # without reading any source body. The directive stays put
            # until the agent commits to a real read.
            if (server_id, tool_name) in self._read_tools():
                adapter_result.observables_delta = {
                    **(adapter_result.observables_delta or {}),
                    "_directive.pivot": "",
                }

        # fix §203 -- single UoW write: tool result message AND the
        # observables delta land atomically so a concurrent reader
        # cannot observe one half without the other.
        msg_id = await self._persist_result_and_observables(
            investigation_id, branch_id,
            payload_kind=adapter_result.payload_kind,
            payload=adapter_result.payload,
            observables_delta=adapter_result.observables_delta or {},
            at_turn=at_turn,
        )

        # fix §81 -- auto-steering rule evaluators key off raw_result
        # shape; a tool that legitimately returns no payload (e.g.
        # list_indexes on an empty repo, callees_of for a leaf
        # function) was triggering rule misfires. Skip when the result
        # is empty AND status is not 'error' (legitimate no-output
        # case). Errors still flow through so contract-violation rules
        # (kwarg rejected, file not found) keep firing.
        result_is_empty = not raw or (
            isinstance(raw, dict)
            and not any(
                k for k in raw.keys()
                if k not in {"status", "action", "kwargs"}
            )
        )
        result_status = raw.get("status") if isinstance(raw, dict) else None
        if result_is_empty and result_status != "error":
            _log.debug(
                "auto_steering SKIP (empty result, non-error) inv=%s "
                "branch=%s tool=%s",
                investigation_id, branch_id, tool_name,
            )
        else:
            # Auto-steering: examine raw tool result for known dead-end
            # patterns (read_lines past EOF, read_function indexer
            # fault). If a rule fires, post an operator-kind message
            # to the investigation just like the human operator would
            # -- same DB write, same prompt position on next turn,
            # same ACK contract. Best-effort; failures here NEVER
            # abort the tool result path.
            #
            # fix §80 (PARTIAL) -- auto-steering still uses its own
            # internal UoWs for the operator-message post; full
            # atomicity with the §203 single UoW above requires
            # extending ``maybe_post_auto_steering`` to accept an
            # external session, which is bundled into the E16 cleanup.
            # The remaining race is theoretical here: the next agent
            # turn cannot start until execute() returns, so the gap
            # between the §203 commit and the auto-steering post is
            # never observable to the agent itself; only an out-of-band
            # reader (operator UI streaming inv messages) could see
            # the result-message before the steering operator-message.
            # fix §198 -- bridge_base_url comes from the audit_mcp
            # bridge instance, not a hardcoded literal. See
            # AuditMcpBridgeTool.base_url(); falls back to default
            # only when the bridge stub lacks the accessor.
            audit_mcp_bridge = self._bridges.get("audit_mcp")
            if hasattr(audit_mcp_bridge, "base_url"):
                try:
                    bridge_base_url = await audit_mcp_bridge.base_url()
                except (AttributeError, RuntimeError, OSError, ValueError, TypeError) as exc:
                    _log.info(
                        "tool_executor: bridge.base_url() failed "
                        "(%s: %s); falling back to default",
                        type(exc).__name__, exc,
                        exc_info=True,
                    )
                    bridge_base_url = "http://127.0.0.1:18822"
            else:
                bridge_base_url = "http://127.0.0.1:18822"
            try:
                posted_id = await maybe_post_auto_steering(
                    investigation_id=investigation_id,
                    branch_id=branch_id,
                    server_id=server_id,
                    tool_name=tool_name,
                    args=args,
                    raw_result=raw if isinstance(raw, dict) else {},
                    bridge_base_url=bridge_base_url,
                    message_model=VRInvestigationMessageRecord,
                    branch_model=VRInvestigationBranchRecord,
                )
                if posted_id:
                    _log.info(
                        "auto_steering POSTED inv=%s branch=%s tool=%s "
                        "msg=%s",
                        investigation_id, branch_id, tool_name, posted_id,
                    )
            except (OSError, RuntimeError, ValueError, TypeError, AttributeError, SQLAlchemyError, httpx.HTTPError) as exc:
                _log.warning(
                    "auto_steering failed (best-effort): %s", exc,
                    exc_info=True,
                )

        _log.info(
            "tool_executor OK server=%s tool=%s args=%s summary=%s",
            server_id, tool_name, list(args.keys()), adapter_result.summary,
        )
        return ToolExecutionResult(
            server_id=server_id, tool_name=tool_name,
            message_id=msg_id, success=True,
        )



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


