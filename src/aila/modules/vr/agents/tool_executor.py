"""Tool executor — dispatches tool_run decisions through MCP bridges (M3.R-3).

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
observables — the engine sees the error in the next turn and can
recover.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from sqlmodel import select as _select

from aila.modules.vr.agents.mcp_adapters import (
    AdapterContext,
    get_adapter,
)
from aila.modules.vr.contracts import PayloadKind, SenderKind
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
)
from aila.modules.vr.tools.android_mcp_bridge import AndroidMcpBridgeTool
from aila.modules.vr.tools.audit_mcp_bridge import AuditMcpBridgeTool
from aila.modules.vr.tools.ida_bridge import IDABridgeTool
from aila.platform.contracts._common import utc_now
from aila.platform.uow import UnitOfWork

__all__ = [
    "ToolExecutionResult",
    "ToolExecutor",
]

_log = logging.getLogger(__name__)


@dataclass(slots=True)
class ToolExecutionResult:
    """Outcome of one tool_run dispatch."""

    server_id: str
    tool_name: str
    message_id: str | None
    success: bool
    error: str = ""


class ToolExecutor:
    """Per-investigation tool dispatcher. Injects the three MCP bridges
    (ida_headless, audit_mcp, android_mcp).

    Tests can construct with fake bridges that have a ``.forward(action, **kwargs)``
    method returning a canned dict.
    """

    # Known placeholder strings agents hallucinate in place of a real
    # audit-mcp index_id. Each one costs an LLM retry-storm worth of
    # wall-clock when it round-trips through the bridge and back to
    # the agent as "Unknown index". Auto-substitute with the actual
    # index_id resolved from the investigation's primary target.
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
        self._bridges: dict[str, Any] = {
            "ida_headless": ida,
            "audit_mcp": audit_mcp,
            "android_mcp": android_mcp,
        }
        # Per-process cache: investigation_id -> resolved audit_mcp index_id
        # (or empty string when the investigation's target has no source
        # repo). Filled lazily on first use per investigation, never
        # invalidated — the index_id of a target doesn't change.
        self._inv_index_id_cache: dict[str, str] = {}

    async def execute(
        self,
        investigation_id: str,
        branch_id: str,
        command_raw: str,
        at_turn: int | None = None,
    ) -> ToolExecutionResult:
        """Dispatch one tool call. Writes a result message + updates observables."""
        call_id = str(uuid4())

        parsed = _parse_command(command_raw)
        if parsed is None:
            # Empty / malformed tool_run is by far the most common loop
            # mode the agent gets stuck in: it picks action=tool_run but
            # produces no command string. The previous behaviour was a
            # plain error text that the LLM ignored on the next turn,
            # producing the same empty command, looping until the turn
            # cap. Two-layer mitigation:
            #   (a) FIRST malformed command on this branch → return the
            #       error AS BEFORE, but include the "you should have
            #       picked observe" hint so the LLM has a clear next move.
            #   (b) SECOND consecutive malformed command → STOP message
            #       with explicit submit/observe options; the agent has
            #       proven it cannot recover via tool_run.
            # The original threshold of >= 2 fired the STOP message only
            # after 3 broken commands; observed b53d3bb0 had branches
            # producing 4-8 consecutive empty commands without the STOP
            # ever firing because the counter only sees the LAST run on
            # this branch (not the whole history).
            malformed_count = await self._count_consecutive_malformed(
                branch_id,
            )
            if malformed_count >= 1:
                err = (
                    "STOP — you have produced 2 consecutive empty or "
                    "malformed tool_run commands. The engine cannot "
                    "dispatch an empty command. Your next turn MUST be "
                    "one of:\n"
                    "  (a) action=tool_run with valid JSON command: "
                    '{\"tool\": \"audit_mcp.read_function\", \"args\": {\"name\": \"...\"}}\n'
                    "  (b) action=submit if you have enough evidence to "
                    "submit your findings.\n"
                    "  (c) action=reasoning to think without a tool call.\n\n"
                    "Pick (c) if you are unsure — reasoning is always safe "
                    "and lets you think before dispatching another tool. "
                    "(There is NO 'observe' action — only tool_run / "
                    "reasoning / submit / submit_outcome_review / "
                    "script_execute.)"
                )
            else:
                err = (
                    "Malformed tool_run command — expected JSON with "
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
                f"prompt — only tools listed there will execute."
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

        try:
            raw = await bridge.forward(action=tool_name, **args)
        except (OSError, TimeoutError, RuntimeError) as exc:
            err = f"{server_id}.{tool_name} bridge call raised: {exc}"
            msg_id = await self._write_error_message(
                investigation_id, branch_id, err, at_turn,
            )
            return ToolExecutionResult(
                server_id=server_id, tool_name=tool_name,
                message_id=msg_id, success=False, error=err,
            )

        if raw.get("status") == "error":
            raw_err = raw.get("error") or ""
            err = f"{server_id}.{tool_name} returned error: {raw_err!r}"
            # Common false-negative: audit_mcp.read_function says
            # 'Function X not indexed' — but the identifier is a
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
                    f"Try audit_mcp.search_macros(name={requested!r}) BEFORE giving up — "
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
            #     with the SAME ERROR PREFIX N times on this branch
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

                if triggered_by_class:
                    # Contract-violation path: the error itself names
                    # the wrong kwarg / missing arg. The bridge
                    # validator (audit_mcp_bridge._validate_kwargs)
                    # already injected a 'did you mean' hint into the
                    # raw error — reinforce the STOP signal at the
                    # breaker level so the agent realizes it's looping.
                    err += (
                        f"\n\n*** REPEAT-FAILURE CIRCUIT BREAKER (error-class match) ***\n"
                        f"You have called {server_id}.{tool_name} {error_class_count + 1} times "
                        f"in this branch and EACH attempt failed with the same error class. "
                        f"Varying the arg VALUE will not help — the arg NAME or shape is "
                        f"wrong. Re-read the tool signature in the # Available tools section "
                        f"of the prompt above. The valid parameter list is named in the error.\n\n"
                        f"PIVOT — do NOT call {server_id}.{tool_name} again until you have "
                        f"a different param NAME, or call a different tool entirely."
                        + ("\nTry one of:\n" + "\n".join(alternatives) if alternatives else "")
                        + "\nOR submit a finding noting the obstacle."
                    )
                else:
                    err += (
                        f"\n\n*** REPEAT-FAILURE CIRCUIT BREAKER ***\n"
                        f"You have already issued THIS EXACT CALL "
                        f"{repeat_count + 1} times in this branch — all failed with the "
                        f"same error. STOP. The identifier {ident!r} does not exist "
                        f"in the form you expect. Possible reasons:\n"
                        f"  (a) it's a directive name, not a function (directives are\n"
                        f"      registered in a static array, not exported as a function\n"
                        f"      with that exact name);\n"
                        f"  (b) it's a macro / typedef / constant, not a function;\n"
                        f"  (c) it never existed and a sibling persona hallucinated it.\n\n"
                        f"PIVOT — your next tool call MUST NOT be the same call again."
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
        #   (a) the rendered text payload — so it shows up in the UI
        #       timeline next to the tool result, and
        #   (b) the observables_delta under the reserved key
        #       `_directive.pivot` — so the next turn's
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
            # Reserved directive observable. Overwrites prior pivot on
            # every fire so the agent only sees the most recent one;
            # cleared when the agent finally makes a non-survey call
            # (see _clear_directive_on_pivot_success below).
            adapter_result.observables_delta = {
                **(adapter_result.observables_delta or {}),
                "_directive.pivot": pivot_hint,
            }
        else:
            # Clear the pivot directive ONLY when the agent satisfied
            # it by calling an actual read/trace tool. Surveys obviously
            # don't satisfy a pivot, but neither does search_functions
            # / search_macros / semantic_search — those find candidates
            # without reading any source body. The directive stays put
            # until the agent commits to a real read.
            if (server_id, tool_name) in self._READ_TOOLS:
                adapter_result.observables_delta = {
                    **(adapter_result.observables_delta or {}),
                    "_directive.pivot": "",
                }

        msg_id = await self._write_result_message(
            investigation_id, branch_id,
            payload_kind=adapter_result.payload_kind,
            payload=adapter_result.payload,
            at_turn=at_turn,
        )
        await self._merge_observables(branch_id, adapter_result.observables_delta)

        # Auto-steering: examine raw tool result for known dead-end
        # patterns (read_lines past EOF, read_function indexer fault).
        # If a rule fires, post an operator-kind message to the
        # investigation just like the human operator would — same DB
        # write, same prompt position on next turn, same ACK contract.
        # Best-effort; failures here NEVER abort the tool result path.
        from aila.modules.vr.agents.auto_steering import (  # noqa: PLC0415
            maybe_post_auto_steering,
        )
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
            )
            if posted_id:
                _log.info(
                    "auto_steering POSTED inv=%s branch=%s tool=%s msg=%s",
                    investigation_id, branch_id, tool_name, posted_id,
                )
        except Exception as exc:  # noqa: BLE001
            _log.warning("auto_steering failed (best-effort): %s", exc)

        _log.info(
            "tool_executor OK server=%s tool=%s args=%s summary=%s",
            server_id, tool_name, list(args.keys()), adapter_result.summary,
        )
        return ToolExecutionResult(
            server_id=server_id, tool_name=tool_name,
            message_id=msg_id, success=True,
        )

    async def _write_result_message(
        self,
        investigation_id: str,
        branch_id: str,
        *,
        payload_kind: PayloadKind,
        payload: dict[str, Any],
        at_turn: int | None,
    ) -> str:
        async with UnitOfWork() as uow:
            msg = VRInvestigationMessageRecord(
                investigation_id=investigation_id,
                branch_id=branch_id,
                sender_kind=SenderKind.ENGINE.value,
                sender_id="tool_executor",
                payload_kind=payload_kind.value,
                payload_json=json.dumps(payload),
                at_turn=at_turn,
                evidence_refs_json="[]",
            )
            uow.session.add(msg)
            await uow.session.commit()
            await uow.session.refresh(msg)
            return msg.id

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
        from logging import getLogger  # noqa: PLC0415
        getLogger(__name__).info(
            "tool_executor: auto-corrected index_id inv=%s "
            "from %r to %r (saves an LLM round-trip)",
            investigation_id, current, resolved,
        )
        return new_args

    async def _resolve_index_id(self, investigation_id: str) -> str:
        """Resolve investigation -> primary target -> audit_mcp_index_id.

        Returns empty string when no source-repo target / no audit-mcp
        index for this investigation.
        """
        if investigation_id in self._inv_index_id_cache:
            return self._inv_index_id_cache[investigation_id]
        try:
            from sqlmodel import select  # noqa: PLC0415

            from aila.modules.vr.db_models import (  # noqa: PLC0415
                VRInvestigationRecord,
                VRTargetRecord,
            )
            from aila.platform.uow import UnitOfWork  # noqa: PLC0415

            async with UnitOfWork() as uow:
                inv = (await uow.session.exec(
                    select(VRInvestigationRecord).where(
                        VRInvestigationRecord.id == investigation_id,
                    ),
                )).first()
                if inv is None or not inv.target_id:
                    self._inv_index_id_cache[investigation_id] = ""
                    return ""
                target = (await uow.session.exec(
                    select(VRTargetRecord).where(
                        VRTargetRecord.id == inv.target_id,
                    ),
                )).first()
                if target is None or not target.mcp_handles_json:
                    self._inv_index_id_cache[investigation_id] = ""
                    return ""
            import json  # noqa: PLC0415
            try:
                handles = json.loads(target.mcp_handles_json or "{}")
            except (ValueError, TypeError):
                handles = {}
            resolved = str(handles.get("audit_mcp_index_id") or "")
            self._inv_index_id_cache[investigation_id] = resolved
            return resolved
        except (OSError, RuntimeError, ImportError, AttributeError):
            return ""

    async def _write_error_message(
        self,
        investigation_id: str,
        branch_id: str,
        error_text: str,
        at_turn: int | None,
    ) -> str:
        return await self._write_result_message(
            investigation_id, branch_id,
            payload_kind=PayloadKind.TEXT,
            payload={"text": error_text, "is_error": True},
            at_turn=at_turn,
        )


    async def _count_consecutive_malformed(
        self,
        branch_id: str,
    ) -> int:
        """Count consecutive recent malformed-command error messages on this
        branch. Walks backward from the latest message; stops at the first
        non-error or non-malformed message.
        """
        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                _select(VRInvestigationMessageRecord)
                .where(
                    VRInvestigationMessageRecord.branch_id == branch_id,
                    VRInvestigationMessageRecord.sender_kind == "engine",
                )
                .order_by(VRInvestigationMessageRecord.created_at.desc())
                .limit(10)
            )).all()

        count = 0
        for row in rows:
            try:
                payload = json.loads(row.payload_json or "{}")
            except (ValueError, TypeError):
                break
            if payload.get("is_error") and "Malformed tool_run" in str(payload.get("text", "")):
                count += 1
            else:
                break
        return count
    async def _count_prior_failures(
        self,
        branch_id: str,
        server_id: str,
        tool_name: str,
        args: dict[str, Any],
    ) -> int:
        """Count prior error-messages on this branch with the same
        ``server_id.tool_name`` and the same ``args``.

        Args are JSON-canonicalised (sorted keys) for the comparison
        so semantic-equivalence holds regardless of dict order. Used
        by the repeat-failure circuit breaker — when the same tool
        call has failed 3+ times on the same branch, the executor
        injects a hard pivot hint into the next error.
        """
        canonical = json.dumps(args, sort_keys=True, default=str)
        prefix = f"{server_id}.{tool_name} returned error"
        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                _select(VRInvestigationMessageRecord)
                .where(VRInvestigationMessageRecord.branch_id == branch_id)
                .where(VRInvestigationMessageRecord.payload_kind == PayloadKind.TEXT.value)
                .order_by(VRInvestigationMessageRecord.created_at.desc())
                .limit(50)
            )).all()
        count = 0
        for r in rows:
            try:
                payload = json.loads(r.payload_json or "{}")
            except (ValueError, TypeError):
                continue
            if not payload.get("is_error"):
                continue
            text = str(payload.get("text") or "")
            if not text.startswith(prefix):
                continue
            # Walk back the call that produced this error: look at the
            # message immediately before with payload_kind=tool_call and
            # check whether its args match.
            prior_call = next(
                (mm for mm in await self._messages_before(uow_branch_id=branch_id, before_id=r.id)
                 if mm[0] == "tool_call"),
                None,
            )
            if prior_call is None:
                continue
            try:
                cmd = json.loads(json.loads(prior_call[1]).get("command") or "{}")
                cmd_args = cmd.get("args") or {}
                if json.dumps(cmd_args, sort_keys=True, default=str) == canonical:
                    count += 1
            except (ValueError, TypeError):
                continue
        return count

    async def _count_prior_error_class(
        self,
        branch_id: str,
        server_id: str,
        tool_name: str,
        raw_err: Any,
    ) -> int:
        """Count prior error-messages on this branch with the same
        ``server_id.tool_name`` whose ``raw_err`` shares the same
        contract-violation class as the current error, regardless of
        args.

        Error-class matching is intentionally narrow — only fires when
        ``raw_err`` looks like a bridge-validator or upstream
        contract-violation message (unknown kwarg, missing required
        kwarg, unexpected keyword argument, signature mismatch). For
        those classes, varying the arg VALUE never helps — the agent
        is calling the tool with the wrong arg NAME or shape and
        needs to pivot, not retry. For other error classes (function
        not indexed, file not found, timeout, etc.) varying args can
        legitimately help, so this helper returns 0 and falls back to
        the strict args-identical counter.
        """
        if not isinstance(raw_err, str):
            return 0
        class_key = self._classify_contract_error(raw_err)
        if class_key is None:
            return 0

        prefix = f"{server_id}.{tool_name} returned error"
        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                _select(VRInvestigationMessageRecord)
                .where(VRInvestigationMessageRecord.branch_id == branch_id)
                .where(VRInvestigationMessageRecord.payload_kind == PayloadKind.TEXT.value)
                .order_by(VRInvestigationMessageRecord.created_at.desc())
                .limit(50)
            )).all()
        count = 0
        for r in rows:
            try:
                payload = json.loads(r.payload_json or "{}")
            except (ValueError, TypeError):
                continue
            if not payload.get("is_error"):
                continue
            text = str(payload.get("text") or "")
            if not text.startswith(prefix):
                continue
            if self._classify_contract_error(text) == class_key:
                count += 1
        return count

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

    # Tools whose call genuinely satisfies a "READ SOURCE / TRACE FLOW"
    # pivot directive. Only these clear `_directive.pivot`. Without this
    # gate, any non-survey call (e.g. semantic_search, search_macros,
    # search_functions) would silently drop the pivot even though no
    # function body was actually read.
    _READ_TOOLS: frozenset[tuple[str, str]] = frozenset({
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

        Returns None unless the streak fires — non-survey calls reset
        the counter immediately. The hint is intentionally short and
        actionable so it lands at the top of the agent's next-turn
        attention without crowding out the actual tool output.
        """
        if (server_id, tool_name) not in self._SURVEY_TOOLS:
            return None
        # Walk back the last 4 tool_call payloads on this branch and
        # count consecutive surveys (excluding the current one — it's
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
            tool_id = (cmd.get("tool") or "").partition(".")
            key = (tool_id[0], tool_id[2])
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
            f"  - audit_mcp.read_function(name=<top candidate>, file_path=<path>) — read the actual body\n"
            f"  - audit_mcp.taint_paths_to(name=<sink>) — trace user input to the candidate\n"
            f"  - audit_mcp.callers_of(name=<candidate>) — who reaches this function\n"
            f"  - audit_mcp.entrypoint_paths_to(name=<candidate>) — what untrusted-input entrypoints reach it\n"
            f"  - OR submit a finding/AssessmentReport if no candidate is concrete enough to read\n"
            f"Adversarial deliberation is consuming turns without acquiring evidence. Read source NOW."
        )

    @staticmethod
    def _classify_contract_error(text: str) -> str | None:
        """Return a coarse class key for contract-violation errors, or
        None when ``text`` doesn't look like one.

        Classes:
          - "unknown_kwarg"  — bridge validator OR upstream Python
                              TypeError about an unexpected keyword
          - "missing_kwarg"  — required kwarg not provided
          - "type_mismatch"  — wrong type passed
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
        return None

    async def _messages_before(
        self, *, uow_branch_id: str, before_id: str,
    ) -> list[tuple[str, str]]:
        """Helper for _count_prior_failures: returns up to 3 messages
        immediately before ``before_id`` on the same branch as
        ``(payload_kind, payload_json)`` tuples."""
        async with UnitOfWork() as uow:
            anchor = (await uow.session.exec(
                _select(VRInvestigationMessageRecord).where(
                    VRInvestigationMessageRecord.id == before_id,
                )
            )).first()
            if anchor is None:
                return []
            rows = (await uow.session.exec(
                _select(VRInvestigationMessageRecord)
                .where(VRInvestigationMessageRecord.branch_id == uow_branch_id)
                .where(VRInvestigationMessageRecord.created_at < anchor.created_at)
                .order_by(VRInvestigationMessageRecord.created_at.desc())
                .limit(3)
            )).all()
        return [(r.payload_kind, r.payload_json or "") for r in rows]

    # Cap on case_state.observables size. Each tool call typically
    # adds 1-2 keys; an investigation that runs for 200+ turns can
    # accumulate thousands of stale observable entries and balloon
    # the case_state_json blob into megabytes. 200 is enough for
    # ~100 turns of context with ~2 keys/turn and keeps the column
    # bounded. `_directive.*` keys are kept regardless of count.
    _MAX_OBSERVABLES: int = 200

    async def _merge_observables(
        self,
        branch_id: str,
        delta: dict[str, Any],
    ) -> None:
        if not delta:
            return
        async with UnitOfWork() as uow:
            branch = (await uow.session.exec(
                _select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.id == branch_id,
                )
            )).first()
            if branch is None:
                _log.warning(
                    "tool_executor: branch %s vanished during observables merge",
                    branch_id,
                )
                return
            try:
                case_state = json.loads(branch.case_state_json or "{}")
            except json.JSONDecodeError:
                case_state = {}
            observables = case_state.get("observables")
            if not isinstance(observables, dict):
                observables = {}
            observables.update({str(k): v for k, v in delta.items()})
            # Bound the dict size. Eviction strategy: keep ALL
            # `_directive.*` keys (steering must survive), drop the
            # OLDEST non-directive keys by dict insertion order
            # (Python 3.7+ guarantees insertion order in dicts).
            if len(observables) > self._MAX_OBSERVABLES:
                directives = {
                    k: v for k, v in observables.items()
                    if str(k).startswith("_directive.")
                }
                non_directives = [
                    (k, v) for k, v in observables.items()
                    if not str(k).startswith("_directive.")
                ]
                keep_n = max(0, self._MAX_OBSERVABLES - len(directives))
                kept = dict(non_directives[-keep_n:])
                observables = {**kept, **directives}
            case_state["observables"] = observables
            branch.case_state_json = json.dumps(case_state)
            branch.updated_at = utc_now()
            uow.session.add(branch)
            await uow.commit()


def _parse_command(raw: str) -> tuple[str, dict[str, Any]] | None:
    """Parse a tool_run command string into (tool_id, args).

    Expected JSON shape:
        {"tool": "<server>.<tool>", "args": {<kwargs>}}
    Returns None on any parse failure so the executor can report the
    error back to the engine via a TEXT message.
    """
    if not raw or not raw.strip():
        return None
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        _log.warning(
            "tool_executor._parse_command: JSON decode failed (raw len=%d): %s",
            len(raw), exc,
        )
        return None
    if not isinstance(decoded, dict):
        return None
    tool_id = decoded.get("tool")
    args = decoded.get("args", {})
    if not isinstance(tool_id, str) or not isinstance(args, dict):
        return None
    return tool_id, args
