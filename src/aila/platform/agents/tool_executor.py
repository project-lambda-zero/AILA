"""Shared ToolExecutor helper base (RFC-03 Phase 4b, helper extraction).

The vr and malware tool executors carried byte-identical copies of the
tool-result persistence, circuit-breaker counting, and observable-merge
helpers -- differing only in the module-specific message / branch record
types. This base owns that shared behavior; a subclass sets
``_message_model`` and ``_branch_model`` and inherits the helpers. The
merged ``execute`` dispatch loop lives here too; its domain-divergent
points (server allowlist, arg correction, error augmentation, pivot
alternatives, post-dispatch observation, bridge-URL resolution) are
expressed as hooks a subclass overrides. The survey-streak hint and
pivot-history parsing stay module-side.
"""
from __future__ import annotations

import json
import logging
from typing import Any
from uuid import uuid4

import httpx
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select as _select

from aila.platform.agents.auto_steering import maybe_post_auto_steering
from aila.platform.agents.tool_execution import (
    ToolExecutionResult,
    classify_contract_error,
    parse_command,
)
from aila.platform.contracts import utc_now
from aila.platform.contracts.enums import SenderKind
from aila.platform.contracts.mcp_payload import PayloadKind
from aila.platform.mcp.adapters import (
    AdapterContext,
    get_adapter,
    get_read_tools,
)
from aila.platform.uow import UnitOfWork

__all__ = ["ToolExecutorHelpersBase"]

_log = logging.getLogger(__name__)

# Single source of the malformed-command marker. The executor emits it and
# _count_total_malformed matches it; drift between the two halves silently
# breaks the STOP circuit breaker. Module executors import this for their
# execute() emit site so both halves stay in lockstep.
_MALFORMED_TOOL_RUN_MARKER: str = "Malformed tool_run"

# Positive success whitelist for a bridge response status; anything else
# (error envelopes, async in-progress values, unknown strings) is treated
# as an executor-visible error.
_SUCCESS_STATUSES: frozenset[str] = frozenset({"ready", "completed", "ok"})


class ToolExecutorHelpersBase:
    """Message-persistence, circuit-breaker, and observable-merge helpers
    shared by every module tool executor.

    A subclass MUST set ``_message_model`` and ``_branch_model`` (the
    module's message / branch SQLModel record types) before any helper
    runs -- typically in ``__init__``. ``_READ_TOOLS_FALLBACK`` is the
    module's domain read-tool set (used only when the adapter registry has
    not been imported, e.g. narrow unit tests).
    """

    # Subclass-provided record types.
    _message_model: type
    _branch_model: type

    # Cap on observables dict size (directives + recall pins always kept).
    _MAX_OBSERVABLES: int = 400

    # Domain read-tool fallback; subclasses override with their tools.
    _READ_TOOLS_FALLBACK: frozenset[tuple[str, str]] = frozenset()

    # ---- merged-dispatch config (subclasses override) -------------------
    # Server allowlist enforced before adapter lookup; None disables the
    # check (all bridged servers reachable).
    _AGENT_ALLOWED_SERVERS: frozenset[str] | None = None
    # Example command + action list rendered in the malformed-command STOP
    # message; subclasses set the domain example.
    _TOOLRUN_EXAMPLE_JSON: str = '{"tool": "<server>.<tool>", "args": {}}'
    _TOOLRUN_ACTIONS: str = (
        "tool_run / reasoning / submit / submit_outcome_review / script_execute"
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
            msg = self._message_model(
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

    async def _persist_result_and_observables(
        self,
        investigation_id: str,
        branch_id: str,
        *,
        payload_kind: PayloadKind,
        payload: dict[str, Any],
        observables_delta: dict[str, Any],
        at_turn: int | None,
    ) -> str:
        """Write the tool result message AND merge observables in ONE UoW.

        fix §203 -- was two separate transactions. A concurrent reader
        (operator UI streaming inv messages, or a sibling branch reading
        case_state mid-flight) could observe one half of the update
        without the other. Single UoW eliminates the gap.

        Returns the new message id.
        """
        async with UnitOfWork() as uow:
            msg = self._message_model(
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
            if observables_delta:
                branch = (await uow.session.exec(
                    _select(self._branch_model).where(
                        self._branch_model.id == branch_id,
                    )
                )).first()
                if branch is None:
                    _log.warning(
                        "tool_executor: branch %s vanished during "
                        "combined result+observables write",
                        branch_id,
                    )
                else:
                    branch.case_state_json = self._apply_observables_delta(
                        branch.case_state_json, observables_delta,
                    )
                    branch.updated_at = utc_now()
                    uow.session.add(branch)
            await uow.session.commit()
            await uow.session.refresh(msg)
            return msg.id

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

    async def _count_total_malformed(
        self,
        branch_id: str,
    ) -> int:
        """Count TOTAL malformed-command error messages on this branch
        across the last 50 engine messages.

        fix §201 -- was ``_count_consecutive_malformed`` which walked
        backwards from the tail and stopped at the first non-malformed
        message. That meant a single good call would reset the counter
        and let the breaker miss alternating empty/good/empty/... loops.
        Total count over a bounded window catches the alternating shape
        while still self-clearing over time as good calls scroll the
        50-message window past the malformed ones.
        """
        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                _select(self._message_model)
                .where(
                    self._message_model.branch_id == branch_id,
                    # fix §256 -- was the literal "engine"; drift hazard
                    # should SenderKind.ENGINE's value ever change.
                    self._message_model.sender_kind == SenderKind.ENGINE.value,
                )
                .order_by(self._message_model.created_at.desc())
                .limit(50)
            )).all()

        count = 0
        for row in rows:
            try:
                payload = json.loads(row.payload_json or "{}")
            except (ValueError, TypeError):
                continue
            if payload.get("is_error") and _MALFORMED_TOOL_RUN_MARKER in str(payload.get("text", "")):
                count += 1
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
        by the repeat-failure circuit breaker -- when the same tool
        call has failed 3+ times on the same branch, the executor
        injects a hard pivot hint into the next error.
        """
        # fix §255 -- was O(N²): each of up-to-50 errors triggered a
        # nested ``_messages_before`` query (1 + 50 round trips).
        # Single query now fetches up to 100 recent messages, then
        # one linear pass pairs each (tool_call, error_text) tuple
        # by adjacency -- equivalent to a LAG() window function but
        # portable across the SQLite/Postgres targets and easier to
        # read.
        canonical = json.dumps(args, sort_keys=True, default=str)
        prefix = f"{server_id}.{tool_name} returned error"
        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                _select(self._message_model)
                .where(self._message_model.branch_id == branch_id)
                .order_by(self._message_model.created_at.desc())
                .limit(100)
            )).all()
        # Walk oldest→newest so `prev` is always the message that
        # preceded `r` chronologically. A repeat-failure pair is a
        # tool_call followed immediately by an error-text whose
        # payload-text starts with `<server>.<tool> returned error`
        # and whose tool_call args canonicalise to the supplied set.
        count = 0
        prev: Any = None
        for r in reversed(rows):
            if (
                prev is not None
                and prev.payload_kind == PayloadKind.TOOL_CALL.value
                and r.payload_kind == PayloadKind.TEXT.value
            ):
                try:
                    err_payload = json.loads(r.payload_json or "{}")
                except (ValueError, TypeError):
                    prev = r
                    continue
                if (
                    err_payload.get("is_error")
                    and str(err_payload.get("text") or "").startswith(prefix)
                ):
                    try:
                        call_payload = json.loads(prev.payload_json or "{}")
                        cmd = json.loads(call_payload.get("command") or "{}")
                        cmd_args = cmd.get("args") or {}
                        if json.dumps(cmd_args, sort_keys=True, default=str) == canonical:
                            count += 1
                    except (ValueError, TypeError):
                        pass
            prev = r
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

        Error-class matching is intentionally narrow -- only fires when
        ``raw_err`` looks like a bridge-validator or upstream
        contract-violation message (unknown kwarg, missing required
        kwarg, unexpected keyword argument, signature mismatch). For
        those classes, varying the arg VALUE never helps -- the agent
        is calling the tool with the wrong arg NAME or shape and
        needs to pivot, not retry. For other error classes (function
        not indexed, file not found, timeout, etc.) varying args can
        legitimately help, so this helper returns 0 and falls back to
        the strict args-identical counter.
        """
        if not isinstance(raw_err, str):
            return 0
        class_key = classify_contract_error(raw_err)
        if class_key is None:
            return 0

        prefix = f"{server_id}.{tool_name} returned error"
        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                _select(self._message_model)
                .where(self._message_model.branch_id == branch_id)
                .where(self._message_model.payload_kind == PayloadKind.TEXT.value)
                .order_by(self._message_model.created_at.desc())
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
            if classify_contract_error(text) == class_key:
                count += 1
        return count

    @classmethod
    def _read_tools(cls) -> frozenset[tuple[str, str]]:
        registered = get_read_tools()
        return registered or cls._READ_TOOLS_FALLBACK

    @classmethod
    def _apply_observables_delta(
        cls, case_state_json: str | None, delta: dict[str, Any],
    ) -> str:
        """Merge ``delta`` into the observables of ``case_state_json``
        and return the new JSON string.

        Preserves §259 insertion order and caps the result at
        :attr:`_MAX_OBSERVABLES` entries (directives always kept). Pure
        helper -- does no I/O -- so it can run inside any UoW.
        """
        try:
            case_state = json.loads(case_state_json or "{}")
        # fix §258 -- also catch TypeError so a corrupted column
        # (e.g. integer or null where a JSON string is expected)
        # never wedges the merge.
        except (json.JSONDecodeError, TypeError):
            case_state = {}
        observables = case_state.get("observables")
        if not isinstance(observables, dict):
            observables = {}
        observables.update({str(k): v for k, v in delta.items()})
        # Bound the dict size. Eviction strategy: keep ALL reserved keys
        # (``_directive.*`` steering must survive; ``_recall.pinned`` is
        # the engine-written recall pin list and must not be evicted
        # out from under the render layer), drop the OLDEST non-reserved
        # keys by dict insertion order (Python 3.7+ guarantees insertion
        # order in dicts).
        if len(observables) > cls._MAX_OBSERVABLES:
            # fix \u00a7259 -- preserve original key insertion order so the
            # prompt-rendering position of every kept key stays stable
            # across turns.
            reserved_keys = {
                k for k in observables
                if str(k).startswith("_directive.")
                or str(k).startswith("_recall.")
            }
            non_reserved_keys = [
                k for k in observables if k not in reserved_keys
            ]
            keep_n = max(0, cls._MAX_OBSERVABLES - len(reserved_keys))
            kept_non_reserved_keys = set(non_reserved_keys[-keep_n:])
            kept_or_reserved = reserved_keys | kept_non_reserved_keys
            observables = {
                k: v for k, v in observables.items()
                if k in kept_or_reserved
            }
        case_state["observables"] = observables
        return json.dumps(case_state)

    async def _merge_observables(
        self,
        branch_id: str,
        delta: dict[str, Any],
    ) -> None:
        """Standalone observables merge (one UoW).

        Retained for call sites that do not also write a result message
        (the success path uses :meth:`_persist_result_and_observables`
        which combines both writes into a single UoW -- see fix §203).
        """
        if not delta:
            return
        async with UnitOfWork() as uow:
            branch = (await uow.session.exec(
                _select(self._branch_model).where(
                    self._branch_model.id == branch_id,
                )
            )).first()
            if branch is None:
                _log.warning(
                    "tool_executor: branch %s vanished during observables merge",
                    branch_id,
                )
                return
            branch.case_state_json = self._apply_observables_delta(
                branch.case_state_json, delta,
            )
            branch.updated_at = utc_now()
            uow.session.add(branch)
            await uow.commit()

    # ---- merged-dispatch hooks (subclasses override) --------------------
    async def _hard_block_repeat_limit(self) -> int | None:
        """Pre-call hard-block threshold for identical repeat failures.

        Default: None (no hard block; the post-call soft breaker still
        applies). VR resolves it from ConfigRegistry.
        """
        return None

    async def _pre_dispatch_correct_args(
        self, investigation_id: str, server_id: str, args: dict[str, Any],
    ) -> dict[str, Any]:
        """Correct dispatch args before the bridge call. Default: identity."""
        del investigation_id, server_id
        return args

    def _augment_tool_error(
        self, server_id: str, tool_name: str, args: dict[str, Any],
        raw_err: Any, err: str,
    ) -> str:
        """Append a domain-specific hint to a tool error. Default: unchanged."""
        del server_id, tool_name, args, raw_err
        return err

    def _pivot_alternatives(
        self, server_id: str, tool_name: str, ident: str,
    ) -> list[str]:
        """Alternative tool calls for the circuit breaker. Default: none."""
        del server_id, tool_name, ident
        return []

    async def _post_dispatch(
        self, *, investigation_id: str, branch_id: str, server_id: str,
        tool_name: str, raw: dict[str, Any],
    ) -> None:
        """Post-dispatch side effect, e.g. observation recording. Default: no-op."""
        del investigation_id, branch_id, server_id, tool_name, raw

    async def _resolve_bridge_base_url(self) -> str:
        """Bridge base URL embedded in auto-steering messages. Default: standard port."""
        return "http://127.0.0.1:18822"

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
                    f"{self._TOOLRUN_EXAMPLE_JSON}\n"
                    "  (b) action=submit if you have enough evidence to "
                    "submit your findings.\n"
                    "  (c) action=reasoning to think without a tool call.\n\n"
                    "Pick (c) if you are unsure -- reasoning is always safe "
                    "and lets you think before dispatching another tool. "
                    f"(There is NO 'observe' action -- only "
                    f"{self._TOOLRUN_ACTIONS}.)"
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

        # Hard reject for MCP servers outside the module allowlist, when
        # one is configured (_AGENT_ALLOWED_SERVERS not None), BEFORE the
        # adapter lookup. The bridge is still constructed for backend
        # services, so without this guard a disallowed call reaches the
        # bridge and the agent thinks the tool worked.
        if (
            self._AGENT_ALLOWED_SERVERS is not None
            and server_id not in self._AGENT_ALLOWED_SERVERS
        ):
            err = (
                f"MCP server {server_id!r} is NOT exposed to this agent. "
                f"Only {sorted(self._AGENT_ALLOWED_SERVERS)} are reachable "
                f"from tool_run. Re-read the # Available tools section in "
                f"the prompt -- any other server name you learned from prior "
                f"context is stale."
            )
            msg_id = await self._write_error_message(
                investigation_id, branch_id, err, at_turn,
            )
            return ToolExecutionResult(
                server_id=server_id, tool_name=tool_name,
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
        # Pre-dispatch arg correction (module hook; VR corrects an
        # audit_mcp index_id placeholder, other modules no-op).
        args = await self._pre_dispatch_correct_args(
            investigation_id, server_id, args,
        )
        # Pre-call HARD-BLOCK of identical repeat failures, when the module
        # enables it (hard_block_limit not None). Refuses the dispatch after
        # N identical failures WITHOUT the network call.
        hard_block_limit = await self._hard_block_repeat_limit()
        if hard_block_limit is not None:
            hard_block_count = await self._count_prior_failures(
                branch_id, server_id, tool_name, args,
            )
            if hard_block_count >= hard_block_limit:
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
            # Module hook: augment the error with a domain-specific
            # hint (VR appends a macro hint for an audit_mcp
            # not-indexed result; other modules no-op).
            err = self._augment_tool_error(
                server_id, tool_name, args, raw_err, err,
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
                alternatives = self._pivot_alternatives(
                    server_id, tool_name, ident,
                )

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

        # Module hook: durable cross-investigation observation for
        # the subset of tools whose results are lasting facts about
        # the target (malware records them; VR no-op).
        await self._post_dispatch(
            investigation_id=investigation_id,
            branch_id=branch_id,
            server_id=server_id,
            tool_name=tool_name,
            raw=raw if isinstance(raw, dict) else {},
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
            # Module hook resolves the bridge base URL that the
            # auto-steering correction messages embed. VR reads the
            # value off its audit_mcp bridge; others take the default.
            bridge_base_url = await self._resolve_bridge_base_url()
            try:
                posted_id = await maybe_post_auto_steering(
                    investigation_id=investigation_id,
                    branch_id=branch_id,
                    server_id=server_id,
                    tool_name=tool_name,
                    args=args,
                    raw_result=raw if isinstance(raw, dict) else {},
                    bridge_base_url=bridge_base_url,
                    message_model=self._message_model,
                    branch_model=self._branch_model,
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
