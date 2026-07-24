"""Shared ToolExecutor helper base (RFC-03 Phase 4b, helper extraction).

The vr and malware tool executors carried byte-identical copies of the
tool-result persistence, circuit-breaker counting, and observable-merge
helpers -- differing only in the module-specific message / branch record
types. This base owns that shared behavior; a subclass sets
``_message_model`` and ``_branch_model`` and inherits the helpers. The
divergent parts (the ``execute`` dispatch loop, the survey-streak hint
text, pivot-history parsing, and each module's index-correction /
observation hooks) stay module-side.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from sqlmodel import select as _select

from aila.platform.agents.tool_execution import classify_contract_error
from aila.platform.contracts import utc_now
from aila.platform.contracts.enums import SenderKind
from aila.platform.contracts.mcp_payload import PayloadKind
from aila.platform.mcp.adapters import get_read_tools
from aila.platform.uow import UnitOfWork

__all__ = ["ToolExecutorHelpersBase"]

_log = logging.getLogger(__name__)

# Single source of the malformed-command marker. The executor emits it and
# _count_total_malformed matches it; drift between the two halves silently
# breaks the STOP circuit breaker. Module executors import this for their
# execute() emit site so both halves stay in lockstep.
_MALFORMED_TOOL_RUN_MARKER: str = "Malformed tool_run"


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
