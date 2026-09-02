"""The planner oracle -- a thin request router over the shared ledger.

RFC-13 (#68). The oracle routes requests, it does not plan. Branches file
requests on the investigation ledger (``kind="request"``) carrying an
``intent`` and a ``target_capability``; the oracle routes each open
request to its decider, and once a request is ratified by a distinct
approver it applies the request's mechanical effect and records the
decision. A confirmed-trust dispatch phase then activates on the next hub
visit because the effect confirmed the underlying discovery.

Contract-net-lite: no bidding, no hidden policy. The two non-negotiables
are (1) a branch cannot approve its own request (distinct-approver,
mirrors the outcome-review quorum rule) and (2) the oracle applies only
the declared, mechanical effect for an intent.

The one place the oracle exercises judgment is
``adjudicate_specialist_requests`` (opt-in, module-invoked): a specialist
request is otherwise ratified only by a distinct sibling branch, so on a
small panel or an early pause it rots open and the specialist never
spawns. When invoked, the oracle asks the model whether such a request is
warranted given the investigation's evidence and records its own
distinct-approver decision accordingly. It still never invents an
objective, a phase, or a discovery -- it only ratifies or rejects a
request a branch already filed.

Request payload convention (``payload_json`` of a ``request`` entry)::

    {"intent": "activate_phase", "target_capability": "re",
     "discovery_id": <int>, "phase": "unpack"}
    {"intent": "open_objective", "target_capability": "re",
     "objective_key": "unpack_sample", "owner_branch_id": "<branch>"}
    {"intent": "write_objective", "objective_key": "<key>",
     "status": "met"}
    {"intent": "replan", "reason": "<why>"}
"""
from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from aila.platform.prompts.registry import PromptRegistry
from aila.platform.prompts.version_store import PromptVersionStore
from aila.platform.services.ledger import (
    _SYSTEM_ACTOR,
    LedgerPermissionError,
    LedgerService,
)

__all__ = ["Oracle", "OracleError"]

_log = logging.getLogger(__name__)

_ORACLE_ACTOR = "__oracle__"

# RFC-09 / req 20: the adjudicator prompt is resolved from the DB prompt version store
# via :class:`PromptRegistry`.
_ADJUDICATOR_PROMPT_REGISTRY = PromptRegistry(
    module="platform",
    version_store=PromptVersionStore(),
)


def _load_adjudicator_prompt() -> str:
    """Return the specialist-adjudicator system prompt from the registry."""
    return _ADJUDICATOR_PROMPT_REGISTRY.load("oracle_specialist_adjudicator")


class OracleError(RuntimeError):
    """A request could not be routed or applied (missing request, bad intent)."""


def _decision_targets(rows: list[dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
    """Group decision entries by the id they target."""
    by_target: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        if row.get("kind") != "decision":
            continue
        payload = row.get("payload") or {}
        target = payload.get("target")
        if target is None:
            continue
        by_target.setdefault(int(target), []).append(row)
    return by_target


class Oracle:
    """Route ledger requests to deciders and apply ratified effects."""

    def __init__(self) -> None:
        self._ledger = LedgerService()

    async def route_pending(
        self,
        investigation_id: str,
        *,
        session: AsyncSession | None = None,
    ) -> list[dict[str, Any]]:
        """Return the open requests with their resolved decider.

        A request is open until a distinct approver ratifies it. The decider
        is the owner of the objective the request names, or ``None`` (a
        quorum of any distinct branch) when it names no objective. The
        ``target_capability`` is echoed so the hub or an operator can see
        which specialty the request wants.
        """
        rows = await self._ledger.read_general(investigation_id, session=session)
        by_target = _decision_targets(rows)
        objectives = await self._ledger.read_objectives(
            investigation_id, session=session,
        )
        owner_by_key = {o["objective_key"]: o["owner_branch_id"] for o in objectives}
        pending: list[dict[str, Any]] = []
        for row in rows:
            if row.get("kind") != "request":
                continue
            request_id = int(row["id"])
            approvals = [
                d for d in by_target.get(request_id, [])
                if (d.get("payload") or {}).get("approved")
            ]
            if approvals:
                continue  # already ratified
            payload = row.get("payload") or {}
            objective_key = payload.get("objective_key")
            pending.append({
                "request_id": request_id,
                "author_branch_id": row.get("author_branch_id"),
                "intent": payload.get("intent"),
                "target_capability": payload.get("target_capability"),
                "objective_key": objective_key,
                "decider": owner_by_key.get(objective_key) if objective_key else None,
            })
        return pending

    async def record_decision(
        self,
        investigation_id: str,
        request_id: int,
        approver_branch_id: str,
        *,
        approve: bool,
        session: AsyncSession | None = None,
    ) -> int:
        """Record one approver's vote on a request as a decision entry.

        A branch may not approve its own request (distinct-approver). The
        vote is idempotency-keyed by ``(request, approver)`` so a retry adds
        no second vote.
        """
        request = await self._load_request(investigation_id, request_id, session)
        if approve and approver_branch_id == request.get("author_branch_id"):
            raise LedgerPermissionError(
                f"branch {approver_branch_id} cannot approve its own request "
                f"{request_id}"
            )
        return await self._ledger.append_general(
            investigation_id,
            approver_branch_id,
            "decision",
            {"approved": approve, "target": request_id, "approver": approver_branch_id},
            idempotency_key=f"decision:{request_id}:{approver_branch_id}",
            session=session,
        )

    async def is_ratified(
        self,
        investigation_id: str,
        request_id: int,
        *,
        quorum_k: int = 1,
        session: AsyncSession | None = None,
    ) -> bool:
        """True when at least ``quorum_k`` distinct branches approved the request."""
        rows = await self._ledger.read_general(investigation_id, session=session)
        approvers: set[str] = set()
        for decision in _decision_targets(rows).get(request_id, []):
            payload = decision.get("payload") or {}
            if payload.get("approved"):
                approvers.add(str(decision.get("author_branch_id")))
        return len(approvers) >= quorum_k

    async def apply_decision(
        self,
        investigation_id: str,
        request_id: int,
        *,
        quorum_k: int = 1,
        session: AsyncSession | None = None,
    ) -> dict[str, Any]:
        """Apply a ratified request's mechanical effect.

        Returns ``{"applied": False}`` when the request has not reached
        quorum. On a ratified request the oracle applies only the declared
        effect for the intent and returns what it did. It never invents an
        objective, a phase, or a discovery.
        """
        if not await self.is_ratified(
            investigation_id, request_id, quorum_k=quorum_k, session=session,
        ):
            return {"applied": False, "reason": "not ratified"}
        if await self._is_applied(investigation_id, request_id, session):
            # The hub applies ratified requests on every visit; an already
            # applied request is a no-op so a non-idempotent effect (opening
            # an objective) never runs twice.
            return {"applied": False, "reason": "already applied"}
        request = await self._load_request(investigation_id, request_id, session)
        payload = request.get("payload") or {}
        result = await self._apply_effect(
            investigation_id, payload.get("intent"), payload, session,
        )
        await self._mark_applied(investigation_id, request_id, session)
        return result

    async def _is_applied(
        self, investigation_id: str, request_id: int, session: AsyncSession | None,
    ) -> bool:
        """True when this request already has an applied marker on the ledger."""
        rows = await self._ledger.read_general(
            investigation_id, kinds=["decision"], session=session,
        )
        for row in rows:
            payload = row.get("payload") or {}
            if payload.get("applied") and int(payload.get("target", -1)) == request_id:
                return True
        return False

    async def _mark_applied(
        self, investigation_id: str, request_id: int, session: AsyncSession | None,
    ) -> None:
        """Record that a ratified request's effect has been applied (idempotent)."""
        await self._ledger.append_general(
            investigation_id,
            _ORACLE_ACTOR,
            "decision",
            {"applied": True, "target": request_id},
            idempotency_key=f"applied:{request_id}",
            session=session,
        )

    async def _apply_effect(
        self,
        investigation_id: str,
        intent: Any,
        payload: dict[str, Any],
        session: AsyncSession | None,
    ) -> dict[str, Any]:
        """Apply the single declared mechanical effect for a request intent."""
        if intent == "activate_phase":
            discovery_id = payload.get("discovery_id")
            if discovery_id is None:
                raise OracleError("activate_phase request has no discovery_id")
            await self._ledger.append_general(
                investigation_id,
                _ORACLE_ACTOR,
                "decision",
                {"approved": True, "target": int(discovery_id)},
                idempotency_key=f"confirm:{int(discovery_id)}",
                session=session,
            )
            return {"applied": True, "intent": intent, "confirmed": int(discovery_id)}
        if intent == "open_objective":
            objective_key = payload.get("objective_key")
            owner = payload.get("owner_branch_id") or _ORACLE_ACTOR
            if not objective_key:
                raise OracleError("open_objective request has no objective_key")
            await self._ledger.open_objective(
                investigation_id, _ORACLE_ACTOR, objective_key, owner,
                session=session,
            )
            return {"applied": True, "intent": intent, "objective_key": objective_key}
        if intent == "write_objective":
            objective_key = payload.get("objective_key")
            status = payload.get("status")
            if not objective_key or not status:
                raise OracleError("write_objective request missing objective_key/status")
            await self._ledger.set_objective_status(
                investigation_id, objective_key, _SYSTEM_ACTOR, status,
                session=session,
            )
            return {"applied": True, "intent": intent, "objective_key": objective_key}
        if intent == "replan":
            # Replan carries no mechanical ledger effect; the dispatch hub
            # relaxes confirmed trust for one pass once a replan is ratified.
            return {"applied": True, "intent": intent}
        if intent == "request_specialist":
            # No ledger-side effect: spawning a specialist branch needs the
            # module's record models + task queue, which the oracle does not
            # hold. The module's setup reads ratified request_specialist
            # requests (ratified_specialist_capabilities) and spawns the
            # matching registry specialist. Recording it here keeps
            # apply_all_ratified from raising on this intent.
            return {
                "applied": True, "intent": intent,
                "capability": payload.get("target_capability"),
            }
        # An unroutable request intent (None or an unknown string) is a
        # corrupt/legacy ledger row -- e.g. a malformed replan request left
        # by an earlier stall. Raising here crashed the ENTIRE dispatch hub
        # on every visit, wedging the investigation permanently. Skip it
        # instead: log the miss and return a non-applied result. The caller
        # (apply_ratified_request) then marks it applied so it never
        # re-routes, and apply_all_ratified drops it (only ``applied`` rows
        # are collected). One bad ledger row can no longer stall a run.
        _log.warning(
            "oracle: skipping unroutable request intent=%r inv=%s -- "
            "marking applied so it does not re-crash dispatch",
            intent, investigation_id,
        )
        return {"applied": False, "intent": intent, "skipped": "unknown_intent"}

    async def ratified_specialist_capabilities(
        self,
        investigation_id: str,
        *,
        quorum_k: int = 1,
        session: AsyncSession | None = None,
    ) -> list[str]:
        """Target capabilities of ratified ``request_specialist`` requests.

        A core branch files ``{intent: 'request_specialist',
        target_capability: X}`` when a case needs a specialist eye; a
        distinct approver (by convention the critic) ratifies it. This
        returns each ratified request's ``target_capability`` so the
        module's setup can resolve it to a registry specialist and spawn
        that branch. Deduplicated, order-preserving.
        """
        requests = await self._ledger.read_general(
            investigation_id, kinds=["request"], session=session,
        )
        caps: list[str] = []
        for request in requests:
            payload = request.get("payload") or {}
            if payload.get("intent") != "request_specialist":
                continue
            capability = payload.get("target_capability")
            if not capability or capability in caps:
                continue
            if await self.is_ratified(
                investigation_id, int(request["id"]),
                quorum_k=quorum_k, session=session,
            ):
                caps.append(str(capability))
        return caps

    async def apply_all_ratified(
        self,
        investigation_id: str,
        *,
        quorum_k: int = 1,
        session: AsyncSession | None = None,
    ) -> list[dict[str, Any]]:
        """Apply every ratified, not-yet-applied request; return what changed.

        The dispatch hub calls this on each visit so a request the panel has
        ratified takes effect (its discovery is confirmed, its objective
        opened) before the hub re-evaluates phase activation. apply_decision
        is idempotent, so an already-applied request is skipped.
        """
        requests = await self._ledger.read_general(
            investigation_id, kinds=["request"], session=session,
        )
        applied: list[dict[str, Any]] = []
        for request in requests:
            result = await self.apply_decision(
                investigation_id, int(request["id"]),
                quorum_k=quorum_k, session=session,
            )
            if result.get("applied"):
                applied.append(result)
        return applied

    async def adjudicate_specialist_requests(
        self,
        investigation_id: str,
        *,
        task_type: str,
        extra_context: str = "",
        quorum_k: int = 1,
        session: AsyncSession | None = None,
    ) -> list[dict[str, Any]]:
        """LLM-judge open ``request_specialist`` entries and ratify the warranted.

        RFC-13 ratified a specialist request only when a DISTINCT branch
        approved it (the distinct-approver quorum). On a small panel -- one
        filer plus a single sibling that never casts the vote -- or an early
        pause, that approval never lands and the request rots open, so the
        specialist (the implementer that would build a PoC, the analyst that
        would run a variant hunt) never spawns.

        This lets the oracle itself decide whether a request is real. For each
        open ``request_specialist`` that is neither already ratified by a
        sibling nor already oracle-adjudicated, it asks the model whether the
        request is warranted given the investigation's evidence, then records
        its OWN decision as ``__oracle__``. Because the oracle is a distinct
        approver, a warranted request reaches ``quorum_k`` and the existing
        spawn path picks it up on the same cycle; a rejected one carries an
        ``oracle_adjudicated`` marker so it never spawns and is never
        re-judged. Best-effort per request: a model, parse, or kill-switch
        outcome leaves the request open so a later cycle or a real sibling
        vote can still ratify it. Returns one entry per request it ruled on.
        """
        # Lazy imports break the platform.services import cycle: the factory
        # pulls in the reasoning engine, which imports back into services.
        from aila.platform.agents.idempotent_llm import idempotent_llm_call
        from aila.platform.services.factory import ServiceFactory

        del quorum_k  # oracle is a single distinct approver; is_ratified uses 1
        rows = await self._ledger.read_general(investigation_id, session=session)
        by_target = _decision_targets(rows)
        evidence = self._render_discovery_context(
            [r for r in rows if r.get("kind") == "discovery"],
        )
        system_prompt = _load_adjudicator_prompt()
        llm_client = ServiceFactory().llm_client
        ruled: list[dict[str, Any]] = []
        for row in rows:
            if row.get("kind") != "request":
                continue
            payload = row.get("payload") or {}
            if payload.get("intent") != "request_specialist":
                continue
            request_id = int(row["id"])
            prior = by_target.get(request_id, [])
            if any((d.get("payload") or {}).get("approved") for d in prior):
                continue  # a real sibling already ratified it
            if any(
                str(d.get("author_branch_id")) == _ORACLE_ACTOR
                and (d.get("payload") or {}).get("oracle_adjudicated")
                for d in prior
            ):
                continue  # already oracle-adjudicated -- idempotent
            capability = payload.get("target_capability")
            user_prompt = (
                f"# Open question\n{extra_context or '(not provided)'}\n\n"
                f"# Requested specialist capability\n{capability}\n\n"
                f"# Filing branch's stated reason\n{payload.get('reason') or '(none)'}\n\n"
                f"# Evidence gathered so far\n{evidence or '(no discoveries recorded yet)'}\n\n"
                "Decide whether spawning this specialist is warranted now."
            )
            try:
                resp, _hit = await idempotent_llm_call(
                    llm_client,
                    method="chat",
                    task_type=task_type,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    investigation_id=investigation_id,
                )
            except (RuntimeError, OSError, TimeoutError) as exc:
                _log.warning(
                    "oracle specialist adjudication LLM failed inv=%s req=%s err=%s",
                    investigation_id, request_id, exc,
                )
                continue
            if resp.disabled:
                _log.info(
                    "oracle specialist adjudication skipped (llm kill switch) "
                    "inv=%s req=%s", investigation_id, request_id,
                )
                continue
            verdict = self._parse_adjudication(resp.content)
            if verdict is None:
                continue
            warranted = bool(verdict.get("warranted"))
            await self._ledger.append_general(
                investigation_id,
                _ORACLE_ACTOR,
                "decision",
                {
                    "approved": warranted,
                    "oracle_adjudicated": True,
                    "target": request_id,
                    "capability": capability,
                    "rationale": str(verdict.get("rationale") or ""),
                },
                idempotency_key=f"oracle_adjudicate:{request_id}",
                session=session,
            )
            _log.info(
                "oracle adjudicated specialist request inv=%s req=%s cap=%s "
                "warranted=%s", investigation_id, request_id, capability, warranted,
            )
            ruled.append({
                "request_id": request_id,
                "capability": capability,
                "warranted": warranted,
                "rationale": verdict.get("rationale"),
            })
        return ruled

    @staticmethod
    def _render_discovery_context(
        discoveries: list[dict[str, Any]],
        *,
        max_items: int = 30,
        char_budget: int = 4000,
    ) -> str:
        """Pack recent discoveries into a compact evidence block for the prompt.

        Bounds item count and total size at the render layer (a prompt-budget
        cap, not a store-side data trim): the most recent discoveries are
        packed until the budget is reached.
        """
        lines: list[str] = []
        used = 0
        for row in discoveries[-max_items:]:
            payload = row.get("payload") or {}
            text = (
                payload.get("summary") or payload.get("claim")
                or payload.get("finding") or payload.get("label")
                or payload.get("description") or payload.get("note")
            )
            if not text:
                text = ", ".join(sorted(str(k) for k in payload)) or "(empty)"
            line = f"- {text}"
            if used + len(line) > char_budget and lines:
                break
            lines.append(line)
            used += len(line)
        return "\n".join(lines)

    @staticmethod
    def _parse_adjudication(content: str | None) -> dict[str, Any] | None:
        """Parse the adjudicator's strict-JSON verdict; None when unusable."""
        if not content:
            _log.debug("oracle adjudication returned empty content")
            return None
        try:
            data = json.loads(content)
        except (ValueError, TypeError):
            _log.debug("oracle adjudication response not JSON: %r", content[:200])
            return None
        if not isinstance(data, dict) or "warranted" not in data:
            _log.debug(
                "oracle adjudication response missing 'warranted': %r",
                content[:200],
            )
            return None
        return data

    async def _load_request(
        self,
        investigation_id: str,
        request_id: int,
        session: AsyncSession | None,
    ) -> dict[str, Any]:
        rows = await self._ledger.read_general(
            investigation_id, kinds=["request"], session=session,
        )
        for row in rows:
            if int(row["id"]) == request_id:
                return row
        raise OracleError(f"request {request_id} not found")
