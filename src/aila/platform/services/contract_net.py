"""Contract-net TTL / reaper + oracle adjudicate-when-quiet (issue #15).

Doc `.run/vr_truth_contract_net.md` measured 588 request entries on the
shared ledger against 68 decision entries -- a closure ratio of 0.12.
The oracle currently answers only ``request_specialist`` on the quiet-
panel fallback (``platform/services/oracle.py:470-482``); every other
intent (``replan``, ``activate_phase``, ``open_objective``,
``write_objective``) sits open until an operator escalates or the hub
halts stalled. The default cause is structural: the self-approval guard
plus the disjoint-claim panel (doc #12) means the branch that filed the
request cannot answer itself and no sibling is on the same ground to
vote. This module gives the coordination surface closure:

* :func:`reap_stale_requests` -- scans open request entries older than
  ``ttl_seconds`` and writes a synthetic decision under author
  ``__reaper__`` that supersedes the request, so the ledger stops
  resurfacing dead rows via ``Oracle.route_pending``.
* :func:`oracle_adjudicate_when_quiet` -- for requests whose quiet
  window elapsed with no sibling vote, invokes the caller's
  ``adjudicator`` async callable (an oracle wrapping the platform LLM
  client) and writes its verdict as an ``oracle_adjudicated`` decision
  under author ``__oracle__``, extending the existing
  ``request_specialist`` fallback to every intent that carries a
  routable ``target``.

Both entry points are async, session-optional, idempotent per request
id (a re-run skips requests already resolved), and never raise on a
per-request failure -- one bad payload does not stop reaping the rest.

The reaper writes the closure decision as a ledger ``decision`` entry
with a supersedes edge, matching the append-only shape the existing
``read_general`` + ``_confirmed_discovery_ids`` readers rely on. No
DB migration is required (the ``status`` column is already used by
objective rows via ``set_objective_status``).
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from aila.platform.services.ledger import LedgerService

__all__ = [
    "ContractNetResolution",
    "ContractNetSummary",
    "OracleAdjudication",
    "REAPER_AUTHOR",
    "REAPER_INTENT_ALLOWLIST",
    "oracle_adjudicate_when_quiet",
    "reap_stale_requests",
]

_log = logging.getLogger(__name__)

# The reaper and oracle both write decision rows using synthetic
# author markers so a live agent's decision stream and the coordination
# rescue path stay distinguishable in the ledger read-back.
REAPER_AUTHOR: str = "__reaper__"
ORACLE_AUTHOR: str = "__oracle__"

# Request intents the reaper / oracle are allowed to touch. Anything
# outside the allowlist is left alone (``recon`` housekeeping requests
# and unknown-intent rows the schema does not model). Doc #15 names
# these four as the intents that presently starve.
REAPER_INTENT_ALLOWLIST: frozenset[str] = frozenset({
    "replan",
    "activate_phase",
    "open_objective",
    "write_objective",
    "request_specialist",
})

_REQUEST_KIND: str = "request"
_DECISION_KIND: str = "decision"


@dataclass(slots=True, frozen=True)
class ContractNetResolution:
    """Single request closed by the reaper or oracle."""

    request_id: int
    intent: str
    author_branch_id: str
    decision_id: int
    resolved_by: str
    verdict: str
    reason: str


@dataclass(slots=True)
class ContractNetSummary:
    """Aggregate reaper / oracle sweep result."""

    scanned: int = 0
    resolved: list[ContractNetResolution] | None = None
    skipped: int = 0
    errored: int = 0

    def __post_init__(self) -> None:
        if self.resolved is None:
            self.resolved = []

    @property
    def resolved_count(self) -> int:
        return len(self.resolved or [])


@dataclass(slots=True, frozen=True)
class OracleAdjudication:
    """Oracle's answer to a quiet request.

    ``approved`` maps directly to the ledger decision's ``approved``
    field so downstream readers do not need to special-case oracle rows.
    ``reason`` is stored on the decision payload for audit.
    """

    approved: bool
    reason: str


def _target_key_for_intent(intent: str, payload: dict[str, Any]) -> str | None:
    """Return the routing target the intent carries (or None)."""
    if intent == "replan":
        return payload.get("branch_id") or payload.get("target") or None
    if intent in {"open_objective", "write_objective"}:
        return (
            payload.get("objective_key")
            or payload.get("target")
            or None
        )
    if intent == "activate_phase":
        return payload.get("phase") or payload.get("target") or None
    if intent == "request_specialist":
        return payload.get("capability") or payload.get("target") or None
    return payload.get("target")


def _decoded_created_at(row: dict[str, Any]) -> datetime | None:
    raw = row.get("created_at")
    if raw is None:
        return None
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=UTC)
    try:
        parsed = datetime.fromisoformat(str(raw))
    except ValueError:
        _log.debug("contract_net: undecodable created_at %r -- treated as undated", raw)
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _index_decision_targets(rows: list[dict[str, Any]]) -> set[int]:
    """Ids of already-answered requests (peer, quorum, oracle, or reaper)."""
    answered: set[int] = set()
    for row in rows:
        payload = row.get("payload") or {}
        target = payload.get("target")
        if target is None:
            continue
        if isinstance(target, int):
            answered.add(target)
            continue
        try:
            answered.add(int(target))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
    return answered


async def reap_stale_requests(
    investigation_id: str,
    *,
    ttl_seconds: float,
    now: datetime | None = None,
    ledger: LedgerService | None = None,
    intent_allowlist: frozenset[str] = REAPER_INTENT_ALLOWLIST,
    session: Any = None,
) -> ContractNetSummary:
    """Close every request older than ``ttl_seconds`` with no decision.

    Iterates request + decision entries with a single ledger read (kinds
    filter avoids the objective / discovery firehose), computes the
    already-answered set, and for each open request past its TTL writes
    a ``dropped`` decision entry. Idempotent: a subsequent call skips
    requests that appear in the answered set the first pass added.

    Args:
        investigation_id: Scope.
        ttl_seconds: Age past which a still-open request is stale.
        now: Injected current time for tests. Defaults to
            ``datetime.now(UTC)``.
        ledger: Optional :class:`LedgerService`.
        intent_allowlist: Intents the reaper touches. Rows outside the
            set are counted as ``skipped``.
        session: Optional pre-existing async session.
    """
    ledger_svc = ledger if ledger is not None else LedgerService()
    cutoff_now = now if now is not None else datetime.now(UTC)
    ttl_delta = timedelta(seconds=max(0.0, float(ttl_seconds)))

    summary = ContractNetSummary()
    request_rows = await ledger_svc.read_general(
        investigation_id, kinds=[_REQUEST_KIND], limit=1000, session=session,
    )
    decision_rows = await ledger_svc.read_general(
        investigation_id, kinds=[_DECISION_KIND], limit=1000, session=session,
    )
    answered = _index_decision_targets(decision_rows)

    for row in request_rows:
        summary.scanned += 1
        request_id = int(row["id"])
        if request_id in answered:
            summary.skipped += 1
            continue
        payload = row.get("payload") or {}
        intent = str(payload.get("intent") or "").strip()
        if intent not in intent_allowlist:
            summary.skipped += 1
            continue
        created = _decoded_created_at(row)
        if created is None or (cutoff_now - created) < ttl_delta:
            summary.skipped += 1
            continue
        try:
            decision_id = await ledger_svc.append_general(
                investigation_id,
                REAPER_AUTHOR,
                _DECISION_KIND,
                {
                    "approved": False,
                    "dropped": True,
                    "target": request_id,
                    "intent": intent,
                    "reason": "reaped_ttl_expired",
                    "ttl_seconds": float(ttl_seconds),
                },
                supersedes_id=request_id,
                idempotency_key=f"reaper:{request_id}",
                session=session,
            )
        except (RuntimeError, ValueError, TypeError) as exc:
            _log.warning(
                "contract_net reap failed inv=%s req=%s: %s",
                investigation_id, request_id, exc,
            )
            summary.errored += 1
            continue
        summary.resolved.append(  # type: ignore[union-attr]
            ContractNetResolution(
                request_id=request_id,
                intent=intent,
                author_branch_id=str(row.get("author_branch_id") or ""),
                decision_id=decision_id,
                resolved_by=REAPER_AUTHOR,
                verdict="dropped",
                reason="ttl_expired",
            )
        )
    _log.info(
        "contract_net reap inv=%s scanned=%d resolved=%d skipped=%d errored=%d",
        investigation_id, summary.scanned, summary.resolved_count,
        summary.skipped, summary.errored,
    )
    return summary


async def oracle_adjudicate_when_quiet(
    investigation_id: str,
    *,
    quiet_window_seconds: float,
    adjudicator: Callable[
        [dict[str, Any]], Awaitable[OracleAdjudication | None]
    ],
    now: datetime | None = None,
    ledger: LedgerService | None = None,
    intent_allowlist: frozenset[str] = REAPER_INTENT_ALLOWLIST,
    session: Any = None,
) -> ContractNetSummary:
    """Ask the oracle to decide requests that peers left unratified.

    Doc #15 fix: the oracle already adjudicates ``request_specialist``
    on the quiet-panel fallback; extend the same pattern to every
    intent the contract-net emits. For each open request whose age
    exceeds ``quiet_window_seconds`` and that carries a routable
    ``target`` for its intent, hand the row to ``adjudicator``. When
    the callable returns an :class:`OracleAdjudication` an
    ``oracle_adjudicated`` decision row is written; ``None`` skips
    (the oracle explicitly declined). Independent of
    :func:`reap_stale_requests`; a deployment may run one, the other,
    or both -- rows resolved by the reaper are naturally skipped here
    because they appear in the answered set.

    ``adjudicator`` receives the raw request row dict (with ``payload``
    already decoded). A raised exception is logged and counted as
    ``errored`` -- the sweep continues on the next request.
    """
    ledger_svc = ledger if ledger is not None else LedgerService()
    cutoff_now = now if now is not None else datetime.now(UTC)
    window = timedelta(seconds=max(0.0, float(quiet_window_seconds)))

    summary = ContractNetSummary()
    request_rows = await ledger_svc.read_general(
        investigation_id, kinds=[_REQUEST_KIND], limit=1000, session=session,
    )
    decision_rows = await ledger_svc.read_general(
        investigation_id, kinds=[_DECISION_KIND], limit=1000, session=session,
    )
    answered = _index_decision_targets(decision_rows)

    for row in request_rows:
        summary.scanned += 1
        request_id = int(row["id"])
        if request_id in answered:
            summary.skipped += 1
            continue
        payload = row.get("payload") or {}
        intent = str(payload.get("intent") or "").strip()
        if intent not in intent_allowlist:
            summary.skipped += 1
            continue
        created = _decoded_created_at(row)
        if created is None or (cutoff_now - created) < window:
            summary.skipped += 1
            continue
        target = _target_key_for_intent(intent, payload)
        if target is None:
            summary.skipped += 1
            continue
        try:
            adjudication = await adjudicator({
                "id": request_id,
                "intent": intent,
                "author_branch_id": row.get("author_branch_id"),
                "payload": payload,
                "target": target,
            })
        except (RuntimeError, ValueError, TypeError, LookupError) as exc:
            _log.warning(
                "contract_net oracle adjudicator raised inv=%s req=%s: %s",
                investigation_id, request_id, exc,
            )
            summary.errored += 1
            continue
        if adjudication is None:
            summary.skipped += 1
            continue
        try:
            decision_id = await ledger_svc.append_general(
                investigation_id,
                ORACLE_AUTHOR,
                _DECISION_KIND,
                {
                    "approved": bool(adjudication.approved),
                    "target": request_id,
                    "intent": intent,
                    "reason": adjudication.reason,
                    "oracle_adjudicated": True,
                },
                supersedes_id=request_id,
                idempotency_key=f"oracle:{request_id}",
                session=session,
            )
        except (RuntimeError, ValueError, TypeError) as exc:
            _log.warning(
                "contract_net oracle write failed inv=%s req=%s: %s",
                investigation_id, request_id, exc,
            )
            summary.errored += 1
            continue
        summary.resolved.append(  # type: ignore[union-attr]
            ContractNetResolution(
                request_id=request_id,
                intent=intent,
                author_branch_id=str(row.get("author_branch_id") or ""),
                decision_id=decision_id,
                resolved_by=ORACLE_AUTHOR,
                verdict="approved" if adjudication.approved else "denied",
                reason=adjudication.reason,
            )
        )
    _log.info(
        "contract_net oracle inv=%s scanned=%d resolved=%d skipped=%d errored=%d",
        investigation_id, summary.scanned, summary.resolved_count,
        summary.skipped, summary.errored,
    )
    return summary
