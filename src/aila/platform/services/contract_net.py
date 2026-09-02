"""Contract-net TTL reaper (issue #15).

Doc `.run/vr_truth_contract_net.md` measured 588 request entries on the
shared ledger against 68 decision entries -- a closure ratio of 0.12.
Every intent past ``request_specialist`` (``replan``, ``activate_phase``,
``open_objective``, ``write_objective``) sits open until an operator
escalates or the hub halts stalled. The default cause is structural:
the self-approval guard plus the disjoint-claim panel (doc #12) means
the branch that filed the request cannot answer itself and no sibling
is on the same ground to vote.

:func:`reap_stale_requests` scans open request entries older than
``ttl_seconds`` and writes a synthetic decision under author
``__reaper__`` that supersedes the request, so the ledger stops
resurfacing dead rows via ``Oracle.route_pending``. It is invoked once
per finalize pass from
:func:`aila.platform.agents.outcome_dispatcher.finalize_investigation_aggregate`.

The entry point is async, session-optional, idempotent per request id
(a re-run skips requests already resolved), and never raises on a
per-request failure -- one bad payload does not stop reaping the rest.

The reaper writes the closure decision as a ledger ``decision`` entry
with a supersedes edge, matching the append-only shape the existing
``read_general`` + ``_confirmed_discovery_ids`` readers rely on. No
DB migration is required.

A quiet-window oracle adjudicator was previously exposed here
(``oracle_adjudicate_when_quiet``) but shipped without a caller: no
finalize path, worker, or cron built an oracle callback for it, so the
symbol sat unconsumed for the audit window. The confirmed audit
verdict removed the function rather than ship dead code; a future
oracle-backed adjudicator is expected to land on
``aila.platform.services.oracle`` alongside the existing
``request_specialist`` fallback rather than as a duplicate surface.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from aila.platform.services.ledger import LedgerService

__all__ = [
    "ContractNetResolution",
    "ContractNetSummary",
    "REAPER_AUTHOR",
    "REAPER_INTENT_ALLOWLIST",
    "reap_stale_requests",
]

_log = logging.getLogger(__name__)

# The reaper writes decision rows under a synthetic author marker so a
# live agent's decision stream and the coordination rescue path stay
# distinguishable in the ledger read-back.
REAPER_AUTHOR: str = "__reaper__"

# Request intents the reaper is allowed to touch. Anything outside the
# allowlist is left alone (``recon`` housekeeping requests and
# unknown-intent rows the schema does not model). Doc #15 names these
# four (plus ``request_specialist``) as the intents that presently
# starve.
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
    """Single request closed by the reaper."""

    request_id: int
    intent: str
    author_branch_id: str
    decision_id: int
    resolved_by: str
    verdict: str
    reason: str


@dataclass(slots=True)
class ContractNetSummary:
    """Aggregate reaper sweep result."""

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

