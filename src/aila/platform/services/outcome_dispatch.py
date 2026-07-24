"""Platform-owned outcome dispatch claim (closes the dispatch TOCTOU).

A module's outcome dispatcher reads an accepted outcome, then runs a
side-effecting handler (spawns a child investigation, writes a finding,
ships a report). Without a claim, two workers can each read the same
outcome as dispatchable and both run the handler, double-shipping the
artifact. This module owns the atomic claim so no module reimplements
the concurrency-critical transaction.

``claim_outcome_for_dispatch`` opens a unit of work, selects the outcome
row ``FOR UPDATE``, runs an optional domain ``guard`` (a module supplies
its own dispatchability rule, e.g. VR's ``state == approved`` gate), and
if the row is not already CLAIMED or DISPATCHED flips ``dispatch_status``
to CLAIMED and commits. A concurrent dispatcher's ``FOR UPDATE`` blocks
until this commit, then observes CLAIMED and loses the claim
(``won=False``), so exactly one caller proceeds to the handler.

A dispatcher that crashes after winning the claim but before writing the
terminal DISPATCHED/FAILED status leaves the row stuck at CLAIMED; the
RFC-07 resilience reaper resets stale CLAIMED rows back to PENDING.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sqlmodel import select

from aila.platform.contracts.enums import OutcomeDispatchStatus
from aila.platform.uow import UnitOfWork

__all__ = ["OutcomeClaim", "claim_outcome_for_dispatch"]

_CLAIMED_OR_DONE: frozenset[str] = frozenset(
    {OutcomeDispatchStatus.CLAIMED.value, OutcomeDispatchStatus.DISPATCHED.value}
)


@dataclass(frozen=True)
class OutcomeClaim:
    """Result of an atomic dispatch claim.

    ``found`` is False when no row matched the id. ``won`` is True only for
    the single caller that flipped PENDING -> CLAIMED. ``skip_reason``
    carries the reason a found row was not claimed (already claimed, or a
    guard refusal such as a non-approved state) for the caller to surface.
    ``outcome_kind`` / ``payload_json`` / ``investigation_id`` snapshot the
    row's dispatch-relevant columns (read under the lock) so the caller
    runs its handler without a second read.
    """

    found: bool
    won: bool
    skip_reason: str | None = None
    outcome_kind: str | None = None
    payload_json: str | None = None
    investigation_id: str | None = None


async def claim_outcome_for_dispatch(
    outcome_model: type,
    outcome_id: str,
    *,
    guard: Callable[[Any], str | None] | None = None,
) -> OutcomeClaim:
    """Atomically claim an outcome for dispatch, returning the claim result.

    ``outcome_model`` is the module's outcome SQLModel record type.
    ``guard`` (optional) receives the FOR UPDATE-locked row and returns a
    skip reason to refuse the claim, or None to allow it; it may raise to
    signal a corrupt row. The caller must treat ``won=True`` as the single
    authority to run its dispatch handler and write the terminal status.
    """
    async with UnitOfWork() as uow:
        row = (
            await uow.session.exec(
                select(outcome_model)
                .where(outcome_model.id == outcome_id)
                .with_for_update()
            )
        ).first()
        if row is None:
            return OutcomeClaim(found=False, won=False)
        snapshot = {
            "outcome_kind": row.outcome_kind,
            "payload_json": row.payload_json,
            "investigation_id": row.investigation_id,
        }
        if row.dispatch_status in _CLAIMED_OR_DONE:
            return OutcomeClaim(
                found=True, won=False,
                skip_reason="already_claimed_or_dispatched", **snapshot,
            )
        if guard is not None:
            reason = guard(row)
            if reason is not None:
                return OutcomeClaim(
                    found=True, won=False, skip_reason=reason, **snapshot,
                )
        row.dispatch_status = OutcomeDispatchStatus.CLAIMED.value
        uow.session.add(row)
        await uow.commit()
        return OutcomeClaim(found=True, won=True, **snapshot)
