"""Same-persona shared claim space (VR-truth issue #12 -- agent interaction trace).

Doc `.run/vr_truth_agent_interaction_trace.md` traced investigation
`4a136d18` and found seven halvar researcher branches exploring disjoint
claim spaces: not one claim was held live in one branch and rejected in
another, so sibling-consensus had nothing to bind on. The cause is
structural -- each branch's ``case_state`` is private and re-fork carries
only that branch's own history forward, so branches of the same persona
never see each other's confirmations or refutations.

Ledger entries already carry ``author_branch_id`` and (issue #07)
``adjudication`` entries record the branch that killed a lead. This
service is the read path: given an investigation and a persona name, it
returns every branch of that persona plus their confirmed discoveries
and adjudication entries. The VR agent's per-turn assembly will call
this to inject a shared-claim-surface observable so a persona re-forked
after a terminal re-enqueue inherits its own siblings' proven-or-refuted
claim set instead of re-proposing the same 10 hypotheses across 140
cycles (doc `.run/vr_truth_aggregation_spine.md` \u00a71).

Public surface:

* :func:`read_shared_claims` -- confirmed discoveries + adjudications
  authored by any branch of the persona.
* :func:`branches_by_persona` -- resolve persona -> branch-id set for a
  caller that wants the raw membership.

The agent-side consume (rendering the pool into an observable, deciding
which sibling adjudications to surface) is out of scope; this file only
supplies the read.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from aila.platform.services.ledger import ADJUDICATION_KIND, LedgerService
from aila.platform.uow import UnitOfWork

__all__ = [
    "SharedClaim",
    "SharedClaimSpace",
    "branches_by_persona",
    "read_shared_claims",
]

_log = logging.getLogger(__name__)

# Discoveries a peer sibling confirmed via the review-quorum bridge
# (``LedgerService.confirm_branch_discoveries`` writes decision entries
# with ``target=<discovery_id>``). Reading ``confirmed_only=True``
# below drops discoveries that no approving decision references, so a
# consumer sees the confirmed set, not the raw discovery firehose.
_CONFIRMED_DISCOVERY_KIND: str = "discovery"


@dataclass(slots=True, frozen=True)
class SharedClaim:
    """One shared-claim row surfaced to a same-persona sibling.

    ``kind`` is either ``"discovery"`` (a confirmed observation)
    or ``"adjudication"`` (a rejected / refuted verdict). ``payload``
    is the raw ledger payload dict -- callers project the fields they
    need (``target_hypothesis_id`` / ``target_outcome_id`` /
    ``verdict`` / ``reason`` / ``cited_evidence`` for adjudications;
    the discovery payload shape is module-defined).
    """

    entry_id: int
    kind: str
    author_branch_id: str
    payload: dict[str, Any]


@dataclass(slots=True)
class SharedClaimSpace:
    """Full shared-claim projection returned by :func:`read_shared_claims`."""

    investigation_id: str
    persona: str
    branch_ids: frozenset[str]
    confirmed_discoveries: list[SharedClaim] = field(default_factory=list)
    adjudications: list[SharedClaim] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.confirmed_discoveries) + len(self.adjudications)


async def branches_by_persona(
    investigation_id: str,
    persona: str,
    *,
    branch_model: type,
    session: AsyncSession | None = None,
) -> frozenset[str]:
    """Return the id set of every branch of ``persona`` on this investigation.

    Persona lookup is a case-sensitive equality on
    ``branch_model.persona_voice`` (the column shape defined by
    :class:`aila.platform.contracts.branch_base.BranchRecordBase`).
    Merged / abandoned / stalled branches are included because their
    adjudications and confirmed discoveries remain durable ledger
    facts a re-forked persona should still inherit.
    """
    persona_key = str(persona or "").strip()
    if not persona_key:
        return frozenset()
    if session is None:
        async with UnitOfWork() as uow:
            rows = list(
                (await uow.session.exec(
                    select(branch_model.id).where(
                        branch_model.investigation_id == investigation_id,
                        branch_model.persona_voice == persona_key,
                    )
                )).all()
            )
    else:
        rows = list(
            (await session.exec(
                select(branch_model.id).where(
                    branch_model.investigation_id == investigation_id,
                    branch_model.persona_voice == persona_key,
                )
            )).all()
        )
    return frozenset(str(row) for row in rows)


async def read_shared_claims(
    investigation_id: str,
    persona: str,
    *,
    branch_model: type,
    ledger: LedgerService | None = None,
    limit: int = 400,
    session: AsyncSession | None = None,
) -> SharedClaimSpace:
    """Read confirmed / adjudicated claims across all branches of ``persona``.

    Issue #12 (agent interaction trace) + issue #19 (aggregation spine).
    The consumer wires this into per-turn observable assembly so a
    re-forked halvar reads its own siblings' confirmed evidence and
    kill decisions, breaking the disjoint-claim-space failure mode.

    Args:
        investigation_id: Scope; ledger + branch reads join on this.
        persona: ``persona_voice`` string; empty / unknown persona
            returns an empty space rather than raising.
        branch_model: Module branch SQLModel record type
            (``VRInvestigationBranchRecord`` / ``MalwareInvestigationBranchRecord``).
        ledger: Optional :class:`LedgerService` (constructed on demand).
        limit: Per-kind row cap forwarded to
            :meth:`LedgerService.read_general`.
        session: Optional pre-existing async session.

    Returns:
        A populated :class:`SharedClaimSpace`. When the persona has no
        branches the branch_ids set is empty and both entry lists are
        empty; callers should treat that as "no cross-branch surface
        yet" rather than an error.
    """
    ledger_svc = ledger if ledger is not None else LedgerService()
    branch_ids = await branches_by_persona(
        investigation_id, persona,
        branch_model=branch_model, session=session,
    )
    if not branch_ids:
        return SharedClaimSpace(
            investigation_id=investigation_id,
            persona=persona,
            branch_ids=frozenset(),
        )

    discovery_rows = await ledger_svc.read_general(
        investigation_id,
        kinds=[_CONFIRMED_DISCOVERY_KIND],
        confirmed_only=True,
        limit=limit,
        session=session,
    )
    adjudication_rows = await ledger_svc.read_general(
        investigation_id,
        kinds=[ADJUDICATION_KIND],
        limit=limit,
        session=session,
    )

    confirmed = [
        SharedClaim(
            entry_id=int(row["id"]),
            kind=_CONFIRMED_DISCOVERY_KIND,
            author_branch_id=str(row.get("author_branch_id") or ""),
            payload=dict(row.get("payload") or {}),
        )
        for row in discovery_rows
        if str(row.get("author_branch_id") or "") in branch_ids
    ]
    adjudications = [
        SharedClaim(
            entry_id=int(row["id"]),
            kind=ADJUDICATION_KIND,
            author_branch_id=str(row.get("author_branch_id") or ""),
            payload=dict(row.get("payload") or {}),
        )
        for row in adjudication_rows
        if str(row.get("author_branch_id") or "") in branch_ids
    ]

    _log.debug(
        "shared_claims investigation=%s persona=%s branches=%d "
        "confirmed=%d adjudications=%d",
        investigation_id, persona, len(branch_ids),
        len(confirmed), len(adjudications),
    )
    return SharedClaimSpace(
        investigation_id=investigation_id,
        persona=persona,
        branch_ids=branch_ids,
        confirmed_discoveries=confirmed,
        adjudications=adjudications,
    )
