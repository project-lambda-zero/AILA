"""Investigation ledger -- the shared blackboard for RFC-13 (#68).

One append-only table per investigation. Every branch appends; every branch
reads. Entries are typed (discovery / request / decision / note /
objective) with a JSON payload. Objectives are ordinary entries tagged with
``objective_key`` + ``owner_branch_id`` + ``status``; a read view folds the
latest per key, so there is no separate objective table. Private per-agent
objectives are not stored here -- they stay the branch's hypotheses.

Append-only: a correction, an objective status change, or an owner transfer
is a new entry with ``supersedes_id`` pointing at the prior one, so the
history is complete and auditable. ``append_general`` is idempotent when
given an ``idempotency_key`` (unique per investigation), so an ARQ task
retry never double-appends.

The table is defined here (not in ``storage/db_models.py``) so the RFC-13
slice owns its schema end-to-end; ``db_models`` adds a side-effect import so
``create_all`` and the Alembic autogenerate see it.
"""
from __future__ import annotations

import json
from collections.abc import AsyncGenerator, Awaitable, Callable, Iterable
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from sqlalchemy import Column, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy import DateTime as SA_DateTime
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import Field, SQLModel, select

from aila.platform.contracts import utc_now
from aila.platform.uow import UnitOfWork

__all__ = [
    "ADJUDICATION_KIND",
    "InvestigationLedgerRecord",
    "LedgerPermissionError",
    "LedgerService",
    "make_discovery_condition",
    "make_evidence_condition",
]

# The single ledger kind used for reject / refute adjudications so
# sibling branches read a first-class negative-knowledge entry off the
# shared blackboard (issue #07 -- ledger economics, RFC #253/#266).
# ``LedgerService.append_adjudication`` writes rows tagged with this
# kind, and ``read_general(kinds=[ADJUDICATION_KIND])`` returns them
# without touching the discovery-confirmation gate (an adjudication is
# not a discovery; the ``confirmed_only`` filter is discovery-only by
# construction, see ``read_general`` below).
ADJUDICATION_KIND: str = "adjudication"

# Adjudication verdict literals. A ``rejected`` adjudication kills a
# hypothesis on the branch that produced it (branch-local refutation
# that other siblings should honor); a ``refuted`` adjudication kills a
# claim across branches (proof-by-evidence that the whole investigation
# should stop pursuing the target). Both are recorded under the same
# ledger kind so a sibling read (``read_general(kinds=[ADJUDICATION_KIND])``)
# returns the whole set in one call.
_ADJUDICATION_VERDICTS: frozenset[str] = frozenset({"rejected", "refuted"})

_UQ_IDEM = "uq_investigation_ledger_idem"
# The system actor used by ownership transfers (branch merge / abandon).
# A write under this author bypasses the owner-only guard on objective
# status because the transfer path IS the ownership-change mechanism.
_SYSTEM_ACTOR = "__system__"


class LedgerPermissionError(RuntimeError):
    """A non-owner branch tried to mutate an objective directly.

    A branch that does not own an objective must file a capability request
    (Phase 4) rather than change the objective's status itself. The owner
    path and the system transfer path are the only direct mutators.
    """


class InvestigationLedgerRecord(SQLModel, table=True):
    """One append-only entry on an investigation's shared ledger."""

    __tablename__ = "investigation_ledger"
    __table_args__ = (
        UniqueConstraint("investigation_id", "idempotency_key", name=_UQ_IDEM),
        Index("ix_investigation_ledger_investigation_id", "investigation_id"),
        Index("ix_investigation_ledger_objective_key", "objective_key"),
        Index("ix_investigation_ledger_kind", "kind"),
    )

    id: int | None = Field(default=None, primary_key=True)
    investigation_id: str = Field(
        sa_column=Column("investigation_id", String(64), nullable=False),
    )
    author_branch_id: str = Field(
        sa_column=Column("author_branch_id", String(64), nullable=False),
    )
    kind: str = Field(sa_column=Column("kind", String(32), nullable=False))
    payload_json: str = Field(
        sa_column=Column("payload_json", Text, nullable=False),
    )
    objective_key: str | None = Field(
        default=None,
        sa_column=Column("objective_key", String(128), nullable=True),
    )
    owner_branch_id: str | None = Field(
        default=None,
        sa_column=Column("owner_branch_id", String(64), nullable=True),
    )
    status: str | None = Field(
        default=None, sa_column=Column("status", String(32), nullable=True),
    )
    supersedes_id: int | None = Field(
        default=None, sa_column=Column("supersedes_id", Integer, nullable=True),
    )
    idempotency_key: str | None = Field(
        default=None,
        sa_column=Column("idempotency_key", String(128), nullable=True),
    )
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(
            "created_at", SA_DateTime(timezone=True), nullable=False,
        ),
    )


@asynccontextmanager
async def _session_or_new(
    session: AsyncSession | None,
) -> AsyncGenerator[tuple[AsyncSession, bool], None]:
    """Yield (session, owns). Own a short-lived session when none is passed."""
    if session is not None:
        yield session, False
    else:
        async with UnitOfWork() as uow:
            yield uow.session, True


def _to_dict(rec: InvestigationLedgerRecord) -> dict[str, Any]:
    try:
        payload = json.loads(rec.payload_json or "{}")
    except (json.JSONDecodeError, TypeError):
        payload = {}
    return {
        "id": rec.id,
        "investigation_id": rec.investigation_id,
        "author_branch_id": rec.author_branch_id,
        "kind": rec.kind,
        "payload": payload,
        "objective_key": rec.objective_key,
        "owner_branch_id": rec.owner_branch_id,
        "status": rec.status,
        "supersedes_id": rec.supersedes_id,
        "created_at": rec.created_at,
    }


def _confirmed_discovery_ids(rows: list[InvestigationLedgerRecord]) -> set[int]:
    """Discovery ids that an approving decision entry references.

    A `decision` entry carries ``payload={"approved": true, "target": <id>}``;
    a discovery is confirmed once such an entry names it. Phase 4 wires the
    quorum to write those decisions; until then only explicitly-decided
    discoveries count as confirmed.
    """
    confirmed: set[int] = set()
    for row in rows:
        if row.kind != "decision":
            continue
        try:
            payload = json.loads(row.payload_json or "{}")
        except (json.JSONDecodeError, TypeError):
            continue
        target = payload.get("target")
        if payload.get("approved") and target is not None:
            confirmed.add(int(target))
    return confirmed


class LedgerService:
    """Append-only reader / writer over :class:`InvestigationLedgerRecord`."""

    async def append_general(
        self,
        investigation_id: str,
        author_branch_id: str,
        kind: str,
        payload: dict[str, Any],
        *,
        objective_key: str | None = None,
        owner_branch_id: str | None = None,
        status: str | None = None,
        supersedes_id: int | None = None,
        idempotency_key: str | None = None,
        session: AsyncSession | None = None,
    ) -> int:
        """Append one entry; idempotent on ``(investigation_id, idempotency_key)``.

        With an ``idempotency_key`` set, a repeat append (an ARQ retry) is a
        no-op that returns the existing id. Without one, every call inserts.

        The kind is stored as given. Note-kind coercion (recon ``note``
        to ``discovery`` so the discovery-gated audit phases activate)
        is owned by ``turn_runner._post_ledger_writes``, which keys the
        decision on the recon phase directive; the ledger layer does not
        second-guess the kind it is handed.
        """
        values = {
            "investigation_id": investigation_id,
            "author_branch_id": author_branch_id,
            "kind": kind,
            "payload_json": json.dumps(payload),
            "objective_key": objective_key,
            "owner_branch_id": owner_branch_id,
            "status": status,
            "supersedes_id": supersedes_id,
            "idempotency_key": idempotency_key,
            "created_at": utc_now(),
        }
        async with _session_or_new(session) as (sess, owns):
            stmt = (
                pg_insert(InvestigationLedgerRecord)
                .values(**values)
                .on_conflict_do_nothing(constraint=_UQ_IDEM)
                .returning(InvestigationLedgerRecord.id)
            )
            new_id = (await sess.execute(stmt)).scalar()
            if new_id is None:
                new_id = (await sess.execute(
                    select(InvestigationLedgerRecord.id).where(
                        InvestigationLedgerRecord.investigation_id == investigation_id,
                        InvestigationLedgerRecord.idempotency_key == idempotency_key,
                    )
                )).scalar()
            if owns:
                await sess.commit()
        return int(new_id)

    async def read_general(
        self,
        investigation_id: str,
        *,
        kinds: list[str] | None = None,
        confirmed_only: bool = False,
        limit: int = 200,
        session: AsyncSession | None = None,
    ) -> list[dict[str, Any]]:
        """Read the ledger oldest-first.

        ``kinds`` filters by entry kind. ``confirmed_only`` drops discovery
        entries that no approving decision references (used by a
        confirmed-trust phase condition); non-discovery entries pass through.
        """
        async with _session_or_new(session) as (sess, _owns):
            stmt = select(InvestigationLedgerRecord).where(
                InvestigationLedgerRecord.investigation_id == investigation_id,
            ).order_by(InvestigationLedgerRecord.id)
            rows = list((await sess.exec(stmt)).all())
        if confirmed_only:
            confirmed = _confirmed_discovery_ids(rows)
            rows = [
                r for r in rows
                if r.kind != "discovery" or (r.id in confirmed)
            ]
        if kinds is not None:
            wanted = set(kinds)
            rows = [r for r in rows if r.kind in wanted]
        return [_to_dict(r) for r in rows[:limit]]

    async def confirm_branch_discoveries(
        self,
        investigation_id: str,
        branch_id: str,
        *,
        approver_branch_id: str = "__quorum__",
        return_hypotheses: bool = False,
        session: AsyncSession | None = None,
    ) -> list[int] | list[tuple[int, str | None]]:
        """Confirm every discovery authored by ``branch_id`` (RFC-13 Phase 4).

        The bridge from the outcome-review quorum to the ledger: once a
        finding is approved by sibling quorum, the discoveries the proposing
        branch posted are confirmed by writing a decision entry
        ``{"approved": true, "target": <discovery_id>}`` per discovery. That
        is exactly what ``_confirmed_discovery_ids`` reads, so confirmed-trust
        phase conditions (e.g. poc_development) and the confirmed-only ledger
        read finally see confirmed discoveries. Idempotent per discovery id
        via the ``confirm:<id>`` key, so a re-run adds no duplicate.

        Returns the list of confirmed discovery ids by default. When
        ``return_hypotheses=True`` returns a list of
        ``(discovery_id, hypothesis_id)`` tuples so a caller can bridge the
        quorum confirmation back to the originating hypothesis on the
        branch's case_state (recon and taint discoveries carry
        ``hypothesis_id`` in their payload). The hypothesis id is ``None``
        when the discovery payload lacks one. The default ``list[int]``
        return is preserved so the platform bases inherited by malware and
        forensics stay backward compatible.
        """
        rows = await self.read_general(
            investigation_id, kinds=["discovery"], session=session,
        )
        confirmed: list[int] = []
        confirmed_pairs: list[tuple[int, str | None]] = []
        for row in rows:
            if str(row.get("author_branch_id")) != str(branch_id):
                continue
            discovery_id = int(row["id"])
            await self.append_general(
                investigation_id,
                approver_branch_id,
                "decision",
                {"approved": True, "target": discovery_id},
                idempotency_key=f"confirm:{discovery_id}",
                session=session,
            )
            confirmed.append(discovery_id)
            if return_hypotheses:
                payload = row.get("payload") or {}
                raw_hid = payload.get("hypothesis_id")
                hyp_id: str | None
                if raw_hid is None:
                    hyp_id = None
                else:
                    hyp_id = str(raw_hid) or None
                confirmed_pairs.append((discovery_id, hyp_id))
        if return_hypotheses:
            return confirmed_pairs
        return confirmed

    async def append_adjudication(
        self,
        investigation_id: str,
        branch_id: str,
        *,
        verdict: str,
        reason: str,
        cited_evidence: list[str],
        target_hypothesis_id: str | None = None,
        target_outcome_id: str | None = None,
        session: AsyncSession | None = None,
    ) -> int:
        """Record a reject / refute adjudication on the shared ledger.

        Issue #07 -- ledger economics (RFC #253/#266). The single most
        reusable fact an investigation produces -- why a lead is dead --
        used to stay branch-private in ``case_state.rejected`` and
        never reach the ledger, so sibling branches re-explored killed
        paths and the consolidator had no negative-knowledge signal to
        distill. This helper writes that judgement as a first-class
        entry the whole workspace can read.

        Payload shape (exact, aligned to the batch Contract):

        ``{
            "verdict": "rejected" | "refuted",
            "target_hypothesis_id": str | None,
            "target_outcome_id": str | None,
            "reason": str,
            "cited_evidence": list[str],
            "author_branch_id": str,
        }``

        Idempotency-keyed on the target (``adjudication:<hyp|out>:<id>``)
        so a retry never double-appends and a sibling voting again on
        the same target upserts the same row.
        """
        if verdict not in _ADJUDICATION_VERDICTS:
            raise ValueError(
                f"adjudication verdict must be one of "
                f"{sorted(_ADJUDICATION_VERDICTS)!r}; got {verdict!r}"
            )
        if target_hypothesis_id is None and target_outcome_id is None:
            raise ValueError(
                "adjudication requires target_hypothesis_id or "
                "target_outcome_id (at least one)"
            )
        if target_hypothesis_id is not None:
            idem = f"adjudication:hyp:{target_hypothesis_id}:{branch_id}"
        else:
            idem = f"adjudication:out:{target_outcome_id}:{branch_id}"
        payload: dict[str, Any] = {
            "verdict": verdict,
            "target_hypothesis_id": target_hypothesis_id,
            "target_outcome_id": target_outcome_id,
            "reason": reason,
            "cited_evidence": list(cited_evidence),
            "author_branch_id": branch_id,
        }
        return await self.append_general(
            investigation_id,
            branch_id,
            ADJUDICATION_KIND,
            payload,
            idempotency_key=idem,
            session=session,
        )

    async def open_objective(
        self,
        investigation_id: str,
        author_branch_id: str,
        objective_key: str,
        owner_branch_id: str,
        *,
        session: AsyncSession | None = None,
    ) -> int:
        """Open a shared objective as a tagged ledger entry."""
        return await self.append_general(
            investigation_id,
            author_branch_id,
            "objective",
            {"objective_key": objective_key, "status": "open"},
            objective_key=objective_key,
            owner_branch_id=owner_branch_id,
            status="open",
            session=session,
        )

    async def read_objectives(
        self,
        investigation_id: str,
        *,
        owner_branch_id: str | None = None,
        session: AsyncSession | None = None,
    ) -> list[dict[str, Any]]:
        """Fold objective entries to the latest per key (current owner+status)."""
        async with _session_or_new(session) as (sess, _owns):
            rows = list((await sess.exec(
                select(InvestigationLedgerRecord).where(
                    InvestigationLedgerRecord.investigation_id == investigation_id,
                    InvestigationLedgerRecord.kind == "objective",
                ).order_by(InvestigationLedgerRecord.id)
            )).all())
        latest: dict[str, InvestigationLedgerRecord] = {}
        for row in rows:
            if row.objective_key:
                latest[row.objective_key] = row
        result: list[dict[str, Any]] = []
        for key, row in latest.items():
            if owner_branch_id is not None and row.owner_branch_id != owner_branch_id:
                continue
            result.append({
                "objective_key": key,
                "owner_branch_id": row.owner_branch_id,
                "status": row.status,
                "entry_id": row.id,
            })
        return result

    async def _latest_objective(
        self, sess: AsyncSession, investigation_id: str, objective_key: str,
    ) -> InvestigationLedgerRecord | None:
        return (await sess.exec(
            select(InvestigationLedgerRecord).where(
                InvestigationLedgerRecord.investigation_id == investigation_id,
                InvestigationLedgerRecord.kind == "objective",
                InvestigationLedgerRecord.objective_key == objective_key,
            ).order_by(InvestigationLedgerRecord.id.desc())
        )).first()

    async def set_objective_status(
        self,
        investigation_id: str,
        objective_key: str,
        author_branch_id: str,
        status: str,
        *,
        session: AsyncSession | None = None,
    ) -> int:
        """Change an objective's status via a new superseding entry.

        Owner-only: a non-owner branch is refused here and must file a
        capability request instead (Phase 4). The system actor bypasses the
        guard because branch merge / abandon changes ownership through this
        path.
        """
        async with _session_or_new(session) as (sess, _owns):
            latest = await self._latest_objective(
                sess, investigation_id, objective_key,
            )
            owner = latest.owner_branch_id if latest else None
            prior_id = latest.id if latest else None
        if (
            latest is not None
            and author_branch_id != owner
            and author_branch_id != _SYSTEM_ACTOR
        ):
            raise LedgerPermissionError(
                f"branch {author_branch_id} does not own objective "
                f"{objective_key!r} (owner {owner!r}); file a request instead"
            )
        return await self.append_general(
            investigation_id,
            author_branch_id,
            "objective",
            {"objective_key": objective_key, "status": status},
            objective_key=objective_key,
            owner_branch_id=owner,
            status=status,
            supersedes_id=prior_id,
            session=session,
        )

    async def transfer_objective_owner(
        self,
        investigation_id: str,
        objective_key: str,
        new_owner_branch_id: str | None,
        *,
        author_branch_id: str = _SYSTEM_ACTOR,
        session: AsyncSession | None = None,
    ) -> int:
        """Reassign an objective's owner (None orphans it to the investigation)."""
        async with _session_or_new(session) as (sess, _owns):
            latest = await self._latest_objective(
                sess, investigation_id, objective_key,
            )
            current_status = latest.status if latest else "open"
            prior_id = latest.id if latest else None
        return await self.append_general(
            investigation_id,
            author_branch_id,
            "objective",
            {"objective_key": objective_key, "status": current_status},
            objective_key=objective_key,
            owner_branch_id=new_owner_branch_id,
            status=current_status,
            supersedes_id=prior_id,
            session=session,
        )


def _resolve_confirmed(state_input: dict[str, Any], confirmed_only: bool) -> bool:
    """Resolve whether a hub condition requires quorum-confirmed discoveries.

    The dispatch hub injects the phase's ``trust`` as ``_dispatch_phase_trust``
    so ``trust`` is the single source of truth for confirmed-versus-advisory;
    a standalone condition (no hub) falls back to the ``confirmed_only`` param.
    A ratified replan relaxes confirmed trust for one pass either way.
    """
    trust = state_input.get("_dispatch_phase_trust")
    if trust == "confirmed":
        base = True
    elif trust == "advisory":
        base = False
    else:
        base = confirmed_only
    return base and not state_input.get("_dispatch_replan_relax")


def make_discovery_condition(
    kind: str = "discovery",
    *,
    confirmed_only: bool = False,
    input_key: str = "investigation_id",
    payload_match: dict[str, Any] | None = None,
    payload_exclude: dict[str, Any] | None = None,
) -> Callable[[dict[str, Any]], Awaitable[tuple[bool, str]]]:
    """Build a dispatch-hub condition that fires when the ledger holds a
    matching entry (RFC-13 #68).

    The returned async predicate matches the phase-graph ``GateFn`` shape:
    it reads the investigation id from the hub state input, reads the
    ledger, and returns ``(present, reason)``. ``confirmed_only`` restricts
    discoveries to those a quorum decision confirmed (a confirmed-trust
    phase). The discovery-driven module graphs use it to activate a phase
    only once a real discovery exists, rather than on a static edge.

    ``payload_match`` narrows the match to entries whose ``payload`` carries
    every listed key with the exact listed value (post-quorum filter). None
    (the default) preserves the pre-existing any-entry-of-the-kind behavior;
    every legacy caller keeps its semantics without change. The malware hub
    uses this to route confirmed ``{finding: packed}`` discoveries to the
    unpack phase and confirmed ``{finding: config_present}`` discoveries to
    the config-extraction phase off the same shared ledger.

    ``payload_exclude`` drops entries whose payload carries every listed key
    with the exact listed value -- the complement of ``payload_match``. The
    VR hub uses it to keep ``poc_development`` from firing on confirmed recon
    hypotheses (``{source: recon_hypothesis}``) that are not exploitable
    findings.
    """

    async def _condition(state_input: dict[str, Any]) -> tuple[bool, str]:
        investigation_id = state_input.get(input_key)
        if not investigation_id:
            return False, f"no {input_key} on dispatch input"
        # Trust (hub-injected) is the source of truth for confirmed-vs-
        # advisory; a ratified replan relaxes it for one pass (RFC-13 #68).
        effective_confirmed = _resolve_confirmed(state_input, confirmed_only)
        entries = await LedgerService().read_general(
            str(investigation_id),
            kinds=[kind],
            confirmed_only=effective_confirmed,
        )
        if payload_match:
            entries = [
                e for e in entries
                if all(
                    (e.get("payload") or {}).get(k) == v
                    for k, v in payload_match.items()
                )
            ]
        if payload_exclude:
            entries = [
                e for e in entries
                if not all(
                    (e.get("payload") or {}).get(k) == v
                    for k, v in payload_exclude.items()
                )
            ]
        if entries:
            scope = "confirmed " if effective_confirmed else ""
            match_note = f" matching {sorted(payload_match)}" if payload_match else ""
            return True, f"{len(entries)} {scope}{kind} entries on ledger{match_note}"
        if payload_match:
            return False, f"no {kind} entries matching {sorted(payload_match)} on ledger yet"
        return False, f"no {kind} entries on ledger yet"

    return _condition


def make_evidence_condition(
    evidence_types: str | Iterable[str],
    *,
    confirmed_only: bool = False,
    input_key: str = "investigation_id",
) -> Callable[[dict[str, Any]], Awaitable[tuple[bool, str]]]:
    """Build a dispatch-hub condition that fires on a discovered evidence type.

    A content-aware sibling of :func:`make_discovery_condition`: it reads
    ``discovery`` entries and matches each entry's ``payload["evidence_type"]``
    against *evidence_types*. The forensics hub uses it so a discovered disk
    image activates the disk lane and a discovered pcap activates the network
    lane, off the shared ledger (RFC-13 #68). ``confirmed_only`` restricts to
    quorum-confirmed discoveries and honors the same ratified-replan relax
    flag as :func:`make_discovery_condition`.
    """
    wanted = {evidence_types} if isinstance(evidence_types, str) else set(evidence_types)

    async def _condition(state_input: dict[str, Any]) -> tuple[bool, str]:
        investigation_id = state_input.get(input_key)
        if not investigation_id:
            return False, f"no {input_key} on dispatch input"
        effective_confirmed = _resolve_confirmed(state_input, confirmed_only)
        entries = await LedgerService().read_general(
            str(investigation_id),
            kinds=["discovery"],
            confirmed_only=effective_confirmed,
        )
        matched = [
            e for e in entries
            if (e.get("payload") or {}).get("evidence_type") in wanted
        ]
        if matched:
            return True, f"{len(matched)} discovery entries matching {sorted(wanted)}"
        return False, f"no discovery matching {sorted(wanted)}"

    return _condition
