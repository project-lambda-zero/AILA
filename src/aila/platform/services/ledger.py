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
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from sqlalchemy import Column, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy import DateTime as SA_DateTime
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import Field, SQLModel, select

from aila.platform.contracts._common import utc_now
from aila.platform.uow import UnitOfWork

__all__ = [
    "InvestigationLedgerRecord",
    "LedgerService",
    "make_discovery_condition",
]

_UQ_IDEM = "uq_investigation_ledger_idem"


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
        """Change an objective's status via a new superseding entry."""
        async with _session_or_new(session) as (sess, _owns):
            latest = await self._latest_objective(
                sess, investigation_id, objective_key,
            )
            owner = latest.owner_branch_id if latest else None
            prior_id = latest.id if latest else None
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
        author_branch_id: str = "__system__",
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


def make_discovery_condition(
    kind: str = "discovery",
    *,
    confirmed_only: bool = False,
    input_key: str = "investigation_id",
) -> Callable[[dict[str, Any]], Awaitable[tuple[bool, str]]]:
    """Build a dispatch-hub condition that fires when the ledger holds a
    matching entry (RFC-13 #68).

    The returned async predicate matches the phase-graph ``GateFn`` shape:
    it reads the investigation id from the hub state input, reads the
    ledger, and returns ``(present, reason)``. ``confirmed_only`` restricts
    discoveries to those a quorum decision confirmed (a confirmed-trust
    phase). The discovery-driven module graphs use it to activate a phase
    only once a real discovery exists, rather than on a static edge.
    """

    async def _condition(state_input: dict[str, Any]) -> tuple[bool, str]:
        investigation_id = state_input.get(input_key)
        if not investigation_id:
            return False, f"no {input_key} on dispatch input"
        entries = await LedgerService().read_general(
            str(investigation_id),
            kinds=[kind],
            confirmed_only=confirmed_only,
        )
        if entries:
            scope = "confirmed " if confirmed_only else ""
            return True, f"{len(entries)} {scope}{kind} entries on ledger"
        return False, f"no {kind} entries on ledger yet"

    return _condition
