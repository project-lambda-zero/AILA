"""C2 append-only hash-chained platform journal.

Covers seq allocation, hash chaining, tamper detection via verify_chain, and
write-time C6 redaction. Runs against the Postgres test_db. The append-only
DB trigger is migration-only (create_all does not install it), so the tamper
test can rewrite a row to prove application-side detection.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
import sqlalchemy as sa
from sqlmodel import select as sm_select

from aila.platform.services.audit import record_audit_event_sync
from aila.platform.services.journal import (
    JournalEntry,
    JournalWriteError,
    append,
    append_sync,
    verify_chain,
)
from aila.storage.database import async_session_scope, session_scope
from aila.storage.db_models import PlatformJournalRecord


def _entry(action: str, payload: dict | None = None) -> JournalEntry:
    return JournalEntry(
        kind="audit",
        source="tests.journal",
        action=action,
        payload=payload or {"note": action},
    )


async def test_append_chains_sequentially(test_db) -> None:
    team = f"t-{uuid4().hex[:8]}"
    chain = f"team:{team}"
    async with async_session_scope() as session:
        r0 = await append(session, entry=_entry("a"), team_id=team)
        r1 = await append(session, entry=_entry("b"), team_id=team)
        r2 = await append(session, entry=_entry("c"), team_id=team)
        await session.commit()

    assert (r0.seq, r1.seq, r2.seq) == (0, 1, 2)
    assert r0.chain_id == chain
    # Each row_hash is a full 64-hex digest and links forward.
    assert len(r0.row_hash) == 64

    async with async_session_scope() as session:
        rows = list(
            (
                await session.execute(
                    sa.select(PlatformJournalRecord)
                    .where(PlatformJournalRecord.chain_id == chain)
                    .order_by(PlatformJournalRecord.seq.asc())
                )
            ).scalars().all()
        )
    assert rows[0].prev_hash is None  # genesis
    assert rows[1].prev_hash == rows[0].row_hash
    assert rows[2].prev_hash == rows[1].row_hash

    async with async_session_scope() as session:
        result = await verify_chain(session, chain_id=chain)
    assert result.ok is True
    assert result.checked == 3


async def test_verify_detects_payload_tampering(test_db) -> None:
    team = f"t-{uuid4().hex[:8]}"
    chain = f"team:{team}"
    async with async_session_scope() as session:
        await append(session, entry=_entry("first"), team_id=team)
        await append(session, entry=_entry("second"), team_id=team)
        await session.commit()

    # Rewrite the payload of seq 1 without recomputing its hashes (the
    # append-only trigger is migration-only, so this UPDATE lands on test_db).
    async with async_session_scope() as session:
        await session.execute(
            sa.update(PlatformJournalRecord)
            .where(
                PlatformJournalRecord.chain_id == chain,
                PlatformJournalRecord.seq == 1,
            )
            .values(payload_json={"note": "tampered"})
        )
        await session.commit()

    async with async_session_scope() as session:
        result = await verify_chain(session, chain_id=chain)
    assert result.ok is False
    assert result.first_bad_seq == 1
    assert result.detail == "payload_hash mismatch"


async def test_append_redacts_secret_payload(test_db) -> None:
    team = f"t-{uuid4().hex[:8]}"
    chain = f"team:{team}"
    async with async_session_scope() as session:
        await append(
            session,
            entry=_entry("rotate", payload={"api_key": "sk-live-xyz", "note": "ok"}),
            team_id=team,
        )
        await session.commit()

    async with async_session_scope() as session:
        row = (
            await session.execute(
                sa.select(PlatformJournalRecord).where(
                    PlatformJournalRecord.chain_id == chain
                )
            )
        ).scalars().first()
    assert row is not None
    assert row.payload_json["api_key"] == "[REDACTED]"
    assert row.payload_json["note"] == "ok"
    assert row.contains_secret is True
    assert "sk-live-xyz" not in str(row.payload_json)

    # The redacted payload still verifies (hash computed over the redaction).
    async with async_session_scope() as session:
        result = await verify_chain(session, chain_id=chain)
    assert result.ok is True


async def test_append_rejects_unknown_kind(test_db) -> None:
    async with async_session_scope() as session:
        with pytest.raises(JournalWriteError):
            await append(
                session,
                entry=JournalEntry(kind="bogus", source="t", action="x"),
                team_id="t-x",
            )


async def test_append_sync_chains(test_db) -> None:
    """The sync append path (worker-thread emitter / CLI) chains identically to
    the async path and passes the async chain verifier."""
    team = f"t-{uuid4().hex[:8]}"
    chain = f"team:{team}"
    with session_scope() as s:
        r0 = append_sync(s, entry=_entry("a"), team_id=team)
        r1 = append_sync(s, entry=_entry("b"), team_id=team)
        s.commit()

    assert (r0.seq, r1.seq) == (0, 1)
    assert r0.chain_id == chain
    assert len(r0.row_hash) == 64

    with session_scope() as s:
        rows = list(
            s.exec(
                sm_select(PlatformJournalRecord)
                .where(PlatformJournalRecord.chain_id == chain)
                .order_by(PlatformJournalRecord.seq.asc())
            ).all()
        )
    assert rows[0].prev_hash is None  # genesis
    assert rows[1].prev_hash == rows[0].row_hash

    # Cross-verify with the async verifier: the sync path shares _build_row, so
    # a sync-written chain must recompute clean.
    async with async_session_scope() as session:
        result = await verify_chain(session, chain_id=chain)
    assert result.ok is True
    assert result.checked == 2


async def test_record_audit_event_sync_writes_journal(test_db) -> None:
    """The migrated CLI audit path writes a tamper-evident journal row (#52)
    rather than the legacy AuditEventRecord table."""
    run_id = f"r-{uuid4().hex[:8]}"
    with session_scope() as s:
        record_audit_event_sync(
            s,
            run_id=run_id,
            stage="auth",
            action="create_api_key",
            status="completed",
            target="ak_abc",
            user_id="cli",
            details={"role": "admin"},
        )
        s.commit()

    with session_scope() as s:
        row = s.exec(
            sm_select(PlatformJournalRecord).where(
                PlatformJournalRecord.run_id == run_id
            )
        ).first()
    assert row is not None
    assert row.kind == "audit"
    assert row.action == "create_api_key"
    assert row.actor_id == "cli"
    assert row.actor_kind == "user"
    assert row.source == "audit.auth"
    assert row.payload_json["target"] == "ak_abc"
    assert row.payload_json["details"] == {"role": "admin"}
