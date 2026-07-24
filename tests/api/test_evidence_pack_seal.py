"""#52 evidence-pack sealing: tamper-evident merkle digest + C2 journal rows.

A BoundedEvidencePack was a mutable bucket with a self-reported drop list and
no verifiable digest. It now seals to a merkle root over the ordered section
hashes: verify() detects any post-seal content change or reordering, add()
refuses after sealing, and seal_and_journal writes evidence_added /
evidence_sealed rows into the C2 platform journal.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
from sqlmodel import select

from aila.platform.services.evidence_pack import (
    BoundedEvidencePack,
    EvidencePackSealedError,
    EvidenceSection,
)
from aila.platform.services.journal import verify_chain
from aila.storage.database import async_session_scope
from aila.storage.db_models import PlatformJournalRecord


def _pack() -> BoundedEvidencePack:
    pack = BoundedEvidencePack(hypothesis="h")
    pack.add(EvidenceSection(title="a", content="alpha", source="s1", priority=10))
    pack.add(EvidenceSection(title="b", content="bravo", source="s2", priority=20))
    return pack


def test_seal_then_verify_ok() -> None:
    pack = _pack()
    digest = pack.seal()
    assert len(digest) == 64
    assert pack.sealed is True
    assert pack.verify() is True


def test_verify_detects_content_tamper() -> None:
    pack = _pack()
    pack.seal()
    # Mutate a section's content after sealing.
    pack.sections[0].content = "tampered"
    assert pack.verify() is False


def test_verify_detects_reorder() -> None:
    pack = _pack()
    pack.seal()
    pack.sections.reverse()
    assert pack.verify() is False


def test_add_after_seal_raises() -> None:
    pack = _pack()
    pack.seal()
    with pytest.raises(EvidencePackSealedError):
        pack.add(EvidenceSection(title="c", content="charlie", source="s3"))


async def test_seal_and_journal_writes_rows(test_db) -> None:
    team = f"t-{uuid4().hex[:8]}"
    chain = f"team:{team}"
    inv = f"inv-{uuid4().hex[:8]}"
    pack = _pack()
    async with async_session_scope() as session:
        digest = await pack.seal_and_journal(
            session, investigation_id=inv, team_id=team
        )
        await session.commit()

    assert pack.sealed is True
    assert pack.seal_digest == digest

    async with async_session_scope() as session:
        rows = list(
            (
                await session.exec(
                    select(PlatformJournalRecord)
                    .where(PlatformJournalRecord.chain_id == chain)
                    .order_by(PlatformJournalRecord.seq.asc())
                )
            ).all()
        )
    kinds = [r.kind for r in rows]
    assert kinds == ["evidence_added", "evidence_added", "evidence_sealed"]
    assert rows[-1].payload_json["seal_digest"] == digest
    # Section content is referenced by hash, not stored inline.
    assert "content_hash" in rows[0].payload_json
    assert "content" not in rows[0].payload_json

    async with async_session_scope() as session:
        result = await verify_chain(session, chain_id=chain)
    assert result.ok is True
    assert result.checked == 3
