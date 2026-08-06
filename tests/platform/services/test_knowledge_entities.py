"""RFC-12 content metadata: entity extraction + metadata_filter retrieval.

``extract_entities`` is a deterministic regex pass; ``store(extract_entities
=True)`` stamps the tags under ``entry_metadata["entities"]``; ``retrieve
(metadata_filter=...)`` scopes the hybrid candidate set by those tags.
"""
from __future__ import annotations

import json

from sqlmodel import select

from aila.platform.services.knowledge import KnowledgeService, _metadata_matches
from aila.platform.services.knowledge_entities import extract_entities
from aila.storage.database import async_session_scope
from aila.storage.db_models import KnowledgeEntryRecord

_DIM = 1024


class _ConstProvider:
    """Fixed non-zero embedding so retrieve's cosine leg is well-defined."""

    @property
    def dimension(self) -> int:
        return _DIM

    @property
    def model_name(self) -> str:
        return "test-provider/vX"

    def encode(self, text: str) -> list[float]:
        del text
        vec = [0.0] * _DIM
        vec[0] = 1.0
        return vec

    async def encode_async(self, text: str) -> list[float]:
        return self.encode(text)


# --- pure extractor ---------------------------------------------------------


def test_extract_all_families() -> None:
    ents = extract_entities(
        "CVE-2024-1234 CWE-79 CAPEC-66 T1055.001 MASVS-STORAGE-1",
    )
    assert ents == [
        "CAPEC-66", "CVE-2024-1234", "CWE-79", "MASVS-STORAGE-1", "T1055.001",
    ]


def test_extract_normalizes_and_dedupes() -> None:
    assert extract_entities("cve-2024-0001 CVE-2024-0001 Cve-2024-0001") == [
        "CVE-2024-0001",
    ]


def test_extract_empty() -> None:
    assert extract_entities("no identifiers here") == []
    assert extract_entities("") == []


# --- _metadata_matches ------------------------------------------------------


def test_metadata_matches_list_membership() -> None:
    meta = json.dumps({"entities": ["CVE-2024-1", "CWE-79"]})
    assert _metadata_matches(meta, {"entities": "CVE-2024-1"}) is True
    assert _metadata_matches(meta, {"entities": "CVE-9999-9"}) is False


def test_metadata_matches_scalar_equality() -> None:
    meta = json.dumps({"domain": "android"})
    assert _metadata_matches(meta, {"domain": "android"}) is True
    assert _metadata_matches(meta, {"domain": "ios"}) is False


def test_metadata_matches_missing_key_and_bad_json() -> None:
    assert _metadata_matches("{}", {"entities": "x"}) is False
    assert _metadata_matches("not json", {"a": "b"}) is False


# --- store stamping + retrieval filter (DB) ---------------------------------


async def test_store_stamps_entities(test_db) -> None:
    del test_db
    svc = KnowledgeService(provider=_ConstProvider())
    r = await svc.store(
        namespace="agent:Ent",
        content="patch for CVE-2024-5555 and CWE-89",
        extract_entities=True,
    )
    async with async_session_scope() as session:
        row = (await session.exec(
            select(KnowledgeEntryRecord).where(
                KnowledgeEntryRecord.id == r["entry_id"],
            )
        )).first()
    meta = json.loads(row.entry_metadata)
    assert "CVE-2024-5555" in meta["entities"]
    assert "CWE-89" in meta["entities"]


async def test_store_no_extract_no_entities(test_db) -> None:
    del test_db
    svc = KnowledgeService(provider=_ConstProvider())
    r = await svc.store(
        namespace="agent:EntOff",
        content="CVE-2024-5555 here",
        extract_entities=False,
    )
    async with async_session_scope() as session:
        row = (await session.exec(
            select(KnowledgeEntryRecord).where(
                KnowledgeEntryRecord.id == r["entry_id"],
            )
        )).first()
    assert "entities" not in json.loads(row.entry_metadata)


async def test_retrieve_metadata_filter_narrows(test_db) -> None:
    del test_db
    svc = KnowledgeService(provider=_ConstProvider())
    await svc.store(
        namespace="agent:EntF",
        content="finding about CVE-2024-1111 issue", extract_entities=True,
    )
    await svc.store(
        namespace="agent:EntF",
        content="finding about CVE-2024-2222 issue", extract_entities=True,
    )
    scoped = await svc.retrieve(
        "finding issue", namespaces=["agent:EntF"],
        metadata_filter={"entities": "CVE-2024-1111"}, limit=10,
    )
    scoped_contents = [h["content"] for h in scoped]
    assert any("CVE-2024-1111" in c for c in scoped_contents)
    assert not any("CVE-2024-2222" in c for c in scoped_contents)

    both = await svc.retrieve("finding issue", namespaces=["agent:EntF"], limit=10)
    both_contents = [h["content"] for h in both]
    assert any("CVE-2024-1111" in c for c in both_contents)
    assert any("CVE-2024-2222" in c for c in both_contents)
