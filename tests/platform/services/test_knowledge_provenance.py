"""RFC-12 provenance + relevance-floor wiring tests for KnowledgeService.

Covers the two observable behaviours added by the criterion-1 provenance
half:

  1. ``KnowledgeService.store`` stamps ``model_id`` (from the resolved
     embedding provider), ``content_hash`` (sha256 of the stored text),
     ``source_type`` (derived from the ``kind`` hint), and ``updated_at``
     on every fresh row -- and ``content_hash`` differs when the content
     differs.

  2. ``PatternStoreBase._resolve_relevance_floor`` resolves the
     PlatformConfigSchema default 0.3 via ConfigRegistry, and an env
     override flows through the same lookup.

These are unit tests against the shared ``test_db`` fixture (see
tests/platform/conftest.py) which drops/creates the full SQLModel
metadata against aila_test -- no alembic migration required to see the
four new KnowledgeEntryRecord columns.

The embedding provider is stubbed so the tests never load
SentenceTransformer / BGE-M3; provenance is a metadata concern and
independent of the actual vector content.
"""
from __future__ import annotations

import hashlib

import pytest
from sqlmodel import select

from aila.platform.config import PlatformConfigSchema
from aila.platform.services.knowledge import KnowledgeService
from aila.platform.services.pattern_store import (
    PATTERN_RELEVANCE_FLOOR_DEFAULT,
    PatternStoreBase,
)
from aila.storage.database import async_session_scope
from aila.storage.db_models import KnowledgeEntryRecord
from aila.storage.registry import ConfigRegistry


class _StubProvider:
    """Minimal EmbeddingProvider satisfying the runtime-checkable Protocol.

    ``encode`` returns a zero vector of the requested dimension so the
    store path succeeds without downloading a real model. ``model_name``
    is the only field these tests read back -- the vector itself is
    inspected nowhere.
    """

    def __init__(self, model_name: str = "test-provider/vX", dim: int = 1024) -> None:
        self._name = model_name
        self._dim = dim

    @property
    def dimension(self) -> int:
        return self._dim

    @property
    def model_name(self) -> str:
        return self._name

    def encode(self, text: str) -> list[float]:
        del text  # unused -- provenance tests do not inspect vector content
        return [0.0] * self._dim

    async def encode_async(self, text: str) -> list[float]:
        return self.encode(text)


# ---------------------------------------------------------------------------
# store() provenance stamping
# ---------------------------------------------------------------------------


async def test_store_stamps_provenance_on_fresh_entry(test_db) -> None:
    """Every fresh insert carries model_id, content_hash, source_type, updated_at."""
    provider = _StubProvider("prov-x/model-y")
    svc = KnowledgeService(provider=provider)
    content = "hello knowledge world"

    result = await svc.store(
        namespace="agent:TestProvenance",
        content=content,
        metadata={"tag": "unit-test"},
    )
    assert result["operation"] == "inserted"
    entry_id = result["entry_id"]
    assert entry_id is not None

    async with async_session_scope() as sess:
        row = (
            await sess.exec(
                select(KnowledgeEntryRecord).where(
                    KnowledgeEntryRecord.id == entry_id,
                )
            )
        ).first()

    assert row is not None, "inserted row must be readable"
    assert row.model_id == "prov-x/model-y", (
        "model_id must match the resolved provider's model_name"
    )
    expected_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    assert row.content_hash == expected_hash, (
        "content_hash must equal sha256 of the stored content bytes"
    )
    # No explicit kind supplied -> the non-chunked path defaults sensibly.
    assert row.source_type == "document"
    assert row.updated_at is not None, "updated_at must be stamped on insert"


async def test_store_source_type_reflects_kind_hint(test_db) -> None:
    """``kind='code'`` on the non-chunked path stamps source_type='code'."""
    provider = _StubProvider()
    svc = KnowledgeService(provider=provider)

    result = await svc.store(
        namespace="agent:TestProvenance",
        content="def foo(): return 1",
        kind="code",
    )
    entry_id = result["entry_id"]

    async with async_session_scope() as sess:
        row = (
            await sess.exec(
                select(KnowledgeEntryRecord).where(
                    KnowledgeEntryRecord.id == entry_id,
                )
            )
        ).first()

    assert row is not None
    assert row.source_type == "code"


async def test_content_hash_differs_for_different_content(test_db) -> None:
    """Two stores with different text yield different content_hash values."""
    provider = _StubProvider()
    svc = KnowledgeService(provider=provider)

    r_alpha = await svc.store(namespace="agent:TestProvenance", content="alpha")
    r_beta = await svc.store(namespace="agent:TestProvenance", content="beta")

    async with async_session_scope() as sess:
        rows = (
            await sess.exec(
                select(KnowledgeEntryRecord).where(
                    KnowledgeEntryRecord.id.in_(
                        [r_alpha["entry_id"], r_beta["entry_id"]],
                    )
                )
            )
        ).all()

    hashes = {row.id: row.content_hash for row in rows}
    assert hashes[r_alpha["entry_id"]] != hashes[r_beta["entry_id"]], (
        "content_hash must vary with content -- collision here means store()"
        " is not hashing per-row content"
    )
    # Direct sanity: the pair matches sha256 of the raw text.
    assert hashes[r_alpha["entry_id"]] == hashlib.sha256(b"alpha").hexdigest()
    assert hashes[r_beta["entry_id"]] == hashlib.sha256(b"beta").hexdigest()


# ---------------------------------------------------------------------------
# Relevance-floor config-schema wiring
# ---------------------------------------------------------------------------


def test_platform_schema_declares_relevance_floor_default() -> None:
    """PlatformConfigSchema exposes the RFC-12 pattern relevance floor at 0.3.

    The schema default is the single source of truth: pattern_store's
    ``PATTERN_RELEVANCE_FLOOR_DEFAULT`` mirrors it, and the two must move
    together.
    """
    schema = PlatformConfigSchema()
    assert schema.knowledge_pattern_relevance_floor == pytest.approx(0.3)
    assert schema.knowledge_pattern_relevance_floor == pytest.approx(
        PATTERN_RELEVANCE_FLOOR_DEFAULT,
    )


async def test_resolve_relevance_floor_returns_platform_schema_default(
    test_db,
    monkeypatch,
) -> None:
    """With no env override and a registered platform schema the floor is 0.3.

    Registering the schema seeds ConfigEntryRecord with the field default,
    so :meth:`ConfigRegistry.get` reads it back via the DB path (fresh
    installs go through the schema-default path). The value must be 0.3,
    matching :data:`PlatformConfigSchema.knowledge_pattern_relevance_floor`.
    """
    monkeypatch.delenv(
        "AILA_PLATFORM_KNOWLEDGE_PATTERN_RELEVANCE_FLOOR",
        raising=False,
    )
    await ConfigRegistry().register("platform", PlatformConfigSchema)

    floor = await PatternStoreBase._resolve_relevance_floor()

    assert floor == pytest.approx(0.3)


async def test_resolve_relevance_floor_env_override_takes_effect(
    monkeypatch,
) -> None:
    """AILA_PLATFORM_KNOWLEDGE_PATTERN_RELEVANCE_FLOOR overrides the schema default.

    :meth:`ConfigRegistry.get` reads the env var before touching the cache
    or the DB, so this path is independent of the seeded schema default.
    """
    monkeypatch.setenv(
        "AILA_PLATFORM_KNOWLEDGE_PATTERN_RELEVANCE_FLOOR",
        "0.55",
    )

    floor = await PatternStoreBase._resolve_relevance_floor()

    assert floor == pytest.approx(0.55)
