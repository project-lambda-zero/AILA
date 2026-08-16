"""Acceptance test for the stable-core knowledge seeder (issue #107).

Before this slice landed the ``platform:stable_core:*`` namespace was
empty in every fresh deployment because no writer wrote into it. This
test locks the fix: the seeder upserts every ``.md`` file under
:data:`SEED_DIR` into the stable-core namespace, and the router's
STABLE_CORE retrieval branch then returns those rows for a matching
query.

The test runs against the shared Postgres ``test_db`` fixture. It uses
the stub embedding provider from the wider retrieval test suite so the
seeder can call :meth:`KnowledgeService.store` without loading a real
model weight in the test process.
"""
from __future__ import annotations

import pytest
from sqlmodel import select

from aila.platform.services import knowledge as knowledge_mod
from aila.platform.services.knowledge import KnowledgeService
from aila.platform.services.knowledge_router import Route
from aila.platform.services.knowledge_stable_core import (
    STABLE_CORE_NAMESPACE_PREFIX,
)
from aila.platform.services.knowledge_stable_core_seed import (
    SEED_DIR,
    seed_stable_core_knowledge,
)
from aila.storage.database import async_session_scope
from aila.storage.db_models import KnowledgeEntryRecord

# All-ones embedding for the stub provider. A zero vector leaves
# pgvector's cosine_distance undefined; ones keep the vector legal
# without matching the real model output. The stable-core route does
# not touch the embedding column, so this only matters for the write
# side.
_STUB_EMBEDDING: list[float] = [1.0] * 1024


class _StubProvider:
    """Minimal EmbeddingProvider that produces a fixed vector.

    The seeder writes through :meth:`KnowledgeService.store`, which
    encodes the content before insert. A stub provider avoids loading
    a real BGE / MiniLM model just to satisfy the column type.
    """

    @property
    def dimension(self) -> int:
        return 1024

    @property
    def model_name(self) -> str:
        return "stub-provider"

    def encode(self, text: str) -> list[float]:
        del text
        return list(_STUB_EMBEDDING)

    async def encode_async(self, text: str) -> list[float]:
        return self.encode("")


pytestmark = pytest.mark.asyncio


async def test_stable_core_seeder_writes_and_retrieval_finds_seeded_key(
    test_db,
) -> None:
    """Seed the on-disk .md corpus and prove the router serves one entry.

    Preconditions:
      * Fresh test DB (``test_db`` truncated everything on setup) so the
        stable-core namespace starts empty.
      * The stub embedding provider avoids loading a real model.

    Assertions:
      1. Before the seeder runs, no ``platform:stable_core:*`` row
         exists (this is the pre-fix baseline that used to hold
         forever).
      2. After the seeder runs, one row per seed file is present and
         each row's namespace prefix matches
         :data:`STABLE_CORE_NAMESPACE_PREFIX`.
      3. ``retrieve_routed`` with a query naming a seeded rubric
         classifies to :data:`Route.STABLE_CORE`, returns at least one
         hit, and the top hit's content carries text from the
         corresponding seed file.
    """
    del test_db  # fixture triggers per-test DB isolation; not consumed here.
    # Drop the process-shared CAG cache so a previous test's preload
    # cannot mask the fresh-DB baseline below.
    knowledge_mod._STABLE_CORE_CACHE.invalidate()

    # (1) Baseline: no stable-core rows exist yet -- this is what the
    # namespace looked like in every deployment before the seeder shipped.
    async with async_session_scope() as session:
        pre_rows = (
            await session.exec(
                select(KnowledgeEntryRecord).where(
                    KnowledgeEntryRecord.namespace.like(
                        f"{STABLE_CORE_NAMESPACE_PREFIX}%",
                    ),
                ),
            )
        ).all()
    assert pre_rows == [], (
        "stable_core namespace must start empty on a fresh DB; "
        f"found {len(pre_rows)} rows"
    )

    # (2) Run the seeder with the stub-backed service so the write path
    # does not load a real embedding model.
    service = KnowledgeService(provider=_StubProvider())
    written = await seed_stable_core_knowledge(service=service)

    # There is at least one committed seed file on disk (the slice
    # ships three); the seeder MUST report a non-zero write count.
    expected = sum(
        1 for p in SEED_DIR.iterdir()
        if p.is_file() and p.suffix == ".md"
    )
    assert expected > 0, (
        f"no seed files discovered under {SEED_DIR}; test cannot verify seeding"
    )
    assert written == expected, (
        f"seeder wrote {written} rows but expected {expected} seed files"
    )

    async with async_session_scope() as session:
        post_rows = (
            await session.exec(
                select(KnowledgeEntryRecord).where(
                    KnowledgeEntryRecord.namespace.like(
                        f"{STABLE_CORE_NAMESPACE_PREFIX}%",
                    ),
                ),
            )
        ).all()
    assert len(post_rows) == expected, (
        f"post-seed DB has {len(post_rows)} stable-core rows; expected {expected}"
    )
    # Every row's namespace carries the required prefix and a non-empty subkey.
    for row in post_rows:
        assert row.namespace.startswith(STABLE_CORE_NAMESPACE_PREFIX), (
            f"seeded row has wrong namespace: {row.namespace!r}"
        )
        assert row.namespace != STABLE_CORE_NAMESPACE_PREFIX, (
            "seeded row missing subkey suffix"
        )
        assert row.content, f"seeded row {row.namespace!r} has empty content"

    # (3) Retrieval proof: a query naming a seeded rubric MUST classify
    # to STABLE_CORE and return at least the matching entry. The
    # accept-bar file contains the phrase 'accept-bar' verbatim, and
    # the router keyword set makes that a stable-core query.
    routed = await service.retrieve_routed(
        query="accept-bar rubric for the confidence gate",
        limit=10,
    )
    assert routed["route"] == Route.STABLE_CORE.value, (
        f"router chose {routed['route']!r} instead of stable_core"
    )
    assert routed["count"] >= 1, (
        f"stable-core retrieval returned zero hits: {routed}"
    )
    top_content = str(routed["results"][0].get("content") or "").lower()
    # The seeded accept-bar file mentions 'accept-bar' inline; its
    # token overlap with the query lands it as the top hit.
    assert "accept-bar" in top_content, (
        f"top stable-core hit does not carry the seeded accept-bar content: "
        f"{top_content[:120]!r}"
    )
