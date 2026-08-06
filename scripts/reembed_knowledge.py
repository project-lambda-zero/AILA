"""Re-embed KnowledgeEntryRecord rows at full 1024-dim BGE-M3.

Run once after migration ``077_knowledge_embedding_1024`` widens the embedding
column to ``vector(1024)`` and clears the prior truncated vectors. Each row is
re-embedded from its stored ``content`` through the canonical
:class:`KnowledgeService` provider (BGE-M3 by default), so vectors land in one
consistent embedding space.

Usage:
    AILA_DATABASE_URL=postgresql+asyncpg://... python scripts/reembed_knowledge.py
    # add --all to re-embed every row, not just the NULL (un-backfilled) ones

Idempotent: re-running only refreshes vectors. Safe to interrupt; already
committed batches persist and the next run picks up the remaining NULL rows.
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from aila._dotenv import load_project_env  # noqa: E402

load_project_env()

from sqlalchemy import select, update  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine  # noqa: E402

from aila.platform.services.knowledge import KnowledgeService  # noqa: E402
from aila.storage.db_models import KnowledgeEntryRecord  # noqa: E402

_COMMIT_EVERY = 200


async def _reembed(url: str, only_null: bool) -> int:
    engine = create_async_engine(url, echo=False)
    service = KnowledgeService()
    processed = 0
    try:
        async with AsyncSession(engine) as session:
            stmt = select(KnowledgeEntryRecord.id, KnowledgeEntryRecord.content)
            if only_null:
                stmt = stmt.where(KnowledgeEntryRecord.embedding.is_(None))
            rows = (await session.execute(stmt)).all()
            for row_id, content in rows:
                vector = service.embed(content)
                await session.execute(
                    update(KnowledgeEntryRecord)
                    .where(KnowledgeEntryRecord.id == row_id)
                    .values(embedding=vector)
                )
                processed += 1
                if processed % _COMMIT_EVERY == 0:
                    await session.commit()
                    print(f"  re-embedded {processed} rows")
            await session.commit()
    finally:
        await engine.dispose()
    return processed


def main() -> None:
    url = os.environ.get("AILA_DATABASE_URL")
    if not url:
        raise SystemExit("AILA_DATABASE_URL is not set")
    only_null = "--all" not in sys.argv[1:]
    scope = "NULL-embedding" if only_null else "all"
    print(f"Re-embedding {scope} knowledge rows via {KnowledgeService().provider.model_name} ...")
    count = asyncio.run(_reembed(url, only_null))
    print(f"Done: re-embedded {count} rows at {KnowledgeService().provider.dimension} dims.")


if __name__ == "__main__":
    main()
