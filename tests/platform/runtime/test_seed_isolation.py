"""#45 -- module seed-version stamping and seed-loop isolation.

Two production contracts are exercised here:

* Every module stamps SeedVersionRecord on seed_data (the malware module was
  the only in-tree module that did not).
* The platform seed loop isolates a failing module: its partial state is rolled
  back and the remaining modules still seed, so one degraded module cannot
  strand platform startup.
"""
from __future__ import annotations

import pytest
from sqlmodel import select

from aila.platform.runtime.builder import _seed_all_modules
from aila.storage.database import async_session_scope
from aila.storage.db_models import SeedVersionRecord


@pytest.mark.asyncio
async def test_malware_seed_data_stamps_version(test_db):
    from aila.modules.malware.module import SEED_VERSION, MalwareModule

    module = MalwareModule()
    async with async_session_scope() as session:
        await module.seed_data(session)

    async with async_session_scope() as session:
        rows = (await session.exec(
            select(SeedVersionRecord).where(SeedVersionRecord.module_id == module.module_id)
        )).all()
    assert len(rows) == 1
    assert rows[0].seed_version == SEED_VERSION


@pytest.mark.asyncio
async def test_malware_seed_data_idempotent(test_db):
    from aila.modules.malware.module import MalwareModule

    module = MalwareModule()
    for _ in range(2):
        async with async_session_scope() as session:
            await module.seed_data(session)

    async with async_session_scope() as session:
        rows = (await session.exec(
            select(SeedVersionRecord).where(SeedVersionRecord.module_id == module.module_id)
        )).all()
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_seed_loop_isolates_failing_module(test_db):
    from aila.modules.malware.module import MalwareModule

    class _BoomModule:
        module_id = "boom"

        async def seed_data(self, session):
            session.add(SeedVersionRecord(module_id="boom", seed_version="9.9"))
            raise RuntimeError("seed boom")

    good = MalwareModule()
    # Failing module first: its raise must neither leak its partial row nor stop
    # the healthy module that follows from seeding.
    async with async_session_scope() as session:
        await _seed_all_modules(session, [_BoomModule(), good])

    async with async_session_scope() as session:
        boom = (await session.exec(
            select(SeedVersionRecord).where(SeedVersionRecord.module_id == "boom")
        )).all()
        good_rows = (await session.exec(
            select(SeedVersionRecord).where(SeedVersionRecord.module_id == good.module_id)
        )).all()
    assert boom == []
    assert len(good_rows) == 1
