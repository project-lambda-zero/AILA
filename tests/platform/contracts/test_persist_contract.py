"""Direct unit tests for ``aila.platform.contracts.persist.PersistContract``.

Closes the #62 coverage gap on the persistence primitive: prior tests only
exercised ``upsert_many`` through ``state_persist`` and one homogeneity check,
so the single-record ``upsert`` conflict path, the no-natural-key insert
path, and the ``id is None`` exclusion invariant had no direct assertions.

Runs against the shared Postgres ``test_db`` fixture. Every write is
committed inside the test so a follow-up read sees the row; the fixture
truncates all tables on teardown so nothing leaks across tests.
"""
from __future__ import annotations

import uuid

import pytest
from sqlmodel import select

from aila.modules.vulnerability.db_models import LatestFindingRecord
from aila.platform.contracts.persist import PersistContract
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowRunRecord


def _finding(
    cve: str,
    *,
    score: float = 5.0,
    criticality: str = "High",
    host: str = "10.0.0.1",
) -> LatestFindingRecord:
    """Assemble a LatestFindingRecord with sensible defaults for the assertions."""
    return LatestFindingRecord(
        host=host,
        package_name="openssl",
        cve_id=cve,
        system_id=1,
        criticality=criticality,
        score=score,
        nvd_url=f"https://nvd.nist.gov/vuln/detail/{cve}",
    )


class TestUpsertSingle:
    """PersistContract.upsert on a single record hits the natural-key branch."""

    @pytest.mark.asyncio
    async def test_upsert_inserts_when_row_absent(self, test_db) -> None:
        del test_db  # fixture triggers per-test truncation
        async with async_session_scope() as session:
            await PersistContract.upsert(session, _finding("CVE-2024-1001"))
            await session.commit()

        async with async_session_scope() as session:
            rows = list((await session.exec(select(LatestFindingRecord))).all())
        assert len(rows) == 1
        assert rows[0].cve_id == "CVE-2024-1001"
        assert rows[0].score == 5.0

    @pytest.mark.asyncio
    async def test_upsert_updates_existing_row_on_natural_key_conflict(
        self, test_db,
    ) -> None:
        """Second upsert for the same natural key updates the non-key columns.

        Proves the ``ON CONFLICT DO UPDATE`` path: without it a second call
        would either raise IntegrityError (unique constraint on the natural
        key) or leave the old score in place.
        """
        del test_db
        async with async_session_scope() as session:
            await PersistContract.upsert(
                session, _finding("CVE-2024-2002", score=5.0, criticality="Moderate"),
            )
            await session.commit()

        async with async_session_scope() as session:
            await PersistContract.upsert(
                session,
                _finding("CVE-2024-2002", score=9.5, criticality="Immediate"),
            )
            await session.commit()

        async with async_session_scope() as session:
            rows = list((await session.exec(select(LatestFindingRecord))).all())
        assert len(rows) == 1, (
            f"upsert must not proliferate rows on natural-key conflict; got {len(rows)}"
        )
        assert rows[0].score == 9.5
        assert rows[0].criticality == "Immediate"

    @pytest.mark.asyncio
    async def test_upsert_excludes_none_id_from_insert_values(
        self, test_db,
    ) -> None:
        """A record whose ``id`` is None must not carry ``id=NULL`` into the
        INSERT payload -- the DB-side serial sequence generates the id.

        Regression guard: if the None-id exclusion in ``PersistContract.upsert``
        regresses to ``INSERT ... (id, ...) VALUES (NULL, ...)`` on a
        ``SERIAL`` primary key, Postgres either raises NotNullViolationError
        or (for BIGSERIAL columns that permit NULL through the ORM path)
        the row lands with id=NULL and subsequent selects blow up.
        """
        del test_db
        record = _finding("CVE-2024-3003")
        assert record.id is None, "sanity: id must start None so the DB assigns it"

        async with async_session_scope() as session:
            await PersistContract.upsert(session, record)
            await session.commit()

        async with async_session_scope() as session:
            rows = list((await session.exec(select(LatestFindingRecord))).all())
        assert len(rows) == 1
        assert rows[0].id is not None, "PK must be populated by the sequence"
        assert isinstance(rows[0].id, int)


class TestUpsertNoNaturalKey:
    """Models without ``__natural_key__`` fall back to plain ``session.add``.

    ``WorkflowRunRecord`` is the canonical example: it carries a UUID PK and
    no natural key, so ``PersistContract.upsert`` must delegate to
    ``session.add(record)`` (no ON CONFLICT clause could apply). A regression
    that always emitted an ON CONFLICT statement would either raise or
    silently no-op on the second call.
    """

    @pytest.mark.asyncio
    async def test_upsert_inserts_when_model_has_no_natural_key(
        self, test_db,
    ) -> None:
        del test_db
        assert getattr(WorkflowRunRecord, "__natural_key__", None) is None, (
            "sanity: WorkflowRunRecord must remain without a natural key"
        )
        run_id = str(uuid.uuid4())
        record = WorkflowRunRecord(
            id=run_id,
            query_text="no-natural-key upsert path",
            action_id="test",
            module_id="test",
        )
        async with async_session_scope() as session:
            await PersistContract.upsert(session, record)
            await session.commit()

        async with async_session_scope() as session:
            fetched = await session.get(WorkflowRunRecord, run_id)
        assert fetched is not None
        assert fetched.query_text == "no-natural-key upsert path"


class TestUpsertManyEdgeCases:
    """Direct coverage on the ``upsert_many`` code paths not touched by the
    existing state_persist-driven tests: the empty-list short-circuit and the
    None-id exclusion inside a batch.
    """

    @pytest.mark.asyncio
    async def test_upsert_many_empty_list_is_no_op(self, test_db) -> None:
        """An empty batch returns without touching the session."""
        del test_db
        async with async_session_scope() as session:
            await PersistContract.upsert_many(session, [])
            await session.commit()
        async with async_session_scope() as session:
            rows = list((await session.exec(select(LatestFindingRecord))).all())
        assert rows == []

    @pytest.mark.asyncio
    async def test_upsert_many_excludes_none_id_across_batch(
        self, test_db,
    ) -> None:
        """Every batch member with ``id=None`` lands with a sequence-assigned
        id, even alongside a conflicting row that already exists.
        """
        del test_db
        async with async_session_scope() as session:
            await PersistContract.upsert(session, _finding("CVE-2024-9001"))
            await session.commit()

        batch = [
            _finding("CVE-2024-9001", score=9.9, criticality="Immediate"),
            _finding("CVE-2024-9002", score=7.5),
            _finding("CVE-2024-9003", score=6.0),
        ]
        assert all(r.id is None for r in batch)

        async with async_session_scope() as session:
            await PersistContract.upsert_many(session, batch)
            await session.commit()

        async with async_session_scope() as session:
            rows = list((await session.exec(select(LatestFindingRecord))).all())
        assert {r.cve_id for r in rows} == {
            "CVE-2024-9001", "CVE-2024-9002", "CVE-2024-9003",
        }
        assert all(r.id is not None for r in rows)
        conflict_row = next(r for r in rows if r.cve_id == "CVE-2024-9001")
        assert conflict_row.score == 9.9
        assert conflict_row.criticality == "Immediate"
