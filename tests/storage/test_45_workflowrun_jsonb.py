"""#45 -- workflowrunrecord.route_json / short_memory_json / summary_json JSONB.

Migration 106 flipped the three columns from ``Text`` (JSON-in-Text) to
``JSONB``. The two behaviors this file locks in:

1) **Dict round-trip.**  A dict written to any of the three columns comes
   back as a dict (not a string) via SQLAlchemy on both drivers -- the fix
   spec's central hazard. The async ``psycopg``-flavour cross-check lives
   with the parent's live-verification pass (asyncpg write from a worker,
   psycopg read from the API); this file covers the synchronous psycopg
   path that the majority of tests and admin queries use, which is enough
   to catch the "asyncpg returns str" / "psycopg returns dict" split that
   migration 104's docstring explicitly warned about.

2) **Substring semantics unchanged.**  ``systems.py`` filters completed
   runs by ``sys_record.name in route_json``. Before #45 this was a raw
   string ``LIKE``-style substring against the text column; after #45 the
   column is JSONB and the router serializes the dict back to text
   (via ``json.dumps``) for the substring check.  Both the in-Python
   substring test and the SQL ``.contains()`` predicate (server-side
   ``cast(JSONB, Text).contains(...)``) must keep matching a system name
   embedded in the ``target`` field of ``route_json``.
"""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest
from sqlalchemy import Text, cast
from sqlmodel import select

from aila.api.routers.systems import _build_scan_map
from aila.storage.database import async_session_scope, session_scope
from aila.storage.db_models import WorkflowRunRecord


def _run(
    *,
    run_id: str,
    route_json: dict[str, object] | None = None,
    short_memory_json: dict[str, object] | None = None,
    summary_json: dict[str, object] | None = None,
    completed_at: datetime | None = None,
    team_id: str | None = None,
) -> WorkflowRunRecord:
    return WorkflowRunRecord(
        id=run_id,
        query_text="test",
        action_id="",
        status="completed",
        route_json=route_json or {},
        short_memory_json=short_memory_json or {},
        summary_json=summary_json or {},
        completed_at=completed_at or datetime.now(UTC),
        team_id=team_id,
    )


def _seed(*records: object) -> None:
    """Insert records via the sync session_scope.

    Wrapped in a sync helper (rather than called inline from an ``async``
    body) so a sync psycopg round-trip does not block the asyncio event
    loop -- the ``sync_in_async`` honesty audit rule. Callers hand this
    to ``asyncio.to_thread`` from the async test body.
    """
    with session_scope() as s:
        for record in records:
            s.add(record)
        s.commit()


@pytest.mark.asyncio
async def test_workflowrunrecord_jsonb_dict_round_trip(storage_db) -> None:
    """#45: writing a dict to each of the three JSONB columns returns a dict
    on re-read (not a JSON string, not a double-encoded blob)."""
    payload_route: dict[str, object] = {
        "target": "web01",
        "selected_module": "vulnerability",
        "nested": {"a": 1, "b": [2, 3]},
    }
    payload_short: dict[str, object] = {"run_state": {"turns": 2}, "error": None}
    payload_summary: dict[str, object] = {
        "action_id": "vulnerability.analyze",
        "module_id": "vulnerability",
        "artifacts": {"primary_report": "/reports/r.csv"},
    }

    await asyncio.to_thread(
        _seed,
        _run(
            run_id="run-jsonb-1",
            route_json=payload_route,
            short_memory_json=payload_short,
            summary_json=payload_summary,
        ),
    )

    async with async_session_scope() as session:
        row = (
            await session.exec(
                select(WorkflowRunRecord).where(WorkflowRunRecord.id == "run-jsonb-1")
            )
        ).first()

    assert row is not None
    # Every column returns a dict, NOT a JSON string. This is the property
    # the pre-JSONB Text column could not guarantee across drivers.
    assert isinstance(row.route_json, dict), type(row.route_json)
    assert isinstance(row.short_memory_json, dict), type(row.short_memory_json)
    assert isinstance(row.summary_json, dict), type(row.summary_json)

    # Values round-trip byte-identical.
    assert row.route_json == payload_route
    assert row.short_memory_json == payload_short
    assert row.summary_json == payload_summary
    # Nested containers survive as native Python types.
    assert row.route_json["nested"] == {"a": 1, "b": [2, 3]}


@pytest.mark.asyncio
async def test_systems_route_json_substring_match_preserved(storage_db) -> None:
    """#45: ``systems.py`` matches system names against ``route_json`` via
    substring. The pre-JSONB behavior treated the column as text and used
    ``name in route_json`` / ``.contains(name)``. Post-JSONB the column is
    a dict; the router serializes it back to text (or ``cast(..., Text)``
    server-side) so a name embedded in ``target`` still matches.
    """
    # Seed three runs: two mention "web01" inside route_json.target, one
    # mentions a different host. The substring surface must match exactly
    # the two web01 runs.
    web01_a = _run(
        run_id="run-web01-a",
        route_json={"target": "web01"},
        completed_at=datetime(2025, 1, 1, tzinfo=UTC),
    )
    web01_b = _run(
        run_id="run-web01-b",
        route_json={"target": "web01", "selected_module": "vulnerability"},
        completed_at=datetime(2025, 1, 2, tzinfo=UTC),
    )
    other = _run(
        run_id="run-other",
        route_json={"target": "db01"},
        completed_at=datetime(2025, 1, 3, tzinfo=UTC),
    )
    await asyncio.to_thread(_seed, web01_a, web01_b, other)

    # 1) In-Python substring pattern (mirrors systems.py:_build_scan_map,
    #    which also drives get_system_scans).
    async with async_session_scope() as session:
        scan_map = await _build_scan_map(session, ["web01", "db01", "absent"])

    # web01 finds a match; db01 finds a match; absent stays absent.
    assert set(scan_map) == {"web01", "db01"}
    web01_completed_at, web01_status = scan_map["web01"]
    # Most-recent match wins (run-web01-b is newer than run-web01-a).
    assert web01_completed_at == datetime(2025, 1, 2, tzinfo=UTC)
    assert web01_status == "completed"

    # 2) SQL-side substring pattern (mirrors get_system() where a system's
    #    name is matched against route_json via cast(..., Text).contains).
    async with async_session_scope() as session:
        stmt = select(WorkflowRunRecord).where(
            cast(WorkflowRunRecord.route_json, Text).contains("web01")
        )
        matched = list((await session.exec(stmt)).all())

    assert {row.id for row in matched} == {"run-web01-a", "run-web01-b"}
