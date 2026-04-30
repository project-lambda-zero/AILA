"""Integration tests for Phase 158: seed loading, LLM resolution E2E, schema version isolation."""

from __future__ import annotations

import json
import os
import uuid

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession as SQLModelAsyncSession

from aila.modules.sbd_nfr.db_models import (
    SbdNfrAnswerRecord,
    SbdNfrQuestionOptionRecord,
    SbdNfrQuestionRecord,
    SbdNfrQuestionSubtaskMapRecord,
    SbdNfrResolutionResultRecord,
    SbdNfrSchemaVersionRecord,
    SbdNfrSectionRecord,
    SbdNfrSessionRecord,
    SbdNfrSubgroupRecord,
    SbdNfrSubtaskComponentRecord,
)
from aila.modules.sbd_nfr.module import SbdNfrModule
from aila.modules.sbd_nfr.services.resolution_service import (
    get_resolution_results,
    run_resolution,
)
from aila.modules.sbd_nfr.services.schema_service import get_schema_tree
from aila.storage.db_models import SeedVersionRecord

# ---------------------------------------------------------------------------
# Mark all tests in this module as asyncio
# ---------------------------------------------------------------------------

pytestmark = pytest.mark.asyncio

_TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


# ---------------------------------------------------------------------------
# Extended in-memory fixture that includes the SeedVersionRecord table
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def seeded_db_session():
    """Async DB session with both sbd_nfr_* tables AND seedversionrecord.

    The base async_db_session fixture (conftest.py) only creates sbd_nfr_*
    tables.  seed_data() also reads/writes SeedVersionRecord (table:
    seedversionrecord), so this fixture extends the setup to include it.

    Yields a clean SQLModel AsyncSession per test.
    """
    # Import models to ensure they are registered in SQLModel.metadata
    import aila.modules.sbd_nfr.db_models  # noqa: F401
    import aila.storage.db_models  # noqa: F401

    # Collect sbd_nfr_* tables + seedversionrecord
    target_tables = [
        t for t in SQLModel.metadata.sorted_tables
        if t.name.startswith("sbd_nfr_") or t.name == "seedversionrecord"
    ]

    engine = create_async_engine(_TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        for table in target_tables:
            await conn.run_sync(table.create)

    async_session_factory = sessionmaker(
        engine, class_=SQLModelAsyncSession, expire_on_commit=False
    )
    async with async_session_factory() as session:
        yield session

    async with engine.begin() as conn:
        for table in reversed(target_tables):
            await conn.run_sync(table.drop)
    await engine.dispose()


# ---------------------------------------------------------------------------
# INTEG-01: Seed and schema tree integration test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_seed_and_schema_tree(async_db_session):
    """INTEG-01: seed_data() on a fresh DB loads all 11 sections and 80 questions.

    Asserts:
    - schema_version returned == 2
    - tree.sections has exactly 11 sections
    - total questions across all sections == 80
    - specific question IDs present: SCOPE-01, AUTH-01, AUTH-02
    """
    db = async_db_session
    module = SbdNfrModule()
    await module.seed_data(db)

    tree = await get_schema_tree(version=None)

    # Schema version must be 2 (current seed)
    assert tree.schema_version == 2

    # Must have exactly 11 sections
    assert len(tree.sections) == 11, (
        f"Expected 11 sections, got {len(tree.sections)}"
    )

    # Collect all question IDs
    all_question_ids = [
        q.id
        for section in tree.sections
        for subgroup in section.subgroups
        for q in subgroup.questions
    ]

    # Must have exactly 80 questions
    assert len(all_question_ids) == 80, (
        f"Expected 80 questions, got {len(all_question_ids)}"
    )

    # Specific question IDs must be present
    for expected_id in ("SCOPE-01", "AUTH-01", "AUTH-02"):
        assert expected_id in all_question_ids, (
            f"Question {expected_id!r} missing from schema tree"
        )


# ---------------------------------------------------------------------------
# INTEG-02: LLM resolution E2E test (real API call)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.skipif(
    not os.environ.get("OPENAI_API_KEY"),
    reason="OPENAI_API_KEY not set — skipping live LLM resolution test",
)
@pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="DATABASE_URL not set — run_resolution() requires real DB",
)
async def test_synthetic_resolution_e2e():
    """INTEG-02: A high-scope session submitted to real LLM resolution produces
    25 results where every triggered component has non-empty reasoning citing
    at least one question ID.

    Requires:
    - OPENAI_API_KEY set (real LLM API call)
    - DATABASE_URL set (run_resolution opens its own async_session_scope)

    Uses the real configured database — test data is inserted and cleaned up
    in a finally block.
    """
    from aila.storage.database import async_session_scope  # noqa: PLC0415
    from sqlmodel import select  # noqa: PLC0415

    session_id = str(uuid.uuid4())

    # Use real DB for setup (resolution service opens its own session scope)
    async with async_session_scope() as db:
        # Ensure schema is seeded
        module = SbdNfrModule()
        await module.seed_data(db)

        # Load 25 subtask keys
        subtasks_result = await db.execute(
            select(SbdNfrSubtaskComponentRecord).order_by(
                SbdNfrSubtaskComponentRecord.display_order
            )
        )
        subtasks = list(subtasks_result.scalars().all())
        assert len(subtasks) == 25, f"Expected 25 subtasks after seed, got {len(subtasks)}"

        # Create a high-scope session in "resolving" status
        session_record = SbdNfrSessionRecord(
            id=session_id,
            schema_version_at_start=2,
            owner_id="test-owner",
            status="resolving",
            project_name="Integration Test — High Scope",
            requestor_name="Tester",
            requestor_email="test@example.com",
        )
        db.add(session_record)
        await db.flush()

        # Insert answers for a high-scope application (API + web + supply chain)
        answers = [
            ("SCOPE-04", "api_provider"),        # triggers api_security section
            ("SCOPE-05", "external_users"),       # triggers web_mobile section
            ("SCOPE-06", "managed_services"),     # triggers supply_chain section
            ("AUTH-01", "Yes"),                   # identity: MFA enforced
            ("AUTH-04", "Yes"),                   # centralized identity provider
            ("SCOPE-01", "new_service"),          # new service
            ("SCOPE-02", "internet_facing"),      # internet-facing deployment
            ("SCOPE-03", "sensitive_data"),       # sensitive data handled
        ]
        for qid, value in answers:
            db.add(
                SbdNfrAnswerRecord(
                    session_id=session_id,
                    question_id=qid,
                    answer_value=value,
                    answered_by_name="Tester",
                    answered_by_email="test@example.com",
                    schema_version=2,
                )
            )
        await db.commit()

    try:
        # Call real LLM resolution — opens its own async_session_scope internally
        await run_resolution(session_id)

        # Verify results via real DB
        async with async_session_scope() as db:
            # Reload session to check status
            from sqlmodel import select as _select  # noqa: PLC0415
            session_result = await db.execute(
                _select(SbdNfrSessionRecord).where(
                    SbdNfrSessionRecord.id == session_id
                )
            )
            session = session_result.scalars().first()
            assert session is not None, "Session not found after resolution"
            assert session.status == "resolved", (
                f"Expected 'resolved', got {session.status!r}. "
                f"error: {session.resolution_error}"
            )

            # Load results
            results = await get_resolution_results(db, session_id)
            assert len(results) == 25, (
                f"Expected 25 resolution results, got {len(results)}"
            )

            triggered = [r for r in results if r.classification == "triggered"]
            assert len(triggered) > 0, (
                "At least one subtask must be triggered in a high-scope session"
            )

            # INTEG-02 core assertion: every triggered subtask has non-empty
            # reasoning citing at least one question ID
            for r in triggered:
                assert r.reasoning, (
                    f"subtask {r.subtask_key!r} has empty reasoning"
                )
                cited = json.loads(r.cited_question_ids_json or "[]")
                assert len(cited) >= 1, (
                    f"subtask {r.subtask_key!r} has no cited question IDs. "
                    f"reasoning: {r.reasoning!r}"
                )

    finally:
        # Clean up test data from real DB
        async with async_session_scope() as db:
            from sqlalchemy import delete  # noqa: PLC0415

            await db.execute(
                delete(SbdNfrResolutionResultRecord).where(
                    SbdNfrResolutionResultRecord.session_id == session_id
                )
            )
            await db.execute(
                delete(SbdNfrAnswerRecord).where(
                    SbdNfrAnswerRecord.session_id == session_id
                )
            )
            await db.execute(
                delete(SbdNfrSessionRecord).where(
                    SbdNfrSessionRecord.id == session_id
                )
            )
            await db.commit()


# ---------------------------------------------------------------------------
# INTEG-03: Schema version isolation test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_schema_version_isolation(async_db_session):
    """INTEG-03: v1 questions do not appear in v2 tree and vice versa.

    Setup:
    1. Insert minimal v1 schema manually (1 section, 1 subgroup, 2 questions)
    2. Run seed_data() to insert v2 schema (80 questions, schema_version=2)
    3. Query get_schema_tree(db, version=1) — must return only v1 questions
    4. Query get_schema_tree(db, version=2) — must return 80 v2 questions

    Asserts cross-version isolation: no v2 question IDs appear in the v1 tree
    and no v1 question IDs appear in the v2 tree.
    """
    db = async_db_session

    # --- Insert v1 schema records manually ---
    v1_schema = SbdNfrSchemaVersionRecord(
        id=str(uuid.uuid4()),
        version=1,
        change_summary="v1 test schema",
        changed_by="test",
    )
    db.add(v1_schema)
    await db.flush()

    v1_section = SbdNfrSectionRecord(
        id=str(uuid.uuid4()),
        schema_version=1,
        section_key="scope_v1",
        label="Scope v1",
        display_order=1,
        is_active=True,
    )
    db.add(v1_section)
    await db.flush()

    v1_subgroup = SbdNfrSubgroupRecord(
        id=str(uuid.uuid4()),
        schema_version=1,
        section_id=v1_section.id,
        subgroup_key="scope_v1_main",
        label="Scope v1 Main",
        display_order=1,
    )
    db.add(v1_subgroup)
    await db.flush()

    db.add(
        SbdNfrQuestionRecord(
            id="V1-SCOPE-01",
            schema_version=1,
            subgroup_id=v1_subgroup.id,
            question_type="scope",
            depth_level="scope",
            answer_type="single_choice",
            label="V1 Scope question 1",
            display_order=1,
        )
    )
    db.add(
        SbdNfrQuestionRecord(
            id="V1-SCOPE-02",
            schema_version=1,
            subgroup_id=v1_subgroup.id,
            question_type="scope",
            depth_level="scope",
            answer_type="single_choice",
            label="V1 Scope question 2",
            display_order=2,
        )
    )
    await db.flush()

    # --- Seed v2 schema (80 questions, schema_version=2) ---
    module = SbdNfrModule()
    await module.seed_data(db)

    # --- Query v1 tree ---
    v1_tree = await get_schema_tree(version=1)

    v1_question_ids = {
        q.id
        for s in v1_tree.sections
        for sg in s.subgroups
        for q in sg.questions
    }

    # V1 questions must be present
    assert "V1-SCOPE-01" in v1_question_ids, (
        "V1-SCOPE-01 missing from v1 schema tree"
    )
    assert "V1-SCOPE-02" in v1_question_ids, (
        "V1-SCOPE-02 missing from v1 schema tree"
    )

    # V2-only question IDs must NOT appear in the v1 tree
    v2_only_ids = {"AUTH-01", "SCOPE-01", "AUTH-02"}
    for v2_id in v2_only_ids:
        assert v2_id not in v1_question_ids, (
            f"v2 question {v2_id!r} appeared in v1 schema tree — isolation broken"
        )

    # --- Query v2 tree ---
    v2_tree = await get_schema_tree(version=2)

    v2_question_ids = {
        q.id
        for s in v2_tree.sections
        for sg in s.subgroups
        for q in sg.questions
    }

    # V2 tree must have the full 80 questions
    assert "AUTH-01" in v2_question_ids, (
        "AUTH-01 missing from v2 schema tree"
    )
    assert "SCOPE-01" in v2_question_ids, (
        "SCOPE-01 missing from v2 schema tree"
    )
    assert len(v2_question_ids) == 80, (
        f"Expected 80 v2 questions, got {len(v2_question_ids)}"
    )

    # V1 questions must NOT appear in the v2 tree
    for v1_id in ("V1-SCOPE-01", "V1-SCOPE-02"):
        assert v1_id not in v2_question_ids, (
            f"v1 question {v1_id!r} appeared in v2 schema tree — isolation broken"
        )
