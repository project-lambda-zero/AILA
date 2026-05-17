"""Integration tests for schema_service.py using real PostgreSQL.

Uses the async_db_session fixture from conftest.py which provides a clean
PostgreSQL session per test (backed by AILA_TEST_DATABASE_URL).

After plan 185-04, all public schema_service functions manage their own
sessions internally via UnitOfWork. Tests seed data directly via
async_db_session, then call service functions without passing db.

No mocks — all tests hit the real service functions against real PostgreSQL.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from aila.modules.sbd_nfr.db_models import (
    SbdNfrQuestionRecord,
    SbdNfrSchemaVersionRecord,
    SbdNfrSectionRecord,
    SbdNfrSubgroupRecord,
)
from aila.modules.sbd_nfr.services.schema_service import (
    _bump_schema_version,
    get_current_schema_version,
    get_schema_tree,
)

# ---------------------------------------------------------------------------
# Seed helpers — accept db for direct insertion, do NOT call service functions
# ---------------------------------------------------------------------------


async def _seed_version(db, version: int = 1) -> str:
    """Insert a schema version record and flush."""
    record = SbdNfrSchemaVersionRecord(
        id=str(uuid4()),
        version=version,
        change_summary="test seed",
        changed_by="test",
    )
    db.add(record)
    await db.flush()
    return record.id


async def _seed_section(
    db,
    schema_version: int,
    section_key: str = "test_section",
    display_order: int = 0,
    depends_on: str | None = None,
    expected_when: str | None = None,
    is_active: bool = True,
) -> SbdNfrSectionRecord:
    """Insert a section record and flush."""
    section = SbdNfrSectionRecord(
        id=str(uuid4()),
        schema_version=schema_version,
        section_key=section_key,
        label=f"Label {section_key}",
        display_order=display_order,
        is_active=is_active,
        depends_on_question_id=depends_on,
        expected_when=expected_when,
    )
    db.add(section)
    await db.flush()
    return section


async def _seed_subgroup(
    db,
    schema_version: int,
    section_id: str,
    subgroup_key: str = "test_sg",
    display_order: int = 0,
) -> SbdNfrSubgroupRecord:
    """Insert a subgroup record and flush."""
    sg = SbdNfrSubgroupRecord(
        id=str(uuid4()),
        schema_version=schema_version,
        section_id=section_id,
        subgroup_key=subgroup_key,
        label=f"Label {subgroup_key}",
        display_order=display_order,
        is_active=True,
    )
    db.add(sg)
    await db.flush()
    return sg


async def _seed_question(
    db,
    schema_version: int,
    subgroup_id: str,
    question_id: str = "Q-01",
    display_order: int = 0,
    is_active: bool = True,
) -> SbdNfrQuestionRecord:
    """Insert a question record and flush."""
    q = SbdNfrQuestionRecord(
        id=question_id,
        schema_version=schema_version,
        subgroup_id=subgroup_id,
        question_type="requirement",
        depth_level="standard",
        answer_type="compliance",
        label=f"Label {question_id}",
        is_required=True,
        is_active=is_active,
        display_order=display_order,
    )
    db.add(q)
    await db.flush()
    return q


# ---------------------------------------------------------------------------
# Test 1: get_schema_tree returns nested structure with sections > 0
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_schema_tree_returns_nested_structure(async_db_session):
    """get_schema_tree returns a SchemaTreeResponse with at least the seeded
    sections and the correct nested structure."""
    db = async_db_session

    await _seed_version(db, version=1)
    sec = await _seed_section(db, schema_version=1, section_key="hygiene")
    sg = await _seed_subgroup(db, schema_version=1, section_id=sec.id, subgroup_key="hyg_main")
    await _seed_question(db, schema_version=1, subgroup_id=sg.id, question_id="HYG-01")
    await db.commit()

    tree = await get_schema_tree(version=1)

    assert tree.schema_version == 1
    assert len(tree.sections) >= 1

    # Find our seeded section
    section_keys = [s.section_key for s in tree.sections]
    assert "hygiene" in section_keys

    hygiene = next(s for s in tree.sections if s.section_key == "hygiene")
    assert len(hygiene.subgroups) == 1
    assert hygiene.subgroups[0].subgroup_key == "hyg_main"
    assert len(hygiene.subgroups[0].questions) == 1
    assert hygiene.subgroups[0].questions[0].id == "HYG-01"


# ---------------------------------------------------------------------------
# Test 2: sections are ordered by display_order
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_schema_tree_sections_ordered_by_display_order(async_db_session):
    """Sections in the returned tree must be ordered ascending by display_order."""
    db = async_db_session

    await _seed_version(db, version=1)
    # Insert in reverse order to prove sorting works
    await _seed_section(db, schema_version=1, section_key="section_c", display_order=2)
    await _seed_section(db, schema_version=1, section_key="section_a", display_order=0)
    await _seed_section(db, schema_version=1, section_key="section_b", display_order=1)
    await db.commit()

    tree = await get_schema_tree(version=1)

    section_keys = [s.section_key for s in tree.sections]
    a_idx = section_keys.index("section_a")
    b_idx = section_keys.index("section_b")
    c_idx = section_keys.index("section_c")
    assert a_idx < b_idx < c_idx, (
        f"Expected a < b < c order, got indices a={a_idx} b={b_idx} c={c_idx}"
    )


# ---------------------------------------------------------------------------
# Test 3: _bump_schema_version correctly increments version number
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bump_schema_version_increments_correctly(async_db_session):
    """_bump_schema_version inserts a new record with version = current + 1."""
    db = async_db_session

    # Start with no version records → get_current_schema_version returns 0
    initial = await get_current_schema_version()
    assert initial == 0, f"Expected 0 before any seeds, got {initial}"

    v1 = await _bump_schema_version(db, change_summary="first bump", changed_by="admin")
    await db.commit()
    assert v1 == 1, f"Expected first bump to be 1, got {v1}"

    v2 = await _bump_schema_version(db, change_summary="second bump", changed_by="admin")
    await db.commit()
    assert v2 == 2, f"Expected second bump to be 2, got {v2}"

    current = await get_current_schema_version()
    assert current == 2, f"Expected current version to be 2 after two bumps, got {current}"


# ---------------------------------------------------------------------------
# Test 4: inactive sections are excluded from tree
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_schema_tree_excludes_inactive_sections(async_db_session):
    """Inactive sections (is_active=False) must not appear in the schema tree."""
    db = async_db_session

    await _seed_version(db, version=1)
    await _seed_section(db, schema_version=1, section_key="active_sec", is_active=True)
    await _seed_section(db, schema_version=1, section_key="inactive_sec", is_active=False)
    await db.commit()

    tree = await get_schema_tree(version=1)

    section_keys = [s.section_key for s in tree.sections]
    assert "active_sec" in section_keys
    assert "inactive_sec" not in section_keys


# ---------------------------------------------------------------------------
# Test 5: get_current_schema_version returns 0 when no records exist
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_current_schema_version_returns_zero_when_empty(test_db):
    """get_current_schema_version must return 0 when no version records exist."""
    version = await get_current_schema_version()
    assert version == 0


# ---------------------------------------------------------------------------
# Phase 155: Subgroup CRUD tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_subgroup(async_db_session):
    """create_subgroup creates a subgroup record and bumps schema version."""
    db = async_db_session
    await _seed_version(db, version=1)
    section = await _seed_section(db, schema_version=1)
    await db.commit()

    from aila.modules.sbd_nfr.contracts.schema import SubgroupCreateRequest
    from aila.modules.sbd_nfr.services.schema_service import create_subgroup

    req = SubgroupCreateRequest(
        section_id=section.id,
        subgroup_key="SG-TEST",
        label="Test Subgroup",
        description=None,
        display_order=0,
    )
    result = await create_subgroup(req, changed_by="admin@test")

    assert result.subgroup_key == "SG-TEST"
    assert result.section_id == section.id
    assert result.is_active is True

    # Schema version should have bumped
    new_ver = await get_current_schema_version()
    assert new_ver == 2


@pytest.mark.asyncio
async def test_update_subgroup(async_db_session):
    """update_subgroup changes label and bumps schema version."""
    db = async_db_session
    await _seed_version(db, version=1)
    section = await _seed_section(db, schema_version=1)
    sg = await _seed_subgroup(db, schema_version=1, section_id=section.id, subgroup_key="SG-UPD")
    await db.commit()

    from aila.modules.sbd_nfr.contracts.schema import SubgroupUpdateRequest
    from aila.modules.sbd_nfr.services.schema_service import update_subgroup

    req = SubgroupUpdateRequest(label="Updated Label")
    result = await update_subgroup(sg.id, req, changed_by="admin@test")

    assert result.label == "Updated Label"
    assert result.subgroup_key == "SG-UPD"

    new_ver = await get_current_schema_version()
    assert new_ver == 2


@pytest.mark.asyncio
async def test_deactivate_subgroup(async_db_session):
    """deactivate_subgroup sets is_active=False on subgroup and cascades to questions."""
    db = async_db_session
    await _seed_version(db, version=1)
    section = await _seed_section(db, schema_version=1)
    sg = await _seed_subgroup(db, schema_version=1, section_id=section.id)
    await _seed_question(db, schema_version=1, subgroup_id=sg.id, question_id="Q-DEACT-01")
    await db.commit()

    from aila.modules.sbd_nfr.services.schema_service import deactivate_subgroup, list_questions

    await deactivate_subgroup(sg.id, changed_by="admin@test")

    # Subgroup should be inactive — populate_existing bypasses the identity map
    # so we get the freshly committed value from the DB.
    from sqlmodel import select as sm_select
    updated_sg = (await db.exec(
        sm_select(SbdNfrSubgroupRecord).where(SbdNfrSubgroupRecord.id == sg.id),
        execution_options={"populate_existing": True},
    )).first()
    assert updated_sg is not None
    assert updated_sg.is_active is False

    # Questions should also be deactivated (cascade)
    questions = await list_questions(subgroup_id=sg.id, schema_version=1, include_inactive=False)
    assert len(questions) == 0

    questions_all = await list_questions(subgroup_id=sg.id, schema_version=1, include_inactive=True)
    assert len(questions_all) == 1
    assert questions_all[0].is_active is False


# ---------------------------------------------------------------------------
# Phase 155: Option CRUD tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_option(async_db_session):
    """create_option creates an option record for a question."""
    db = async_db_session
    await _seed_version(db, version=1)
    section = await _seed_section(db, schema_version=1)
    sg = await _seed_subgroup(db, schema_version=1, section_id=section.id)
    await _seed_question(db, schema_version=1, subgroup_id=sg.id, question_id="Q-OPT-01")
    await db.commit()

    from aila.modules.sbd_nfr.contracts.schema import OptionCreateRequest
    from aila.modules.sbd_nfr.services.schema_service import create_option

    req = OptionCreateRequest(
        question_id="Q-OPT-01",
        value="yes",
        label="Yes",
        description=None,
        display_order=0,
    )
    result = await create_option(req, changed_by="admin@test")

    assert result.value == "yes"
    assert result.label == "Yes"
    assert result.question_id == "Q-OPT-01"


@pytest.mark.asyncio
async def test_update_option(async_db_session):
    """update_option changes option label."""
    db = async_db_session
    await _seed_version(db, version=1)
    section = await _seed_section(db, schema_version=1)
    sg = await _seed_subgroup(db, schema_version=1, section_id=section.id)
    await _seed_question(db, schema_version=1, subgroup_id=sg.id, question_id="Q-UPD-OPT-01")
    await db.commit()

    from aila.modules.sbd_nfr.contracts.schema import OptionCreateRequest, OptionUpdateRequest
    from aila.modules.sbd_nfr.services.schema_service import create_option, update_option

    opt = await create_option(
        OptionCreateRequest(question_id="Q-UPD-OPT-01", value="no", label="No", display_order=1),
        changed_by="admin@test",
    )

    updated = await update_option(opt.id, OptionUpdateRequest(label="No (Updated)"), changed_by="admin@test")
    assert updated.label == "No (Updated)"
    assert updated.value == "no"


@pytest.mark.asyncio
async def test_delete_option(async_db_session):
    """delete_option removes the option; list_options returns empty afterward."""
    db = async_db_session
    await _seed_version(db, version=1)
    section = await _seed_section(db, schema_version=1)
    sg = await _seed_subgroup(db, schema_version=1, section_id=section.id)
    await _seed_question(db, schema_version=1, subgroup_id=sg.id, question_id="Q-DEL-OPT-01")
    await db.commit()

    from aila.modules.sbd_nfr.contracts.schema import OptionCreateRequest
    from aila.modules.sbd_nfr.services.schema_service import create_option, delete_option, list_options

    opt = await create_option(
        OptionCreateRequest(question_id="Q-DEL-OPT-01", value="partial", label="Partial", display_order=0),
        changed_by="admin@test",
    )

    await delete_option(opt.id, changed_by="admin@test")

    remaining = await list_options(question_id="Q-DEL-OPT-01")
    assert len(remaining) == 0


# ---------------------------------------------------------------------------
# Phase 155: Subtask mapping tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_subtask_mapping(async_db_session):
    """create_subtask_mapping creates a mapping between a question and subtask key."""
    db = async_db_session
    await _seed_version(db, version=1)
    section = await _seed_section(db, schema_version=1)
    sg = await _seed_subgroup(db, schema_version=1, section_id=section.id)
    await _seed_question(db, schema_version=1, subgroup_id=sg.id, question_id="Q-MAP-01")
    await db.commit()

    from aila.modules.sbd_nfr.contracts.schema import MappingCreateRequest
    from aila.modules.sbd_nfr.services.schema_service import create_subtask_mapping

    req = MappingCreateRequest(question_id="Q-MAP-01", subtask_key="network_security")
    result = await create_subtask_mapping(req, changed_by="admin@test")

    assert result.question_id == "Q-MAP-01"
    assert result.subtask_key == "network_security"
    assert result.id is not None


@pytest.mark.asyncio
async def test_create_subtask_mapping_duplicate(async_db_session):
    """Creating a duplicate mapping raises ValueError with 'already exists' in message."""
    db = async_db_session
    await _seed_version(db, version=1)
    section = await _seed_section(db, schema_version=1)
    sg = await _seed_subgroup(db, schema_version=1, section_id=section.id)
    await _seed_question(db, schema_version=1, subgroup_id=sg.id, question_id="Q-DUP-MAP-01")
    await db.commit()

    from aila.modules.sbd_nfr.contracts.schema import MappingCreateRequest
    from aila.modules.sbd_nfr.services.schema_service import create_subtask_mapping

    req = MappingCreateRequest(question_id="Q-DUP-MAP-01", subtask_key="encryption")
    await create_subtask_mapping(req, changed_by="admin@test")

    with pytest.raises(ValueError) as exc_info:
        await create_subtask_mapping(req, changed_by="admin@test")

    assert "already exists" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_delete_subtask_mapping(async_db_session):
    """delete_subtask_mapping removes the mapping; list_subtask_mappings returns empty."""
    db = async_db_session
    await _seed_version(db, version=1)
    section = await _seed_section(db, schema_version=1)
    sg = await _seed_subgroup(db, schema_version=1, section_id=section.id)
    await _seed_question(db, schema_version=1, subgroup_id=sg.id, question_id="Q-DEL-MAP-01")
    await db.commit()

    from aila.modules.sbd_nfr.contracts.schema import MappingCreateRequest
    from aila.modules.sbd_nfr.services.schema_service import (
        create_subtask_mapping,
        delete_subtask_mapping,
        list_subtask_mappings,
    )

    req = MappingCreateRequest(question_id="Q-DEL-MAP-01", subtask_key="access_control")
    mapping = await create_subtask_mapping(req, changed_by="admin@test")

    await delete_subtask_mapping(mapping.id, changed_by="admin@test")

    remaining = await list_subtask_mappings(question_id="Q-DEL-MAP-01")
    assert len(remaining) == 0


# ---------------------------------------------------------------------------
# Phase 155: Version publish tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_publish_schema_version(test_db):
    """publish_schema_version increments version counter and returns version > 0."""
    from aila.modules.sbd_nfr.services.schema_service import publish_schema_version

    result = await publish_schema_version(change_summary="First publish", changed_by="admin@test")
    assert result.version > 0
    assert result.change_summary == "First publish"
    assert result.changed_by == "admin@test"

    result2 = await publish_schema_version(change_summary="Second publish", changed_by="admin@test")
    assert result2.version == result.version + 1


# ---------------------------------------------------------------------------
# Phase 155: Session pinning test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_session_pinned_after_publish(async_db_session):
    """schema_version_at_start on a session is unaffected by publishing a new version."""
    db = async_db_session

    from aila.modules.sbd_nfr.db_models import SbdNfrSessionRecord
    from aila.modules.sbd_nfr.services.schema_service import publish_schema_version

    # Seed a version record so schema version starts at 1
    await _seed_version(db, version=1)
    await db.commit()

    # Create a session pinned at schema_version=1
    session_rec = SbdNfrSessionRecord(
        id=str(uuid4()),
        schema_version_at_start=1,
        owner_id="test-user",
        project_name="Pinning Test",
        requestor_name="Test",
        requestor_email="test@test.com",
        status="draft",
    )
    db.add(session_rec)
    await db.commit()

    # Publish a new schema version (v2)
    published = await publish_schema_version(change_summary="Version bump", changed_by="admin@test")
    assert published.version == 2

    # Reload session and verify it's still pinned at v1
    from sqlmodel import select as sm_select
    reloaded = (await db.exec(
        sm_select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_rec.id)
    )).first()
    assert reloaded is not None
    assert reloaded.schema_version_at_start == 1


# ---------------------------------------------------------------------------
# Phase 155: List endpoint tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_sections(async_db_session):
    """list_sections returns all active sections ordered by display_order."""
    db = async_db_session
    await _seed_version(db, version=1)
    await _seed_section(db, schema_version=1, section_key="sec_b", display_order=1)
    await _seed_section(db, schema_version=1, section_key="sec_a", display_order=0)
    await db.commit()

    from aila.modules.sbd_nfr.services.schema_service import list_sections

    sections = await list_sections(schema_version=1)
    assert len(sections) == 2
    assert sections[0].section_key == "sec_a"
    assert sections[1].section_key == "sec_b"


@pytest.mark.asyncio
async def test_list_questions_by_subgroup(async_db_session):
    """list_questions with subgroup_id filter returns only questions in that subgroup."""
    db = async_db_session
    await _seed_version(db, version=1)
    section = await _seed_section(db, schema_version=1)
    sg1 = await _seed_subgroup(db, schema_version=1, section_id=section.id, subgroup_key="SG-A")
    sg2 = await _seed_subgroup(db, schema_version=1, section_id=section.id, subgroup_key="SG-B")
    await _seed_question(db, schema_version=1, subgroup_id=sg1.id, question_id="Q-SG-A-01")
    await _seed_question(db, schema_version=1, subgroup_id=sg2.id, question_id="Q-SG-B-01")
    await db.commit()

    from aila.modules.sbd_nfr.services.schema_service import list_questions

    sg1_questions = await list_questions(subgroup_id=sg1.id, schema_version=1)
    assert len(sg1_questions) == 1
    assert sg1_questions[0].id == "Q-SG-A-01"


@pytest.mark.asyncio
async def test_create_question_generates_editor_fields(async_db_session):
    """create_question accepts a missing question_id and preserves editor fields."""
    db = async_db_session
    await _seed_version(db, version=1)
    section = await _seed_section(db, schema_version=1, section_key="scope")
    subgroup = await _seed_subgroup(db, schema_version=1, section_id=section.id, subgroup_key="scope_core")
    await db.commit()

    from aila.modules.sbd_nfr.contracts.schema import QuestionCreateRequest
    from aila.modules.sbd_nfr.services.schema_service import create_question

    created = await create_question(
        QuestionCreateRequest(
            subgroup_id=subgroup.id,
            question_id=None,
            question_type="scope",
            depth_level="primary",
            answer_type="single_choice",
            label="What is the system type?",
            depends_on_question_id="SCOPE-00",
            expected_when="yes",
            condition_expr_json='{"op":"and","conditions":[]}',
        ),
        changed_by="admin@test",
    )

    assert created.id.startswith("SCOPE_CORE-")
    assert created.answer_type == "single_choice"
    assert created.condition_expr_json == '{"op":"and","conditions":[]}'


@pytest.mark.asyncio
async def test_list_questions_exposes_editor_metadata(async_db_session):
    """list_questions returns the fields needed by the schema editor and logic visualizer."""
    db = async_db_session
    await _seed_version(db, version=1)
    section = await _seed_section(db, schema_version=1, section_key="scope")
    subgroup = await _seed_subgroup(db, schema_version=1, section_id=section.id, subgroup_key="scope_core")
    question = await _seed_question(db, schema_version=1, subgroup_id=subgroup.id, question_id="SCOPE-01")
    question.instruction = "Choose one"
    question.guideline = "Use the closest match"
    question.help_text = "Shown in the editor"
    question.depends_on_question_id = "SCOPE-00"
    question.expected_when = "yes"
    question.condition_expr_json = '{"op":"or","conditions":[]}'
    question.max_length = 42
    db.add(question)
    await db.commit()

    from aila.modules.sbd_nfr.services.schema_service import list_questions

    questions = await list_questions(subgroup_id=subgroup.id, schema_version=1)

    assert len(questions) == 1
    assert questions[0].instruction == "Choose one"
    assert questions[0].guideline == "Use the closest match"
    assert questions[0].help_text == "Shown in the editor"
    assert questions[0].depends_on_question_id == "SCOPE-00"
    assert questions[0].expected_when == "yes"
    assert questions[0].condition_expr_json == '{"op":"or","conditions":[]}'
    assert questions[0].max_length == 42

# ---------------------------------------------------------------------------
# Phase 155: Auth boundary tests (HTTP-level via FastAPI dependency override)
# ---------------------------------------------------------------------------


def test_403_non_admin_mutation():
    """Non-admin caller gets 403 on POST /sbd_nfr/schema/subgroups (T-155-05)."""
    import time

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from aila.modules.sbd_nfr.api_router import create_sbd_nfr_router
    from aila.platform.contracts.auth import require_auth

    fake_reader = type("FakeAuth", (), {"user_id": "reader-001", "role": "reader", "auth_type": "api_key"})()

    app = FastAPI()
    app.state.start_time = time.monotonic()

    # Override require_auth to return the fake reader
    app.dependency_overrides[require_auth] = lambda: fake_reader

    router = create_sbd_nfr_router()
    app.include_router(router, prefix="/sbd_nfr")

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.post(
        "/sbd_nfr/schema/subgroups",
        json={"section_id": "sec-1", "subgroup_key": "SG-X", "label": "Test", "display_order": 0},
        headers={"Authorization": "Bearer fake-token"},
    )
    assert resp.status_code == 403


def test_200_admin_read_sections():
    """Authenticated caller gets 200 on GET /sbd_nfr/schema/sections (list endpoint).

    Patches schema_service.list_sections so no real DB is needed.
    Validates that the route handler returns 200 and an empty list for any
    authenticated user.
    """
    import time
    from unittest.mock import AsyncMock, patch

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from aila.modules.sbd_nfr.api_router import create_sbd_nfr_router
    from aila.platform.contracts.auth import require_auth

    fake_auth = type("FakeAuth", (), {"user_id": "user-001", "role": "reader", "auth_type": "api_key"})()

    app = FastAPI()
    app.state.start_time = time.monotonic()
    app.dependency_overrides[require_auth] = lambda: fake_auth

    router = create_sbd_nfr_router()
    app.include_router(router, prefix="/sbd_nfr")

    client = TestClient(app, raise_server_exceptions=True)

    # Patch only schema_service.list_sections — no DB layer mocked
    with patch("aila.modules.sbd_nfr.api_router.schema_service") as mock_svc:
        mock_svc.list_sections = AsyncMock(return_value=[])

        resp = client.get(
            "/sbd_nfr/schema/sections",
            headers={"Authorization": "Bearer fake-token"},
        )

    assert resp.status_code == 200
    assert resp.json() == []
