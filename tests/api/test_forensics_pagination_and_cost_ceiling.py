"""#59 findings 59-3.4 (list pagination) and 59-3.6 (freeflow cost ceiling).

Two disjoint acceptance surfaces, both grounded on the source paths named
in ``.run/designs/DESIGN_module_correctness.md``:

* ``list_evidence`` / ``list_findings`` / ``list_investigations`` in
  ``src/aila/modules/forensics/api_router.py`` previously fetched every
  matching row before any Python-side slicing. LIMIT/OFFSET at the SQL
  layer now caps each response to ``page_size`` items.
* ``ForensicsConfigSchema.freeflow_max_cost_usd`` is a new operator knob;
  the enforcement helpers in
  ``src/aila/modules/forensics/workflow/states/freeflow.py`` sum
  ``LLMCostRecord.cost_usd`` per ``run_id == investigation_id`` and the
  monitor loop flips the investigation to ``cancelled`` (which the
  investigator turn-loop already halts on) when the cap is crossed.

Tests here exercise both the endpoint-level page bound AND the pure
ceiling-check helper wired against real ``aila_test`` rows.
"""
from __future__ import annotations

import asyncio
import json
from uuid import uuid4

import pytest
from sqlmodel import select

from aila.api.auth import AuthContext
from aila.modules.forensics.api_router import create_forensics_router
from aila.modules.forensics.api_router import limiter as _forensics_limiter
from aila.modules.forensics.config_schema import ForensicsConfigSchema
from aila.modules.forensics.contracts.status import InvestigationStatus
from aila.modules.forensics.db_models import (
    ArtifactRecord,
    ForensicsProjectRecord,
    InvestigationRunRecord,
    ProjectEvidenceRecord,
)
from aila.modules.forensics.workflow.states.freeflow import (
    _cost_ceiling_monitor,
    _freeflow_actual_cost_usd,
    _freeflow_cost_ceiling_exceeded,
)
from aila.platform.llm.cost_record import LLMCostRecord
from aila.storage.database import async_session_scope
from aila.storage.db_models import ManagedSystemRecord

# --------------------------------------------------------------------------
# Shared fixtures + helpers
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _disable_forensics_limiter():
    """Disable the module-local slowapi limiter for the test.

    Mirrors ``tests/api/test_forensics_delete_project.py``: the forensics
    router carries its own Limiter that the shared api-limiter fixture
    does not reach, so tests calling the endpoint directly need it off.
    """
    prev = _forensics_limiter.enabled
    _forensics_limiter.enabled = False
    yield
    _forensics_limiter.enabled = prev


class _Req:
    """Minimal stand-in for FastAPI ``Request``.

    Every list endpoint does ``del request`` before touching it, so any
    object satisfies the signature.
    """


def _endpoint(path: str, method: str):
    """Look up a route handler by path + method on a fresh router."""
    for route in create_forensics_router().routes:
        methods = getattr(route, "methods", set()) or set()
        if getattr(route, "path", None) == path and method in methods:
            return route.endpoint
    raise AssertionError(f"route {method} {path} not registered")


def _admin() -> AuthContext:
    """Admin identity with ``team_id=None`` -- unfiltered by the team gate."""
    return AuthContext(user_id="admin", role="admin", auth_type="user", team_id=None)


async def _seed_project(suffix: str) -> str:
    """Create a system + project row and return the project id."""
    async with async_session_scope() as session:
        sys_rec = ManagedSystemRecord(
            name=f"sys-{suffix}", host="10.0.0.1", username="u",
        )
        session.add(sys_rec)
        await session.flush()
        proj = ForensicsProjectRecord(
            name=f"proj-{suffix}",
            system_id=sys_rec.id,
            evidence_directory=f"/tmp/{suffix}",
        )
        session.add(proj)
        await session.flush()
        pid = proj.id
        await session.commit()
    return pid


# --------------------------------------------------------------------------
# 59-3.4 pagination
# --------------------------------------------------------------------------


async def test_list_investigations_returns_bounded_page(test_db) -> None:
    """page_size caps ``data`` at the requested count regardless of row total."""
    suffix = uuid4().hex[:8]
    pid = await _seed_project(suffix)
    async with async_session_scope() as session:
        for i in range(6):
            session.add(InvestigationRunRecord(
                project_id=pid,
                question=f"q-{i}",
            ))
        await session.commit()

    list_investigations = _endpoint("/projects/{project_id}/investigations", "GET")

    # page_size < row count => data length == page_size.
    envelope = await list_investigations(
        request=_Req(),
        project_id=pid,
        auth=_admin(),
        page=1,
        page_size=3,
    )
    assert len(envelope.data) == 3

    # Second page returns the remaining rows.
    envelope_page2 = await list_investigations(
        request=_Req(),
        project_id=pid,
        auth=_admin(),
        page=2,
        page_size=3,
    )
    assert len(envelope_page2.data) == 3
    first_ids = {item.id for item in envelope.data}
    second_ids = {item.id for item in envelope_page2.data}
    assert first_ids.isdisjoint(second_ids), (
        "page 2 must not repeat rows from page 1 -- ORDER BY id ASC tiebreaker "
        "is required for stable LIMIT/OFFSET"
    )

    # Past the last page returns an empty list; envelope shape unchanged.
    envelope_empty = await list_investigations(
        request=_Req(),
        project_id=pid,
        auth=_admin(),
        page=99,
        page_size=3,
    )
    assert envelope_empty.data == []


async def test_list_evidence_returns_bounded_page(test_db) -> None:
    """list_evidence honours ``page_size`` at the SQL layer."""
    suffix = uuid4().hex[:8]
    pid = await _seed_project(suffix)
    async with async_session_scope() as session:
        for i in range(5):
            session.add(ProjectEvidenceRecord(
                project_id=pid,
                file_path=f"/evidence/{i}.raw",
                evidence_type="disk_image",
            ))
        await session.commit()

    list_evidence = _endpoint("/projects/{project_id}/evidence", "GET")
    envelope = await list_evidence(
        request=_Req(),
        project_id=pid,
        auth=_admin(),
        page=1,
        page_size=2,
    )
    assert len(envelope.data) == 2


async def test_list_findings_page_caps_artifact_fetch(test_db) -> None:
    """list_findings bounds the artifact scan at ``page_size`` rows.

    Each seeded artifact carries exactly one suspicious record, so the
    emitted findings count is bounded by the artifact page.
    """
    suffix = uuid4().hex[:8]
    pid = await _seed_project(suffix)
    async with async_session_scope() as session:
        for i in range(4):
            session.add(ArtifactRecord(
                project_id=pid,
                artifact_family="autoruns",
                artifact_type="runkey",
                source_tool="dissect",
                data_json=json.dumps({
                    "records": [
                        {
                            "path": f"/tmp/thing-{i}.exe",
                            "name": f"thing-{i}",
                            "suspicious_reasons": [f"reason-{i}"],
                        }
                    ]
                }),
            ))
        await session.commit()

    list_findings = _endpoint("/projects/{project_id}/findings", "GET")
    envelope = await list_findings(
        request=_Req(),
        project_id=pid,
        auth=_admin(),
        page=1,
        page_size=2,
    )
    # 2 artifacts on this page, each yields exactly 1 finding.
    assert len(envelope.data) == 2


# --------------------------------------------------------------------------
# 59-3.6 freeflow cost ceiling
# --------------------------------------------------------------------------


def test_freeflow_cost_ceiling_exceeded_pure() -> None:
    """The pure check treats cap<=0 as disabled and fires on cap crossing."""
    # Cap disabled: any actual reads as under the ceiling.
    assert _freeflow_cost_ceiling_exceeded(0.0, 0.0) is False
    assert _freeflow_cost_ceiling_exceeded(1000.0, 0.0) is False
    assert _freeflow_cost_ceiling_exceeded(1000.0, -1.0) is False

    # Cap active: strict-less is safe, equal-or-greater fires.
    assert _freeflow_cost_ceiling_exceeded(0.99, 1.0) is False
    assert _freeflow_cost_ceiling_exceeded(1.0, 1.0) is True
    assert _freeflow_cost_ceiling_exceeded(1.5, 1.0) is True


def test_forensics_config_schema_ships_cost_ceiling_field() -> None:
    """The new operator knob is on the schema with a positive default."""
    field = ForensicsConfigSchema.model_fields["freeflow_max_cost_usd"]
    assert field.default > 0.0
    # Field annotation is ``float`` (may show as either the class or its name).
    annotation = field.annotation
    if isinstance(annotation, type):
        assert annotation is float
    else:
        assert "float" in str(annotation)


async def test_freeflow_actual_cost_sums_llm_cost_records(test_db) -> None:
    """The DB-backed sum + pure ceiling check compose to a truthful gate.

    Seeds LLMCostRecord rows with ``run_id == investigation_id`` (the key
    the design pins as the aggregation dimension), verifies the sum
    matches what was seeded, and asserts the ceiling flips exactly when
    the cumulative cost crosses the cap.
    """
    investigation_id = f"inv-{uuid4().hex[:8]}"
    cap_usd = 1.0

    # Empty run: no cost, ceiling not tripped.
    initial = await _freeflow_actual_cost_usd(investigation_id)
    assert initial == pytest.approx(0.0)
    assert _freeflow_cost_ceiling_exceeded(initial, cap_usd) is False

    # Under cap: two cheap calls sum to $0.60.
    async with async_session_scope() as session:
        session.add(LLMCostRecord(
            run_id=investigation_id,
            model_id="test-model",
            task_type="forensics_freeflow",
            cost_usd=0.30,
        ))
        session.add(LLMCostRecord(
            run_id=investigation_id,
            model_id="test-model",
            task_type="forensics_freeflow",
            cost_usd=0.30,
        ))
        await session.commit()

    under = await _freeflow_actual_cost_usd(investigation_id)
    assert under == pytest.approx(0.60)
    assert _freeflow_cost_ceiling_exceeded(under, cap_usd) is False

    # Over cap: one more call pushes cumulative cost past $1.00.
    async with async_session_scope() as session:
        session.add(LLMCostRecord(
            run_id=investigation_id,
            model_id="test-model",
            task_type="forensics_freeflow",
            cost_usd=0.50,
        ))
        await session.commit()

    over = await _freeflow_actual_cost_usd(investigation_id)
    assert over == pytest.approx(1.10)
    assert _freeflow_cost_ceiling_exceeded(over, cap_usd) is True

    # Cross-investigation isolation: a second run stays at zero.
    other_id = f"inv-{uuid4().hex[:8]}"
    other = await _freeflow_actual_cost_usd(other_id)
    assert other == pytest.approx(0.0)


async def test_freeflow_actual_cost_is_zero_for_empty_investigation_id() -> None:
    """Empty investigation_id shortcuts to 0.0 without touching the DB."""
    assert await _freeflow_actual_cost_usd("") == pytest.approx(0.0)


async def test_freeflow_cost_ceiling_triggers_investigation_cancel(test_db) -> None:
    """The monitor loop flips the investigation to ``cancelled`` on breach.

    This exercises the integration path documented in freeflow.py:
    ``_cost_ceiling_monitor`` is expected to see the seeded cost sum,
    invoke ``_flip_investigation_cancelled``, and set the outcome flag
    so the caller can override the final status to ``exhausted``.
    """
    suffix = uuid4().hex[:8]
    pid = await _seed_project(suffix)
    async with async_session_scope() as session:
        inv = InvestigationRunRecord(
            project_id=pid,
            question="q-cost-ceiling",
            status=InvestigationStatus.RUNNING.value,
        )
        session.add(inv)
        await session.flush()
        inv_id = inv.id
        # Seed cost above the cap so the first poll trips the ceiling.
        session.add(LLMCostRecord(
            run_id=inv_id,
            model_id="test-model",
            task_type="forensics_freeflow",
            cost_usd=2.0,
        ))
        await session.commit()

    class _StubEmitter:
        def __init__(self) -> None:
            self.events: list[tuple[str, str, dict]] = []

        async def emit(self, stream: str, message: str, meta: dict | None = None) -> None:
            self.events.append((stream, message, meta or {}))

    emitter = _StubEmitter()
    stop_event = asyncio.Event()
    outcome: dict[str, object] = {"hit": False, "actual_usd": 0.0}

    # cap_usd = 1.0, actual = 2.0 -> ceiling should trip on the first
    # poll and the monitor should exit without waiting a full interval.
    await asyncio.wait_for(
        _cost_ceiling_monitor(
            investigation_id=inv_id,
            cap_usd=1.0,
            emitter=emitter,
            stop_event=stop_event,
            outcome=outcome,
        ),
        timeout=5.0,
    )

    assert outcome["hit"] is True
    assert float(outcome["actual_usd"]) == pytest.approx(2.0)

    # The investigation row is flipped to CANCELLED so the investigator
    # loop halts at its next _is_cancelled check.
    async with async_session_scope() as session:
        row = (await session.exec(
            select(InvestigationRunRecord).where(InvestigationRunRecord.id == inv_id)
        )).first()
    assert row is not None
    assert row.status == InvestigationStatus.CANCELLED.value

    # And the operator sees a cost_ceiling_reached SSE event.
    stages = [meta.get("stage") for _, _, meta in emitter.events]
    assert "cost_ceiling_reached" in stages
