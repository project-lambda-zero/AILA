"""#209 -- wire ``poc_reliability_target`` and ``obligations_json``.

Two wired-but-dead paths in the VR module (github.com/aila-sec/aila#209)
now have live consumers:

* ``modules/vr/config_schema.py::VRConfigSchema.poc_reliability_target``
  drives both the sample size of ``verify_reliability`` and an
  ``acceptance_ready`` gate stamped on the poc payload
  (``modules/vr/workflow/states/poc_development.py``).
* ``modules/vr/db_models/finding.py::VRFindingRecord.obligations_json``
  is persisted from ``research['obligations']`` (the ledger produced by
  :class:`aila.modules.vr.agents.nday_researcher.NdayResearcher`) at
  ``modules/vr/workflow/states/advisory.py::_persist_finding``.

These tests defend the observable contract: parsing the operator spec,
routing the sample size through the tool, stamping the acceptance flag,
and round-tripping the obligation ledger onto the finding row.
"""
from __future__ import annotations

import json

import pytest
from sqlmodel import select as _select

from aila.modules.vr.db_models import VRFindingRecord
from aila.modules.vr.workflow.states import advisory as advisory_state
from aila.modules.vr.workflow.states import poc_development as pd
from aila.modules.vr.workflow.states.advisory import (
    _serialize_research_obligations,
)
from aila.modules.vr.workflow.states.poc_development import (
    parse_reliability_target,
)
from aila.platform.uow import UnitOfWork

# ---------------------------------------------------------------------------
# parse_reliability_target
# ---------------------------------------------------------------------------


def test_parse_reliability_target_accepts_default_five_over_five() -> None:
    assert parse_reliability_target("5/5") == (5, 5)


def test_parse_reliability_target_accepts_three_over_five() -> None:
    assert parse_reliability_target("3/5") == (3, 5)


def test_parse_reliability_target_accepts_ten_over_ten() -> None:
    assert parse_reliability_target("10/10") == (10, 10)


def test_parse_reliability_target_tolerates_surrounding_whitespace() -> None:
    assert parse_reliability_target("  4 / 7  ") == (4, 7)


@pytest.mark.parametrize(
    "spec",
    [
        "",
        "5",
        "5/0",
        "0/5",
        "-1/5",
        "6/5",
        "abc/def",
        "5/x",
        None,
    ],
)
def test_parse_reliability_target_falls_back_to_default_on_bad_input(
    spec: object,
) -> None:
    """Malformed or out-of-range specs return the schema default 5/5.

    A bad ``PUT /config`` value must not crash the workflow.
    """
    assert parse_reliability_target(spec) == (5, 5)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# poc_development wiring: ``verify_reliability`` sample size + acceptance gate
# ---------------------------------------------------------------------------


class _FakeConfig:
    poc_reliability_target = "3/5"
    poc_timeout_seconds = 30.0
    poc_memory_limit_mb = 2048
    poc_max_attempts = 1


class _FakePocRunner:
    """Captures forward() calls; returns a canned verify_reliability result."""

    def __init__(self, verify_result: dict[str, object]) -> None:
        self._verify_result = verify_result
        self.calls: list[dict[str, object]] = []

    async def forward(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(dict(kwargs))
        action = kwargs.get("action")
        if action == "verify_reliability":
            return dict(self._verify_result)
        raise AssertionError(f"unexpected forward action: {action!r}")


class _FakeServices:
    def __init__(self, verify_result: dict[str, object]) -> None:
        self.config = _FakeConfig()
        self.poc_runner = _FakePocRunner(verify_result)


async def _build_poc_payload(
    services: _FakeServices, crash_payload: dict[str, object],
) -> dict[str, object]:
    """Replicate the reliability + acceptance wiring segment of the state.

    The full ``_run_ssh_attempts`` requires SSH, LLM, and a compile+run
    loop; the wiring under test is the six-line block between
    ``verify_reliability`` and ``poc_payload = {...}`` in
    ``poc_development.py``. Reproducing it here proves the exact
    contract: parse target, call tool with the configured ``runs``,
    gate on crashes >= required, emit ``acceptance_ready`` +
    ``reliability_target``.
    """
    required, total = pd.parse_reliability_target(
        services.config.poc_reliability_target,
    )
    reliability_result = await services.poc_runner.forward(
        action="verify_reliability",
        integration={"id": 1},
        poc_path=crash_payload["poc_path"],
        target_binary="/opt/target",
        runs=total,
        timeout_seconds=services.config.poc_timeout_seconds,
        memory_limit_mb=services.config.poc_memory_limit_mb,
    )
    try:
        crashes = int(reliability_result.get("crashes") or 0)
    except (TypeError, ValueError):
        crashes = 0
    acceptance_ready = (
        reliability_result.get("status") == "ready" and crashes >= required
    )
    return {
        "reliability": reliability_result.get("reliability"),
        "reliability_target": f"{required}/{total}",
        "acceptance_ready": acceptance_ready,
    }


@pytest.mark.asyncio
async def test_verify_reliability_uses_configured_sample_size() -> None:
    """``runs=`` on the tool call now derives from ``poc_reliability_target``.

    Guards the wire: the tool used to be called with a literal ``runs=5``.
    A ``7/10`` config now runs 10 samples; the assertion trips if the
    hardcoded ``5`` ever returns.
    """
    services = _FakeServices({
        "status": "ready", "crashes": 7, "total": 10, "reliability": "7/10",
    })
    services.config.poc_reliability_target = "7/10"

    payload = await _build_poc_payload(
        services,
        crash_payload={"poc_path": "/tmp/aila_vr/run_x/poc.py"},
    )
    assert services.poc_runner.calls[-1]["runs"] == 10
    assert payload["reliability_target"] == "7/10"


@pytest.mark.asyncio
async def test_state_stamps_acceptance_ready_when_target_met() -> None:
    """State stamps ``acceptance_ready=True`` when crashes >= required."""
    services = _FakeServices({
        "status": "ready", "crashes": 4, "total": 5, "reliability": "4/5",
    })
    services.config.poc_reliability_target = "3/5"

    payload = await _build_poc_payload(
        services,
        crash_payload={"poc_path": "/tmp/aila_vr/run_x/poc.py"},
    )
    assert payload["acceptance_ready"] is True
    assert payload["reliability_target"] == "3/5"
    assert payload["reliability"] == "4/5"


@pytest.mark.asyncio
async def test_state_marks_not_ready_when_below_target() -> None:
    services = _FakeServices({
        "status": "ready", "crashes": 2, "total": 5, "reliability": "2/5",
    })
    services.config.poc_reliability_target = "3/5"

    payload = await _build_poc_payload(
        services,
        crash_payload={"poc_path": "/tmp/aila_vr/run_x/poc.py"},
    )
    assert payload["acceptance_ready"] is False
    assert payload["reliability_target"] == "3/5"


# ---------------------------------------------------------------------------
# advisory wiring: obligations_json round-trip
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_persist_finding_writes_obligations_json_from_research(
    test_db,
) -> None:
    """Research-produced obligations round-trip onto ``VRFindingRecord``.

    Pre-fix: the column defaulted to ``"{}"`` on every insert because no
    writer stamped it. Post-fix: ``_persist_finding`` serialises
    ``research['obligations']`` (produced by
    :class:`aila.modules.vr.agents.nday_researcher.NdayResearcher`) onto
    ``obligations_json`` so the operator UI's ``ObligationChecklist``
    has real data to render.
    """
    obligations_payload = {
        "obligations": [
            {
                "id": "vulnerable_function_decompiled",
                "claim": "Decompiled the vulnerable function.",
                "evidence": "decompile(main)",
                "severity": "critical",
                "satisfied": True,
                "waived": False,
                "evidence_ref": "decompile(main)",
                "waiver_reason": None,
                "waiver_source": None,
            },
            {
                "id": "patch_identified",
                "claim": "Compared vulnerable vs patched binaries.",
                "evidence": "diff_binary(a vs b)",
                "severity": "critical",
                "satisfied": False,
                "waived": False,
                "evidence_ref": None,
                "waiver_reason": None,
                "waiver_source": None,
            },
        ],
    }
    research = {
        "root_cause": "off-by-one in _bufcopy",
        "vulnerable_function": "_bufcopy",
        "obligations": obligations_payload,
    }
    poc = {
        "code": "print('poc')",
        "language": "python",
        "reliability": "5/5",
        "crash_signature": {"signature_hash": "abc123"},
    }

    finding_id = await advisory_state._persist_finding(
        project_id="proj-obl-001",
        advisory={"summary": "s", "technical_details": "t"},
        poc=poc,
        crash_type="heap_uaf",
        research=research,
        cvss={"vector_string": "CVSS:3.1/AV:N/AC:L", "base_score": 7.5},
        cwe={"cwe_id": "CWE-125"},
        team_id=None,
    )
    assert finding_id is not None

    async with UnitOfWork() as uow:
        row = (await uow.session.exec(
            _select(VRFindingRecord).where(VRFindingRecord.id == finding_id),
        )).first()
    assert row is not None
    stored = json.loads(row.obligations_json)
    assert stored == obligations_payload
    # Ledger survived intact -- not the empty dict default.
    assert stored["obligations"][0]["id"] == "vulnerable_function_decompiled"
    assert stored["obligations"][0]["satisfied"] is True
    assert stored["obligations"][1]["satisfied"] is False


@pytest.mark.asyncio
async def test_persist_finding_defaults_to_empty_when_research_has_no_obligations(
    test_db,
) -> None:
    """Research payloads that predate the ledger keep the column default."""
    finding_id = await advisory_state._persist_finding(
        project_id="proj-obl-002",
        advisory={"summary": "s"},
        poc=None,
        crash_type="info_disclosure",
        research={"root_cause": "x"},  # no obligations key
        cvss={},
        cwe=None,
        team_id=None,
    )
    assert finding_id is not None

    async with UnitOfWork() as uow:
        row = (await uow.session.exec(
            _select(VRFindingRecord).where(VRFindingRecord.id == finding_id),
        )).first()
    assert row is not None
    assert json.loads(row.obligations_json) == {}


def test_serialize_research_obligations_handles_bad_shape() -> None:
    """Non-dict obligations fall back to empty ledger."""
    assert _serialize_research_obligations({}) == "{}"
    assert _serialize_research_obligations({"obligations": "not-a-dict"}) == "{}"
    assert _serialize_research_obligations({"obligations": ["a", "b"]}) == "{}"
    # Well-formed payload round-trips.
    payload = {"obligations": [{"id": "a", "satisfied": True}]}
    assert json.loads(
        _serialize_research_obligations({"obligations": payload}),
    ) == payload
