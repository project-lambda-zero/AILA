"""VR + malware module system_summary / report_count / health_checks (#70).

These are the three ModuleProtocol hooks the platform calls to aggregate
per-module dashboard data (:mod:`aila.api.routers.dashboard`), per-system
dashboard data (:mod:`aila.api.routers.systems`), and GET /health MCP
reachability (:mod:`aila.api.routers.health`).

Pre-#70 both modules returned empty dicts / no probes, so the platform
totals carried nothing for vr/malware. This test proves each method now
returns the expected shape and issues cheap aggregate queries. The DB
session is stubbed offline (mirrors
``tests/modules/vulnerability/test_system_summary_keys.py``) and MCP
health probes are only asserted callable -- invoking them would hit real
MCP servers.
"""
from __future__ import annotations

import pytest

from aila.modules.malware.module import MalwareModule
from aila.modules.vr import module as vr_module
from aila.modules.vr.module import VRModule


class _Result:
    """Minimal SQLModel Result substitute serving .all() OR .one() per query."""

    def __init__(self, value: object) -> None:
        self._value = value

    def all(self) -> object:
        return self._value

    def one(self) -> object:
        return self._value


class _StubSession:
    """FIFO queue of query results returned by successive await session.exec(...)."""

    def __init__(self, results: list[_Result]) -> None:
        self._results = list(results)

    async def exec(self, _stmt: object) -> _Result:
        return self._results.pop(0)


# ---------------------------------------------------------------------------
# system_summary(system_id, session): join investigations via project.analysis_system_id
# ---------------------------------------------------------------------------


async def test_vr_system_summary_rolls_up_by_status() -> None:
    session = _StubSession([
        _Result(3),  # project count scalar
        _Result([("running", 2), ("paused", 1), ("completed", 4), ("failed", 1)]),
    ])
    result = await VRModule().system_summary(system_id=42, session=session)
    assert result == {
        "vr_projects": 3,
        "vr_investigations": 8,
        "vr_active": 3,
        "vr_completed": 4,
    }


async def test_vr_system_summary_empty_when_no_project_on_system() -> None:
    session = _StubSession([_Result(0)])
    result = await VRModule().system_summary(system_id=99, session=session)
    assert result == {}


async def test_vr_system_summary_none_session_returns_empty() -> None:
    result = await VRModule().system_summary(system_id=1, session=None)
    assert result == {}


async def test_malware_system_summary_rolls_up_by_status() -> None:
    session = _StubSession([
        _Result(2),
        _Result([("running", 1), ("completed", 3), ("paused", 1)]),
    ])
    result = await MalwareModule().system_summary(system_id=17, session=session)
    assert result == {
        "malware_projects": 2,
        "malware_investigations": 5,
        "malware_active": 2,
        "malware_completed": 3,
    }


async def test_malware_system_summary_empty_when_no_project_on_system() -> None:
    session = _StubSession([_Result(0)])
    result = await MalwareModule().system_summary(system_id=99, session=session)
    assert result == {}


async def test_malware_system_summary_none_session_returns_empty() -> None:
    result = await MalwareModule().system_summary(system_id=1, session=None)
    assert result == {}


# ---------------------------------------------------------------------------
# report_count(run_id, session, *, team_id=None): module-wide investigation counts
# ---------------------------------------------------------------------------


async def test_vr_report_count_returns_investigation_breakdown() -> None:
    session = _StubSession([
        _Result([
            ("running", 5),
            ("completed", 10),
            ("failed", 2),
            ("stalled", 1),
            ("paused", 3),
        ]),
        _Result(7),  # recent_outcomes scalar
    ])
    result = await VRModule().report_count(run_id="", session=session)
    assert result["total_investigations"] == 21
    assert result["running"] == 5
    assert result["paused"] == 3
    assert result["completed"] == 10
    assert result["failed"] == 2
    assert result["stalled"] == 1
    assert result["recent_outcomes"] == 7
    # Absent finding-shape keys let the dashboard's .get("total_findings", 0)
    # correctly contribute zero -- vr/malware do not own findings.
    assert "total_findings" not in result
    assert "critical" not in result


async def test_vr_report_count_none_session_returns_empty() -> None:
    result = await VRModule().report_count(run_id="", session=None)
    assert result == {}


async def test_vr_report_count_empty_db_returns_empty() -> None:
    session = _StubSession([_Result([])])
    result = await VRModule().report_count(run_id="", session=session)
    assert result == {}


async def test_vr_report_count_accepts_team_id_kwarg() -> None:
    session = _StubSession([
        _Result([("running", 1)]),
        _Result(0),
    ])
    result = await VRModule().report_count(
        run_id="", session=session, team_id="team-abc",
    )
    assert result["total_investigations"] == 1
    assert result["running"] == 1


async def test_malware_report_count_returns_investigation_breakdown() -> None:
    session = _StubSession([
        _Result([("running", 2), ("completed", 8), ("abandoned", 1)]),
        _Result(4),
    ])
    result = await MalwareModule().report_count(run_id="", session=session)
    assert result["total_investigations"] == 11
    assert result["running"] == 2
    assert result["completed"] == 8
    assert result["abandoned"] == 1
    assert result["recent_outcomes"] == 4
    assert "total_findings" not in result


async def test_malware_report_count_none_session_returns_empty() -> None:
    result = await MalwareModule().report_count(run_id="", session=None)
    assert result == {}


async def test_malware_report_count_empty_db_returns_empty() -> None:
    session = _StubSession([_Result([])])
    result = await MalwareModule().report_count(run_id="", session=session)
    assert result == {}


async def test_malware_report_count_accepts_team_id_kwarg() -> None:
    session = _StubSession([
        _Result([("completed", 4)]),
        _Result(2),
    ])
    result = await MalwareModule().report_count(
        run_id="", session=session, team_id="team-xyz",
    )
    assert result["total_investigations"] == 4
    assert result["completed"] == 4


# ---------------------------------------------------------------------------
# health_checks(): MCP reachability probe factories
# ---------------------------------------------------------------------------


def test_vr_health_checks_covers_all_mcp_dependencies() -> None:
    """VR depends on ida_headless, audit_mcp, and android_mcp."""
    checks = VRModule().health_checks()
    assert set(checks.keys()) == {
        "ida_headless_reachability",
        "audit_mcp_reachability",
        "android_mcp_reachability",
    }
    for probe in checks.values():
        assert callable(probe)


def test_malware_health_checks_covers_all_mcp_dependencies() -> None:
    """Malware depends on ida_headless_exp and audit_mcp."""
    checks = MalwareModule().health_checks()
    assert set(checks.keys()) == {
        "ida_headless_exp_reachability",
        "audit_mcp_reachability",
    }
    for probe in checks.values():
        assert callable(probe)


async def test_health_probe_returns_down_when_mcp_unreachable(monkeypatch) -> None:
    """A wedged / missing MCP server yields a ``status: down`` entry.

    Points make_bridge at a discard port (0) so the transport connect
    fails synchronously in the client. Proves the probe never raises
    and always returns the ModuleHealthResult-shaped dict the platform
    :func:`_run_single_health_check` maps into HealthCheckResult.
    """
    class _StubBridge:
        async def health(self) -> dict:
            # Mirrors McpClient.health()'s unreachable envelope so the
            # probe maps it to a down entry without any real transport.
            return {
                "status": "error",
                "error": "Unreachable: http://127.0.0.1:0/health",
            }

    def _fake_make_bridge(server_id, *, module_id, recorder=None):
        del server_id, module_id, recorder
        return _StubBridge()

    monkeypatch.setattr(
        "aila.platform.mcp.factory.make_bridge",
        _fake_make_bridge,
    )

    probe = vr_module._mcp_health_probe("vr", "ida_headless")
    result = await probe()
    assert isinstance(result, dict)
    assert result["status"] == "down"
    assert "ida_headless" in str(result["detail"])


# ---------------------------------------------------------------------------
# Contract regression: dashboard/systems consumer keys stay stable
# ---------------------------------------------------------------------------


async def test_vr_system_summary_result_serializable_as_module_summary() -> None:
    """The dict returned lands in SystemDetailResponse.module_summaries[<mid>].

    The systems router stores per-module data via
    ``summaries[module_id] = result`` and Pydantic v2 requires
    JSON-serializable primitives.
    """
    session = _StubSession([
        _Result(1),
        _Result([("running", 1)]),
    ])
    result = await VRModule().system_summary(system_id=1, session=session)
    for key, value in result.items():
        assert isinstance(key, str)
        assert isinstance(value, int)


@pytest.mark.parametrize(
    "module_cls,server_ids",
    [
        (VRModule, {"ida_headless", "audit_mcp", "android_mcp"}),
        (MalwareModule, {"ida_headless_exp", "audit_mcp"}),
    ],
)
def test_health_check_names_encode_server_id(module_cls, server_ids: set[str]) -> None:
    checks = module_cls().health_checks()
    for server_id in server_ids:
        assert any(server_id in name for name in checks), (
            f"health_checks() missing probe for {server_id}: keys={sorted(checks)}"
        )
