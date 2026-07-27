"""#48 -- ReportRepository partitions its "cached report" surface by team.

The reporting cache is a scan-time short-circuit: dispatchers ask
``has_target_reports`` before starting a full analysis and, on hit, feed the
cached rows into the current run instead of paying for a fresh scan. Before
this fix ``latest_report`` / ``has_target_reports`` walked every completed
``WorkflowRunRecord`` in reverse chronological order and returned the newest
row regardless of ``team_id``, so a team-B call could resurrect team-A's
stored report. These tests prove that a ``team_id`` filter parameter now
partitions the cache; ``team_id=None`` still exposes the god-tier admin
bypass (TEAM-06).
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from aila.platform.contracts.reporting import LatestReportResult
from aila.platform.exceptions import NotFoundError
from aila.storage.database import async_session_scope, session_scope
from aila.storage.db_models import ReportArtifactRecord, WorkflowRunRecord
from aila.storage.report_repository import ReportRepository
from aila.storage.report_store import ReportArtifactBundle, ReportArtifactStore


def _run(
    *,
    run_id: str,
    team_id: str | None,
    completed_at: datetime,
    status: str = "completed",
) -> WorkflowRunRecord:
    return WorkflowRunRecord(
        id=run_id,
        query_text="scan fleet",
        action_id="",
        status=status,
        route_json="{}",
        summary_json="{}",
        completed_at=completed_at,
        team_id=team_id,
    )


def _artifact(
    *,
    run_id: str,
    team_id: str | None,
    scope: str = "target",
) -> ReportArtifactRecord:
    return ReportArtifactRecord(
        run_id=run_id,
        scope=scope,
        system_name="host-1",
        host="host-1",
        artifact_type="csv",
        path=f"/reports/{run_id}.csv",
        content=f"/reports/{run_id}.csv",
        team_id=team_id,
    )


def _seed(*records: object) -> None:
    with session_scope() as s:
        for record in records:
            s.add(record)
        s.commit()


def _bundle(*, report_path: str = "/reports/x.csv") -> ReportArtifactBundle:
    return ReportArtifactBundle(
        storage="database",
        report_path=report_path,
        report_content="col1,col2\na,b",
        summary_document={"total_findings": 1},
        rows_document=None,
        report_artifact_id=1,
        summary_artifact_id=2,
        rows_artifact_id=3,
        summary_path="/reports/x_summary.json",
    )


def _store(bundle_by_run: dict[str, ReportArtifactBundle | None]) -> MagicMock:
    """Return a MagicMock ReportArtifactStore whose per-run bundle is picked
    from ``bundle_by_run`` keyed on the ``run.id`` requested by the repo.
    ``list_run_records`` returns a single target-scoped record so the
    ``has_target_reports`` module-scoped branch reports True.
    """
    store = MagicMock(spec=ReportArtifactStore)
    store.target_report_references.return_value = []

    async def _list_run_records(_session, run_id):
        return [_artifact(run_id=run_id, team_id=None, scope="target")]

    async def _load_run_bundle(_session, run_id, target=None, records=None):
        return bundle_by_run.get(run_id)

    store.list_run_records.side_effect = _list_run_records
    store.load_run_bundle.side_effect = _load_run_bundle
    return store


# ---------------------------------------------------------------------------
# latest_report -- team-partitioned cache lookup
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_latest_report_returns_own_team_run_over_newer_other_team(test_db):
    """team-alpha's older run MUST beat team-beta's newer run when scoped to alpha."""
    alpha_completed = datetime(2026, 1, 1, tzinfo=UTC)
    beta_completed = alpha_completed + timedelta(days=1)  # strictly newer
    _seed(
        _run(run_id="run-alpha", team_id="team-alpha", completed_at=alpha_completed),
        _run(run_id="run-beta", team_id="team-beta", completed_at=beta_completed),
    )
    repo = ReportRepository(
        artifact_store=_store({
            "run-alpha": _bundle(report_path="/reports/alpha.csv"),
            "run-beta": _bundle(report_path="/reports/beta.csv"),
        })
    )

    async with async_session_scope() as session:
        alpha_result = await repo.latest_report(session, team_id="team-alpha")
        beta_result = await repo.latest_report(session, team_id="team-beta")

    assert isinstance(alpha_result, LatestReportResult)
    assert alpha_result.run_id == "run-alpha"
    assert alpha_result.report_path == "/reports/alpha.csv"

    assert isinstance(beta_result, LatestReportResult)
    assert beta_result.run_id == "run-beta"
    assert beta_result.report_path == "/reports/beta.csv"


@pytest.mark.asyncio
async def test_latest_report_notfound_for_team_with_no_run(test_db):
    """A team that never ran a scan MUST get NotFoundError, not another team's cached report."""
    _seed(
        _run(
            run_id="run-alpha",
            team_id="team-alpha",
            completed_at=datetime(2026, 1, 1, tzinfo=UTC),
        ),
    )
    repo = ReportRepository(
        artifact_store=_store({"run-alpha": _bundle()})
    )

    async with async_session_scope() as session:
        with pytest.raises(NotFoundError, match="No completed reports"):
            await repo.latest_report(session, team_id="team-charlie")


@pytest.mark.asyncio
async def test_latest_report_admin_bypass_returns_newest_across_teams(test_db):
    """team_id=None (god-tier admin, TEAM-06) still walks every team's runs."""
    older = datetime(2026, 1, 1, tzinfo=UTC)
    newer = older + timedelta(days=2)
    _seed(
        _run(run_id="run-alpha", team_id="team-alpha", completed_at=older),
        _run(run_id="run-beta", team_id="team-beta", completed_at=newer),
    )
    repo = ReportRepository(
        artifact_store=_store({
            "run-alpha": _bundle(report_path="/reports/alpha.csv"),
            "run-beta": _bundle(report_path="/reports/beta.csv"),
        })
    )

    async with async_session_scope() as session:
        result = await repo.latest_report(session)  # team_id defaults to None

    assert result.run_id == "run-beta"  # newest wins for admin


# ---------------------------------------------------------------------------
# has_target_reports -- the boolean "cache hit" probe
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_has_target_reports_module_scope_partitioned_by_team(test_db):
    """A team-alpha stored report MUST NOT report a cache hit for team-charlie.

    Regression for #48: has_target_reports feeds
    planning.has_cached_report() which decides whether to skip a scan; a
    cross-team True there silently substitutes another team's data.
    """
    _seed(
        _run(
            run_id="run-alpha",
            team_id="team-alpha",
            completed_at=datetime(2026, 1, 1, tzinfo=UTC),
            status="completed",
        ),
        _artifact(run_id="run-alpha", team_id="team-alpha", scope="target"),
    )
    # Real artifact store (module-scope branch uses list_run_records off it),
    # so we build one that just reads from the DB.
    repo = ReportRepository(artifact_store=ReportArtifactStore())

    async with async_session_scope() as session:
        alpha_hit = await repo.has_target_reports(
            session, module_id=None, team_id="team-alpha",
        )
        charlie_hit = await repo.has_target_reports(
            session, module_id=None, team_id="team-charlie",
        )
        admin_hit = await repo.has_target_reports(session, module_id=None)

    assert alpha_hit is True
    assert charlie_hit is False  # cross-team probe: cache miss
    assert admin_hit is True  # god-tier admin sees everything


# ---------------------------------------------------------------------------
# materialized_findings -- row-level team filter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_materialized_findings_drops_other_team_rows(test_db):
    """Rows stamped with another ``team_id`` MUST NOT appear in a team-scoped call."""
    alpha_row = {"id": 1, "team_id": "team-alpha", "cve_id": "CVE-2026-1"}
    beta_row = {"id": 2, "team_id": "team-beta", "cve_id": "CVE-2026-2"}
    unstamped_row = {"id": 3, "team_id": None, "cve_id": "CVE-2026-3"}

    async def _fake_query(_session, _target):
        return [alpha_row, beta_row, unstamped_row]

    repo = ReportRepository(materialized_query=_fake_query)

    async with async_session_scope() as session:
        alpha_rows = await repo.materialized_findings(session, team_id="team-alpha")
        beta_rows = await repo.materialized_findings(session, team_id="team-beta")
        admin_rows = await repo.materialized_findings(session)

    assert [r["id"] for r in alpha_rows] == [1]
    assert [r["id"] for r in beta_rows] == [2]
    # Admin bypass still returns every row -- including the NULL team row.
    assert {r["id"] for r in admin_rows} == {1, 2, 3}
