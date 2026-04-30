"""Phase 176a Task 3: ReportService.fetch_reports + fetch_report_detail tests.

Real PostgreSQL via the test_db fixture — no mocks. Verifies:
- fetch_reports returns (list, int) tuple; total is team-scoped and
  independent of limit/offset.
- Pagination, ordering (created_at DESC), and team-scoped isolation.
- severity_counts has exactly the five locked keys.
- fetch_report_detail happy path.
- fetch_report_detail raises NotFoundError for unknown ids.
- Cross-team lookup returns NotFoundError (no existence leak).
- Schema round-trip: ReportSummary/ReportDetail serialize+deserialize.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from aila.api.schemas.reports import FindingSummary, ReportDetail, ReportSummary
from aila.modules.vulnerability.db_models import LatestFindingRecord
from aila.modules.vulnerability.module import _query_latest_findings, _query_run_findings
from aila.platform.exceptions import NotFoundError
from aila.platform.services.factory import ServiceFactory
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowRunRecord
from aila.storage.report_repository import ReportRepository

ReportRepository.set_default_queries(
    materialized_query=_query_latest_findings,
    run_findings_query=_query_run_findings,
)


def _make_run(
    *,
    run_id: str,
    team_id: str | None,
    created_at: datetime,
    query_text: str = "scan fleet for vulnerabilities",
    status: str = "completed",
    target: str | None = "web01",
) -> WorkflowRunRecord:
    route = f'{{"target": "{target}"}}' if target else "{}"
    return WorkflowRunRecord(
        id=run_id,
        query_text=query_text,
        action_id="vulnerability.analyze",
        module_id="vulnerability",
        status=status,
        route_json=route,
        team_id=team_id,
        created_at=created_at,
        completed_at=created_at + timedelta(minutes=5),
    )


def _make_finding(
    *,
    team_id: str | None,
    host: str,
    cve_id: str,
    criticality: str,
    package: str = "openssl",
) -> LatestFindingRecord:
    now = datetime.now(timezone.utc)
    return LatestFindingRecord(
        system_id=1,
        system_name=host,
        host=host,
        cve_id=cve_id,
        package_name=package,
        criticality=criticality,
        score=9.5 if criticality == "CRITICAL" else 5.0,
        nvd_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        last_scanned_at=now,
        team_id=team_id,
        created_at=now,
    )


@pytest_asyncio.fixture
async def seeded_team_reports(test_db):
    """Seed 25 reports for team-alpha, 5 for team-beta, and findings for each host."""
    base_time = datetime.now(timezone.utc) - timedelta(days=30)

    runs: list[WorkflowRunRecord] = []
    for i in range(25):
        runs.append(
            _make_run(
                run_id=f"run-alpha-{i:03d}",
                team_id="team-alpha",
                created_at=base_time + timedelta(hours=i),
                target=f"host-alpha-{i:03d}",
            )
        )
    for i in range(5):
        runs.append(
            _make_run(
                run_id=f"run-beta-{i:03d}",
                team_id="team-beta",
                created_at=base_time + timedelta(hours=i),
                target=f"host-beta-{i:03d}",
            )
        )

    # One finding per host, varying criticality to exercise severity_counts.
    findings: list[LatestFindingRecord] = []
    severity_cycle = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    for i in range(25):
        findings.append(
            _make_finding(
                team_id="team-alpha",
                host=f"host-alpha-{i:03d}",
                cve_id=f"CVE-2026-{i:04d}",
                criticality=severity_cycle[i % 5],
            )
        )
    for i in range(5):
        findings.append(
            _make_finding(
                team_id="team-beta",
                host=f"host-beta-{i:03d}",
                cve_id=f"CVE-2026-B{i:04d}",
                criticality="HIGH",
            )
        )

    async with async_session_scope() as session:
        for r in runs:
            session.add(r)
        for f in findings:
            session.add(f)
        await session.commit()

    return {"alpha_runs": [r for r in runs if r.team_id == "team-alpha"],
            "beta_runs": [r for r in runs if r.team_id == "team-beta"],
            "alpha_findings": [f for f in findings if f.team_id == "team-alpha"],
            "beta_findings": [f for f in findings if f.team_id == "team-beta"]}


# ---------------------------------------------------------------------------
# fetch_reports
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_reports_returns_tuple_with_total(seeded_team_reports):
    svc = ServiceFactory().reports
    rows, total = await svc.fetch_reports(limit=10, offset=0, team_id="team-alpha")
    assert isinstance(rows, list)
    assert isinstance(total, int)
    # Total is team-alpha count, independent of limit=10.
    assert total == 25


@pytest.mark.asyncio
async def test_fetch_reports_paginated(seeded_team_reports):
    svc = ServiceFactory().reports
    page1, total = await svc.fetch_reports(limit=10, offset=0, team_id="team-alpha")
    assert len(page1) == 10
    assert total == 25

    page2, total2 = await svc.fetch_reports(limit=10, offset=10, team_id="team-alpha")
    assert len(page2) == 10
    assert total2 == 25

    page3, total3 = await svc.fetch_reports(limit=10, offset=20, team_id="team-alpha")
    assert len(page3) == 5  # remainder
    assert total3 == 25

    # Disjoint ids.
    ids = {r.id for r in page1} | {r.id for r in page2} | {r.id for r in page3}
    assert len(ids) == 25


@pytest.mark.asyncio
async def test_fetch_reports_respects_team_scope(seeded_team_reports):
    svc = ServiceFactory().reports

    alpha_rows, alpha_total = await svc.fetch_reports(
        limit=100, offset=0, team_id="team-alpha"
    )
    beta_rows, beta_total = await svc.fetch_reports(
        limit=100, offset=0, team_id="team-beta"
    )

    assert alpha_total == 25
    assert beta_total == 5
    assert all(r.id.startswith("run-alpha") for r in alpha_rows)
    assert all(r.id.startswith("run-beta") for r in beta_rows)


@pytest.mark.asyncio
async def test_fetch_reports_severity_counts(seeded_team_reports):
    svc = ServiceFactory().reports
    rows, _ = await svc.fetch_reports(limit=5, offset=0, team_id="team-alpha")

    for summary in rows:
        assert set(summary.severity_counts.keys()) == {
            "critical",
            "high",
            "medium",
            "low",
            "info",
        }
        assert summary.finding_count == sum(summary.severity_counts.values())
        # Each host has a single finding → count is exactly 1.
        assert summary.finding_count == 1


@pytest.mark.asyncio
async def test_fetch_reports_sort_order_desc(seeded_team_reports):
    svc = ServiceFactory().reports
    rows, _ = await svc.fetch_reports(limit=25, offset=0, team_id="team-alpha")

    created_ats = [r.created_at for r in rows]
    assert created_ats == sorted(created_ats, reverse=True)


@pytest.mark.asyncio
async def test_fetch_reports_empty_team(test_db):
    svc = ServiceFactory().reports
    rows, total = await svc.fetch_reports(limit=10, offset=0, team_id="team-nobody")
    assert rows == []
    assert total == 0


# ---------------------------------------------------------------------------
# fetch_report_detail
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetch_report_detail_returns_full_shape(seeded_team_reports):
    svc = ServiceFactory().reports
    alpha_run = seeded_team_reports["alpha_runs"][0]

    detail = await svc.fetch_report_detail(alpha_run.id, team_id="team-alpha")

    assert isinstance(detail, ReportDetail)
    assert detail.id == alpha_run.id
    assert detail.status == "completed"
    assert set(detail.severity_counts.keys()) == {
        "critical",
        "high",
        "medium",
        "low",
        "info",
    }
    assert detail.finding_count == len(detail.findings)
    assert isinstance(detail.metadata, dict)
    assert detail.metadata["module_id"] == "vulnerability"
    assert detail.remediation_notes is None
    # Findings all belong to alpha-scoped hosts.
    assert all(f.host.startswith("host-alpha") for f in detail.findings)


@pytest.mark.asyncio
async def test_fetch_report_detail_not_found(seeded_team_reports):
    svc = ServiceFactory().reports
    with pytest.raises(NotFoundError):
        await svc.fetch_report_detail("run-does-not-exist", team_id="team-alpha")


@pytest.mark.asyncio
async def test_fetch_report_detail_cross_team_is_notfound(seeded_team_reports):
    """A report belonging to team-beta looked up with team-alpha scope raises
    NotFoundError — no 403, no existence leak (T-176a-01-02)."""
    svc = ServiceFactory().reports
    beta_run = seeded_team_reports["beta_runs"][0]
    with pytest.raises(NotFoundError):
        await svc.fetch_report_detail(beta_run.id, team_id="team-alpha")


@pytest.mark.asyncio
async def test_fetch_report_detail_admin_sees_all(seeded_team_reports):
    """team_id=None (admin context) can fetch any report regardless of owner."""
    svc = ServiceFactory().reports
    beta_run = seeded_team_reports["beta_runs"][0]
    detail = await svc.fetch_report_detail(beta_run.id, team_id=None)
    assert detail.id == beta_run.id


# ---------------------------------------------------------------------------
# Schema round-trip
# ---------------------------------------------------------------------------


def test_schema_round_trip_report_summary():
    summary = ReportSummary(
        id="run-xyz",
        title="scan web01",
        target="web01",
        created_at=datetime.now(timezone.utc),
        status="completed",
        severity_counts={"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 0},
        finding_count=10,
    )
    roundtrip = ReportSummary.model_validate_json(summary.model_dump_json())
    assert roundtrip == summary


def test_schema_round_trip_report_detail():
    detail = ReportDetail(
        id="run-xyz",
        title="scan web01",
        target="web01",
        created_at=datetime.now(timezone.utc),
        status="completed",
        severity_counts={"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
        finding_count=1,
        findings=[
            FindingSummary(
                id=42,
                cve_id="CVE-2026-0001",
                title="CVE-2026-0001 in openssl",
                severity="critical",
                host="web01",
                package="openssl",
            )
        ],
        metadata={"route": {"target": "web01"}},
        remediation_notes=None,
    )
    roundtrip = ReportDetail.model_validate_json(detail.model_dump_json())
    assert roundtrip == detail
    assert roundtrip.finding_count == len(roundtrip.findings)
