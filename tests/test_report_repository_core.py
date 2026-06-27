"""Unit tests for ReportRepository core paths: latest_report, latest_report_rows,
normalize_report_summary_payload, _build_materialized_summary, has_target_reports,
and private helpers (_module_id, _find_target_report, _parse_json_object, _artifact_payload).

Complements test_report_repository_materialized.py (which covers latest_materialized_findings).
Uses in-memory SQLite with real SQLModel sessions and mock artifact stores to exercise
the uncovered branches without filesystem I/O.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

import pytest
from sqlmodel import Session, SQLModel, create_engine

from aila.platform.contracts.reporting import (
    LatestReportResult,
    LatestReportRowsResult,
    TargetReportReference,
    normalize_report_summary_payload,
)
from aila.platform.exceptions import NotFoundError
from aila.storage.db_models import ReportArtifactRecord, WorkflowRunRecord
from aila.storage.report_repository import (
    MAX_ROW_PAGE_SIZE,
    ReportRepository,
    _build_materialized_summary,
    _find_target_report,
    _module_id,
    _parse_json_object,
)
from aila.storage.report_store import ReportArtifactBundle, ReportArtifactStore

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(eng)
    yield eng
    SQLModel.metadata.drop_all(eng)


@pytest.fixture
def session(engine):
    with Session(engine) as s:
        yield s


def _make_run(
    *,
    run_id: str = "run-1",
    status: str = "completed",
    action_id: str = "",
    route_json: str = "{}",
    summary_json: str = "{}",
    completed_at: datetime | None = None,
) -> WorkflowRunRecord:
    return WorkflowRunRecord(
        id=run_id,
        query_text="test query",
        action_id=action_id,
        status=status,
        route_json=route_json,
        summary_json=summary_json,
        completed_at=completed_at or datetime.now(UTC),
    )


def _fleet_bundle(
    *,
    report_path: str = "/reports/fleet.csv",
    summary_doc: dict | None = None,
    rows_doc: list[dict] | None = None,
    report_artifact_id: int | None = 1,
    summary_artifact_id: int | None = 2,
    rows_artifact_id: int | None = 3,
    summary_path: str | None = "/reports/fleet_summary.json",
) -> ReportArtifactBundle:
    return ReportArtifactBundle(
        storage="database",
        report_path=report_path,
        report_content="col1,col2\na,b",
        summary_document=summary_doc if summary_doc is not None else {"total_findings": 5},
        rows_document=rows_doc,
        report_artifact_id=report_artifact_id,
        summary_artifact_id=summary_artifact_id,
        rows_artifact_id=rows_artifact_id,
        summary_path=summary_path,
    )


def _target_bundle(
    *,
    report_path: str = "/reports/target.csv",
    summary_doc: dict | None = None,
    rows_doc: list[dict] | None = None,
) -> ReportArtifactBundle:
    return ReportArtifactBundle(
        storage="database",
        report_path=report_path,
        report_content="col1,col2\nx,y",
        summary_document=summary_doc if summary_doc is not None else {"total_findings": 2},
        rows_document=rows_doc,
        report_artifact_id=10,
        summary_artifact_id=11,
        rows_artifact_id=12,
        summary_path="/reports/target_summary.json",
    )


def _target_ref(
    *,
    system_name: str = "prod-01",
    host: str = "10.0.0.1",
    summary: dict | None = None,
) -> TargetReportReference:
    return TargetReportReference(
        system_id=1,
        system_name=system_name,
        host=host,
        report_artifact_id=10,
        summary_artifact_id=11,
        rows_artifact_id=12,
        summary=summary or {"total_findings": 2},
    )


# ---------------------------------------------------------------------------
# _parse_json_object
# ---------------------------------------------------------------------------


class TestParseJsonObject:
    def test_valid_json_dict(self):
        assert _parse_json_object('{"key": "value"}') == {"key": "value"}

    def test_none_returns_empty_dict(self):
        assert _parse_json_object(None) == {}

    def test_empty_string_returns_empty_dict(self):
        assert _parse_json_object("") == {}

    def test_invalid_json_returns_empty_dict(self):
        assert _parse_json_object("not json") == {}

    def test_json_array_returns_empty_dict(self):
        """JSON arrays are valid JSON but not dicts; should return {}."""
        assert _parse_json_object("[1, 2, 3]") == {}

    def test_json_string_returns_empty_dict(self):
        assert _parse_json_object('"just a string"') == {}

    def test_json_number_returns_empty_dict(self):
        assert _parse_json_object("42") == {}


# ---------------------------------------------------------------------------
# _module_id
# ---------------------------------------------------------------------------


class TestModuleId:
    def test_from_route_json_selected_module(self, session):
        run = _make_run(route_json=json.dumps({"selected_module": "vulnerability"}))
        assert _module_id(run) == "vulnerability"

    def test_from_summary_json_module_id(self, session):
        run = _make_run(summary_json=json.dumps({"module_id": "compliance"}))
        assert _module_id(run) == "compliance"

    def test_route_json_takes_precedence_over_summary_json(self, session):
        run = _make_run(
            route_json=json.dumps({"selected_module": "vulnerability"}),
            summary_json=json.dumps({"module_id": "compliance"}),
        )
        assert _module_id(run) == "vulnerability"

    def test_from_action_id_prefix(self, session):
        run = _make_run(action_id="vulnerability.scan_report")
        assert _module_id(run) == "vulnerability"

    def test_action_id_no_dot_returns_none(self, session):
        run = _make_run(action_id="nodot")
        assert _module_id(run) is None

    def test_empty_action_id_returns_none(self, session):
        run = _make_run()
        assert _module_id(run) is None

    def test_whitespace_selected_module_ignored(self, session):
        """A whitespace-only selected_module should not be returned."""
        run = _make_run(route_json=json.dumps({"selected_module": "   "}))
        assert _module_id(run) is None

    def test_whitespace_summary_module_id_ignored(self, session):
        run = _make_run(summary_json=json.dumps({"module_id": "  "}))
        assert _module_id(run) is None

    def test_non_string_selected_module_falls_through(self, session):
        """Non-string selected_module should not match the isinstance check."""
        run = _make_run(route_json=json.dumps({"selected_module": 123}))
        assert _module_id(run) is None

    def test_invalid_route_json_falls_through(self, session):
        run = _make_run(route_json="not json")
        assert _module_id(run) is None

    def test_action_id_with_whitespace_prefix(self, session):
        """action_id 'vuln.scan' where prefix after strip is 'vuln'."""
        run = _make_run(action_id=" vuln .scan")
        # " vuln " after split on first dot -> " vuln " -> strip -> "vuln"
        assert _module_id(run) == "vuln"

    def test_action_id_with_empty_prefix(self, session):
        """'.scan' has empty prefix -> should return None."""
        run = _make_run(action_id=".scan")
        assert _module_id(run) is None


# ---------------------------------------------------------------------------
# _find_target_report
# ---------------------------------------------------------------------------


class TestFindTargetReport:
    def test_match_by_system_name(self):
        ref = _target_ref(system_name="prod-01", host="10.0.0.1")
        result = _find_target_report([ref], "prod-01")
        assert result is ref

    def test_match_by_host(self):
        ref = _target_ref(system_name="prod-01", host="10.0.0.1")
        result = _find_target_report([ref], "10.0.0.1")
        assert result is ref

    def test_case_insensitive_match(self):
        ref = _target_ref(system_name="Prod-01", host="10.0.0.1")
        result = _find_target_report([ref], "PROD-01")
        assert result is ref

    def test_whitespace_tolerance(self):
        ref = _target_ref(system_name="  prod-01  ", host="10.0.0.1")
        result = _find_target_report([ref], "  prod-01  ")
        assert result is ref

    def test_no_match_returns_none(self):
        ref = _target_ref(system_name="prod-01", host="10.0.0.1")
        assert _find_target_report([ref], "prod-99") is None

    def test_empty_list_returns_none(self):
        assert _find_target_report([], "anything") is None

    def test_multiple_refs_returns_first_match(self):
        ref1 = _target_ref(system_name="prod-01", host="10.0.0.1")
        ref2 = _target_ref(system_name="prod-02", host="10.0.0.2")
        assert _find_target_report([ref1, ref2], "prod-02") is ref2


# ---------------------------------------------------------------------------
# _build_materialized_summary
# ---------------------------------------------------------------------------


class TestBuildMaterializedSummary:
    def test_counts_criticalities(self):
        rows: list[dict[str, Any]] = [
            {"criticality": "Immediate"},
            {"criticality": "Immediate"},
            {"criticality": "High"},
            {"criticality": "Moderate"},
            {"criticality": "Planned"},
        ]
        result = _build_materialized_summary(rows)
        assert result["total_findings"] == 5
        assert result["immediate"] == 2
        assert result["high"] == 1
        assert result["moderate"] == 1
        assert result["planned"] == 1
        assert result["report_scope"] == "latest_target_reports"

    def test_empty_rows(self):
        result = _build_materialized_summary([])
        assert result["total_findings"] == 0
        assert result["immediate"] == 0
        assert result["high"] == 0
        assert result["moderate"] == 0
        assert result["planned"] == 0

    def test_unknown_criticality_ignored(self):
        rows: list[dict[str, Any]] = [
            {"criticality": "Unknown"},
            {"criticality": "Critical"},
            {"criticality": None},
            {},
        ]
        result = _build_materialized_summary(rows)
        assert result["total_findings"] == 4
        assert result["immediate"] == 0
        assert result["high"] == 0
        assert result["moderate"] == 0
        assert result["planned"] == 0

    def test_mixed_known_and_unknown(self):
        rows: list[dict[str, Any]] = [
            {"criticality": "High"},
            {"criticality": "NotReal"},
            {"criticality": "Planned"},
        ]
        result = _build_materialized_summary(rows)
        assert result["total_findings"] == 3
        assert result["high"] == 1
        assert result["planned"] == 1
        assert result["immediate"] == 0
        assert result["moderate"] == 0


# ---------------------------------------------------------------------------
# normalize_report_summary_payload
# ---------------------------------------------------------------------------


class TestNormalizeReportSummaryPayload:
    def test_none_returns_empty_dict(self):
        assert normalize_report_summary_payload(None) == {}

    def test_non_dict_returns_empty_dict(self):
        assert normalize_report_summary_payload("string") == {}  # type: ignore[arg-type]
        assert normalize_report_summary_payload(42) == {}  # type: ignore[arg-type]

    def test_empty_dict_normalizes_notes(self):
        result = normalize_report_summary_payload({})
        assert result["notes"] == []

    def test_strips_empty_notes(self):
        result = normalize_report_summary_payload({"notes": ["valid", "", "  ", "also valid"]})
        assert result["notes"] == ["valid", "also valid"]

    def test_none_notes_becomes_empty_list(self):
        result = normalize_report_summary_payload({"notes": None})
        assert result["notes"] == []

    def test_scoring_counts_coerced(self):
        result = normalize_report_summary_payload({
            "scoring_counts": {"model": "5", "cache": 3.7}
        })
        assert result["scoring_counts"] == {"model": 5, "cache": 3}

    def test_scoring_counts_negative_clamp(self):
        result = normalize_report_summary_payload({
            "scoring_counts": {"model": -10, "cache": -1}
        })
        assert result["scoring_counts"] == {"model": 0, "cache": 0}

    def test_scoring_counts_invalid_values(self):
        result = normalize_report_summary_payload({
            "scoring_counts": {"model": "abc", "cache": None}
        })
        assert result["scoring_counts"] == {"model": 0, "cache": 0}

    def test_preserves_other_keys(self):
        result = normalize_report_summary_payload({
            "total_findings": 10,
            "extra_key": "preserved",
        })
        assert result["total_findings"] == 10
        assert result["extra_key"] == "preserved"

    def test_scoring_counts_missing_keys(self):
        """scoring_counts dict without model/cache keys."""
        result = normalize_report_summary_payload({
            "scoring_counts": {}
        })
        assert result["scoring_counts"] == {"model": 0, "cache": 0}


# ---------------------------------------------------------------------------
# ReportRepository.latest_report -- fleet scope
# ---------------------------------------------------------------------------


class TestLatestReportFleet:
    def _repo_with_mock_store(self, bundle: ReportArtifactBundle | None, target_refs=None):
        store = MagicMock(spec=ReportArtifactStore)
        store.list_run_records.return_value = []
        store.target_report_references.return_value = target_refs or []
        store.load_run_bundle.return_value = bundle
        return ReportRepository(artifact_store=store)

    def test_fleet_report_basic(self, session):
        run = _make_run(completed_at=datetime(2025, 1, 1, tzinfo=UTC))
        session.add(run)
        session.commit()

        bundle = _fleet_bundle()
        repo = self._repo_with_mock_store(bundle)
        result = repo.latest_report(session)

        assert isinstance(result, LatestReportResult)
        assert result.report_scope == "fleet"
        assert result.run_id == "run-1"
        assert result.report_path == "/reports/fleet.csv"
        assert result.completed_at is not None
        assert result.completed_at.startswith("2025-01-01T00:00:00")

    def test_fleet_report_skips_none_bundle(self, session):
        """If load_run_bundle returns None, skip the run and raise NotFoundError."""
        run = _make_run()
        session.add(run)
        session.commit()

        repo = self._repo_with_mock_store(None)
        with pytest.raises(NotFoundError, match="No completed reports"):
            repo.latest_report(session)

    def test_fleet_report_skips_bundle_without_report_path(self, session):
        """If bundle.report_path is None, skip the run."""
        run = _make_run()
        session.add(run)
        session.commit()

        bundle = _fleet_bundle(report_path=None)  # type: ignore[arg-type]
        repo = self._repo_with_mock_store(bundle)
        with pytest.raises(NotFoundError):
            repo.latest_report(session)

    def test_fleet_report_with_include_content(self, session):
        run = _make_run()
        session.add(run)
        session.commit()

        bundle = _fleet_bundle(
            rows_doc=[{"cve": "CVE-2024-0001"}, {"cve": "CVE-2024-0002"}],
        )
        repo = self._repo_with_mock_store(bundle)
        result = repo.latest_report(session, include_content=True)

        assert result.artifact_storage == "database"
        assert result.report_content == "col1,col2\na,b"
        assert result.summary_document is not None
        assert result.rows_document == [{"cve": "CVE-2024-0001"}, {"cve": "CVE-2024-0002"}]

    def test_fleet_report_include_content_non_dict_rows_skipped(self, session):
        """rows_document with non-dict items should be filtered out."""
        run = _make_run()
        session.add(run)
        session.commit()

        bundle = _fleet_bundle(rows_doc=[{"cve": "CVE-1"}, "not-a-dict", {"cve": "CVE-2"}])  # type: ignore[list-item]
        repo = self._repo_with_mock_store(bundle)
        result = repo.latest_report(session, include_content=True)

        assert result.rows_document == [{"cve": "CVE-1"}, {"cve": "CVE-2"}]

    def test_fleet_report_include_content_non_list_rows(self, session):
        """If rows_document is not a list, result.rows_document should be None."""
        run = _make_run()
        session.add(run)
        session.commit()

        bundle = _fleet_bundle()
        bundle.rows_document = "not a list"  # type: ignore[assignment]
        repo = self._repo_with_mock_store(bundle)
        result = repo.latest_report(session, include_content=True)

        assert result.rows_document is None

    def test_fleet_report_summary_not_dict_fallback(self, session):
        """If summary_document is not a dict, fallback to empty dict."""
        run = _make_run()
        session.add(run)
        session.commit()

        bundle = _fleet_bundle(summary_doc=None)
        bundle.summary_document = "not a dict"  # type: ignore[assignment]
        repo = self._repo_with_mock_store(bundle)
        result = repo.latest_report(session)

        # summary_payload falls back to {} when not a dict
        assert result.summary == normalize_report_summary_payload({})

    def test_fleet_module_id_filter(self, session):
        """When module_id is specified, runs with different module_id are skipped."""
        run1 = _make_run(
            run_id="run-vuln",
            route_json=json.dumps({"selected_module": "vulnerability"}),
            completed_at=datetime(2025, 1, 2, tzinfo=UTC),
        )
        run2 = _make_run(
            run_id="run-comp",
            route_json=json.dumps({"selected_module": "compliance"}),
            completed_at=datetime(2025, 1, 1, tzinfo=UTC),
        )
        session.add(run1)
        session.add(run2)
        session.commit()

        bundle = _fleet_bundle()
        repo = self._repo_with_mock_store(bundle)
        result = repo.latest_report(session, module_id="vulnerability")

        assert result.run_id == "run-vuln"
        assert result.module_id == "vulnerability"

    def test_fleet_target_reports_populated(self, session):
        run = _make_run()
        session.add(run)
        session.commit()

        target_refs = [_target_ref(system_name="prod-01"), _target_ref(system_name="prod-02")]
        bundle = _fleet_bundle()
        repo = self._repo_with_mock_store(bundle, target_refs=target_refs)
        result = repo.latest_report(session)

        assert len(result.target_reports) == 2

    def test_no_completed_runs_raises(self, session):
        """If only non-completed runs exist, raise NotFoundError."""
        run = _make_run(status="running")
        session.add(run)
        session.commit()

        repo = self._repo_with_mock_store(_fleet_bundle())
        with pytest.raises(NotFoundError, match="No completed reports"):
            repo.latest_report(session)

    def test_notfound_includes_target_in_message(self, session):
        with pytest.raises(NotFoundError, match="for target 'webserver'"):
            repo = self._repo_with_mock_store(None)
            repo.latest_report(session, target="webserver")

    def test_fleet_include_content_summary_none(self, session):
        """When bundle.summary_document is None, summary_document on result should be None."""
        run = _make_run()
        session.add(run)
        session.commit()

        bundle = _fleet_bundle(summary_doc=None)
        bundle.summary_document = None
        repo = self._repo_with_mock_store(bundle)
        result = repo.latest_report(session, include_content=True)

        assert result.summary_document is None


# ---------------------------------------------------------------------------
# ReportRepository.latest_report -- target scope
# ---------------------------------------------------------------------------


class TestLatestReportTarget:
    def _repo_with_mock_store(
        self,
        bundle: ReportArtifactBundle | None,
        target_refs: list[TargetReportReference] | None = None,
    ):
        store = MagicMock(spec=ReportArtifactStore)
        store.list_run_records.return_value = []
        store.target_report_references.return_value = target_refs or []
        store.load_run_bundle.return_value = bundle
        return ReportRepository(artifact_store=store)

    def test_target_report_basic(self, session):
        run = _make_run(completed_at=datetime(2025, 1, 1, tzinfo=UTC))
        session.add(run)
        session.commit()

        ref = _target_ref(system_name="prod-01", host="10.0.0.1")
        bundle = _target_bundle(summary_doc={"total_findings": 2})
        repo = self._repo_with_mock_store(bundle, target_refs=[ref])
        result = repo.latest_report(session, target="prod-01")

        assert result.report_scope == "target"
        assert result.target is not None
        assert result.target.system_name == "prod-01"
        assert "target 'prod-01'" in result.message

    def test_target_report_uses_bundle_summary_when_dict(self, session):
        """When summary_document is a dict, use it instead of the target reference summary."""
        run = _make_run()
        session.add(run)
        session.commit()

        ref = _target_ref(summary={"from_ref": True})
        bundle = _target_bundle(summary_doc={"from_bundle": True})
        repo = self._repo_with_mock_store(bundle, target_refs=[ref])
        result = repo.latest_report(session, target="prod-01")

        assert result.summary == normalize_report_summary_payload({"from_bundle": True})

    def test_target_report_falls_back_to_ref_summary(self, session):
        """When summary_document is not a dict, fall back to target_report.summary."""
        run = _make_run()
        session.add(run)
        session.commit()

        ref = _target_ref(summary={"from_ref": True})
        bundle = _target_bundle()
        bundle.summary_document = "not a dict"  # type: ignore[assignment]
        repo = self._repo_with_mock_store(bundle, target_refs=[ref])
        result = repo.latest_report(session, target="prod-01")

        assert result.summary == normalize_report_summary_payload({"from_ref": True})

    def test_target_not_found_skips_run(self, session):
        """When target doesn't match any target reference, skip the run."""
        run = _make_run()
        session.add(run)
        session.commit()

        ref = _target_ref(system_name="prod-01", host="10.0.0.1")
        bundle = _target_bundle()
        repo = self._repo_with_mock_store(bundle, target_refs=[ref])

        with pytest.raises(NotFoundError, match="for target 'prod-99'"):
            repo.latest_report(session, target="prod-99")

    def test_target_bundle_none_skips_run(self, session):
        """When bundle is None for a target query, skip the run."""
        run = _make_run()
        session.add(run)
        session.commit()

        ref = _target_ref()
        repo = self._repo_with_mock_store(None, target_refs=[ref])

        with pytest.raises(NotFoundError, match="for target 'prod-01'"):
            repo.latest_report(session, target="prod-01")

    def test_target_with_include_content(self, session):
        run = _make_run()
        session.add(run)
        session.commit()

        ref = _target_ref()
        bundle = _target_bundle(
            rows_doc=[{"cve": "CVE-2024-0001"}],
        )
        repo = self._repo_with_mock_store(bundle, target_refs=[ref])
        result = repo.latest_report(session, target="prod-01", include_content=True)

        assert result.artifact_storage == "database"
        assert result.report_content == "col1,col2\nx,y"
        assert result.rows_document == [{"cve": "CVE-2024-0001"}]

    def test_target_include_content_rows_non_list(self, session):
        """Non-list rows_document -> None."""
        run = _make_run()
        session.add(run)
        session.commit()

        ref = _target_ref()
        bundle = _target_bundle()
        bundle.rows_document = "bad"  # type: ignore[assignment]
        repo = self._repo_with_mock_store(bundle, target_refs=[ref])
        result = repo.latest_report(session, target="prod-01", include_content=True)

        assert result.rows_document is None

    def test_target_completed_at_none(self, session):
        """When run.completed_at is None, result.completed_at should be None."""
        run = _make_run(completed_at=None)
        # Manually set completed_at to None (the factory may set a default)
        run.completed_at = None
        session.add(run)
        session.commit()

        ref = _target_ref()
        bundle = _target_bundle()
        repo = self._repo_with_mock_store(bundle, target_refs=[ref])
        result = repo.latest_report(session, target="prod-01")

        assert result.completed_at is None


# ---------------------------------------------------------------------------
# ReportRepository.latest_report_rows
# ---------------------------------------------------------------------------


class TestLatestReportRows:
    def _repo_returning_report(self, rows_doc: list[dict] | None, report_path: str | None = "/r.csv"):
        """Build a repo whose latest_report returns a known payload."""
        store = MagicMock(spec=ReportArtifactStore)
        store.list_run_records.return_value = []
        store.target_report_references.return_value = []
        store.load_run_bundle.return_value = ReportArtifactBundle(
            storage="database",
            report_path=report_path,
            report_content="data",
            summary_document={"total_findings": 3},
            rows_document=rows_doc,
            report_artifact_id=1,
            summary_artifact_id=2,
            rows_artifact_id=3,
            summary_path="/s.json",
        )
        return ReportRepository(artifact_store=store)

    def test_basic_pagination(self, session):
        run = _make_run()
        session.add(run)
        session.commit()

        rows = [{"id": i} for i in range(10)]
        repo = self._repo_returning_report(rows)
        result = repo.latest_report_rows(session, offset=2, limit=3)

        assert isinstance(result, LatestReportRowsResult)
        assert result.total_rows == 10
        assert result.offset == 2
        assert result.limit == 3
        assert len(result.rows) == 3
        assert result.rows[0] == {"id": 2}

    def test_offset_normalization_negative(self, session):
        run = _make_run()
        session.add(run)
        session.commit()

        rows = [{"id": i} for i in range(5)]
        repo = self._repo_returning_report(rows)
        result = repo.latest_report_rows(session, offset=-10, limit=2)

        assert result.offset == 0
        assert len(result.rows) == 2

    def test_limit_normalization_zero(self, session):
        run = _make_run()
        session.add(run)
        session.commit()

        rows = [{"id": i} for i in range(5)]
        repo = self._repo_returning_report(rows)
        result = repo.latest_report_rows(session, offset=0, limit=0)

        assert result.limit == 1
        assert len(result.rows) == 1

    def test_limit_capped_at_max(self, session):
        run = _make_run()
        session.add(run)
        session.commit()

        rows = [{"id": 0}]
        repo = self._repo_returning_report(rows)
        result = repo.latest_report_rows(session, limit=MAX_ROW_PAGE_SIZE + 100)

        assert result.limit == MAX_ROW_PAGE_SIZE

    def test_rows_document_none_raises(self, session):
        run = _make_run()
        session.add(run)
        session.commit()

        repo = self._repo_returning_report(None, report_path="/some/report.csv")
        with pytest.raises(NotFoundError, match="Structured report rows are unavailable"):
            repo.latest_report_rows(session)

    def test_rows_document_none_with_path_in_message(self, session):
        """When rows_document is None and report_path exists, error message includes the artifact path."""
        run = _make_run()
        session.add(run)
        session.commit()

        repo = self._repo_returning_report(None, report_path="/some/report.csv")
        with pytest.raises(NotFoundError, match="for artifact '/some/report.csv'"):
            repo.latest_report_rows(session)

    def test_rows_document_none_without_path_in_message(self, session):
        """When rows_document is None and report_path is empty, error message has no artifact name."""
        run = _make_run()
        session.add(run)
        session.commit()

        # report_path must be truthy for latest_report to succeed, but the result's
        # report_path can be empty string (artifact_bundle has a real path but result
        # gets empty). Use a custom approach: mock latest_report directly.
        repo = ReportRepository()
        report_result = LatestReportResult(
            message="test",
            run_id="run-1",
            report_scope="fleet",
            report_path="",
            rows_document=None,
        )
        repo.latest_report = MagicMock(return_value=report_result)  # type: ignore[method-assign]
        with pytest.raises(NotFoundError, match=r"unavailable\.$"):
            repo.latest_report_rows(session)

    def test_row_filter_applied(self, session):
        run = _make_run()
        session.add(run)
        session.commit()

        rows = [{"sev": "high"}, {"sev": "low"}, {"sev": "high"}]
        repo = self._repo_returning_report(rows)

        def filter_high(rows_list, filters):
            return [r for r in rows_list if r["sev"] == "high"]

        result = repo.latest_report_rows(session, row_filter=filter_high)
        assert result.total_rows == 2
        assert all(r["sev"] == "high" for r in result.rows)

    def test_row_filter_with_filters_dict(self, session):
        """Filters dict is passed through to row_filter."""
        run = _make_run()
        session.add(run)
        session.commit()

        rows = [{"sev": "high"}, {"sev": "low"}]
        repo = self._repo_returning_report(rows)

        received_filters = {}

        def capture_filter(rows_list, filters):
            received_filters.update(filters or {})
            return rows_list

        result = repo.latest_report_rows(session, row_filter=capture_filter, filters={"sev": "high"})
        assert received_filters == {"sev": "high"}

    def test_module_id_forwarded(self, session):
        """module_id is forwarded to latest_report for filtering."""
        run = _make_run(route_json=json.dumps({"selected_module": "vulnerability"}))
        session.add(run)
        session.commit()

        rows = [{"id": 1}]
        repo = self._repo_returning_report(rows)
        result = repo.latest_report_rows(session, module_id="vulnerability")

        assert result.module_id == "vulnerability"

    def test_offset_beyond_rows(self, session):
        """Offset past the end of rows returns empty slice."""
        run = _make_run()
        session.add(run)
        session.commit()

        rows = [{"id": 0}, {"id": 1}]
        repo = self._repo_returning_report(rows)
        result = repo.latest_report_rows(session, offset=100, limit=10)

        assert result.total_rows == 2
        assert result.rows == []

    def test_result_inherits_report_fields(self, session):
        """The rows result carries metadata from the parent report result."""
        run = _make_run()
        session.add(run)
        session.commit()

        rows = [{"id": 0}]
        repo = self._repo_returning_report(rows)
        result = repo.latest_report_rows(session)

        assert result.run_id == "run-1"
        assert result.report_path == "/r.csv"
        assert result.summary_artifact_id == 2
        assert result.rows_artifact_id == 3


# ---------------------------------------------------------------------------
# ReportRepository.has_target_reports
# ---------------------------------------------------------------------------


class TestHasTargetReports:
    def test_no_records_returns_false(self, session):
        repo = ReportRepository()
        assert repo.has_target_reports(session) is False

    def test_target_record_exists(self, session):
        """A target-scoped artifact record should make has_target_reports True."""
        record = ReportArtifactRecord(
            run_id="run-1",
            scope="target",
            system_name="prod-01",
            host="10.0.0.1",
            artifact_type="csv",
            path="/reports/target.csv",
        )
        session.add(record)
        session.commit()

        repo = ReportRepository()
        assert repo.has_target_reports(session) is True

    def test_fleet_only_returns_false(self, session):
        """Only fleet-scoped records should return False."""
        record = ReportArtifactRecord(
            run_id="run-1",
            scope="fleet",
            artifact_type="csv",
            path="/reports/fleet.csv",
        )
        session.add(record)
        session.commit()

        repo = ReportRepository()
        assert repo.has_target_reports(session) is False

    def test_with_module_id_matching(self, session):
        run = _make_run(
            run_id="run-vuln",
            route_json=json.dumps({"selected_module": "vulnerability"}),
        )
        session.add(run)
        session.commit()

        # Use the real artifact store's list_run_records, but mock the records in the DB
        record = ReportArtifactRecord(
            run_id="run-vuln",
            scope="target",
            system_name="prod-01",
            host="10.0.0.1",
            artifact_type="csv",
            path="/reports/target.csv",
        )
        session.add(record)
        session.commit()

        repo = ReportRepository()
        assert repo.has_target_reports(session, module_id="vulnerability") is True

    def test_with_module_id_not_matching(self, session):
        run = _make_run(
            run_id="run-comp",
            route_json=json.dumps({"selected_module": "compliance"}),
        )
        session.add(run)
        session.commit()

        record = ReportArtifactRecord(
            run_id="run-comp",
            scope="target",
            system_name="prod-01",
            host="10.0.0.1",
            artifact_type="csv",
            path="/reports/target.csv",
        )
        session.add(record)
        session.commit()

        repo = ReportRepository()
        assert repo.has_target_reports(session, module_id="vulnerability") is False

    def test_with_module_id_no_completed_runs(self, session):
        run = _make_run(status="running", run_id="run-running")
        session.add(run)
        session.commit()

        repo = ReportRepository()
        assert repo.has_target_reports(session, module_id="vulnerability") is False

    def test_with_module_id_run_has_only_fleet_records(self, session):
        """module_id matches but no target-scoped records for that run."""
        run = _make_run(
            run_id="run-vuln",
            route_json=json.dumps({"selected_module": "vulnerability"}),
        )
        session.add(run)
        session.commit()

        record = ReportArtifactRecord(
            run_id="run-vuln",
            scope="fleet",
            artifact_type="csv",
            path="/reports/fleet.csv",
        )
        session.add(record)
        session.commit()

        repo = ReportRepository()
        assert repo.has_target_reports(session, module_id="vulnerability") is False


# ---------------------------------------------------------------------------
# ReportRepository.register_materialized_query
# ---------------------------------------------------------------------------


class TestRegisterMaterializedQuery:
    def test_register_and_use(self, session):
        repo = ReportRepository()
        assert repo._materialized_query is None

        def fake_query(sess, target):
            return [{"criticality": "High", "last_scanned_at": "2025-01-01"}]

        repo.register_materialized_query(fake_query)
        assert repo._materialized_query is fake_query

    def test_overwrite_previous(self):
        def q1(s, t):
            return []

        def q2(s, t):
            return []

        repo = ReportRepository(materialized_query=q1)
        assert repo._materialized_query is q1
        repo.register_materialized_query(q2)
        assert repo._materialized_query is q2


# ---------------------------------------------------------------------------
# latest_report -- multiple runs iteration
# ---------------------------------------------------------------------------


class TestLatestReportMultipleRuns:
    def test_skips_first_run_continues_to_second(self, session):
        """When the first run's bundle has no report_path, skip it and try the next."""
        run1 = _make_run(run_id="run-1", completed_at=datetime(2025, 1, 2, tzinfo=UTC))
        run2 = _make_run(run_id="run-2", completed_at=datetime(2025, 1, 1, tzinfo=UTC))
        session.add(run1)
        session.add(run2)
        session.commit()

        call_count = {"n": 0}

        def load_bundle_side_effect(session, run_id, target=None, records=None):
            call_count["n"] += 1
            if run_id == "run-1":
                # First run: no report_path
                return ReportArtifactBundle(storage="database", report_path=None)
            return _fleet_bundle()

        store = MagicMock(spec=ReportArtifactStore)
        store.list_run_records.return_value = []
        store.target_report_references.return_value = []
        store.load_run_bundle.side_effect = load_bundle_side_effect

        repo = ReportRepository(artifact_store=store)
        result = repo.latest_report(session)

        assert result.run_id == "run-2"
        assert call_count["n"] == 2

    def test_module_id_filter_skips_non_matching_runs(self, session):
        """module_id filter skips runs with different module identifiers."""
        run_comp = _make_run(
            run_id="run-comp",
            route_json=json.dumps({"selected_module": "compliance"}),
            completed_at=datetime(2025, 1, 3, tzinfo=UTC),
        )
        run_vuln = _make_run(
            run_id="run-vuln",
            route_json=json.dumps({"selected_module": "vulnerability"}),
            completed_at=datetime(2025, 1, 2, tzinfo=UTC),
        )
        session.add(run_comp)
        session.add(run_vuln)
        session.commit()

        store = MagicMock(spec=ReportArtifactStore)
        store.list_run_records.return_value = []
        store.target_report_references.return_value = []
        store.load_run_bundle.return_value = _fleet_bundle()

        repo = ReportRepository(artifact_store=store)
        result = repo.latest_report(session, module_id="vulnerability")

        assert result.run_id == "run-vuln"
