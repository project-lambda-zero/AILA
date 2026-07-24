"""Unit tests for ReportRepository core paths: latest_report, latest_report_rows,
normalize_report_summary_payload, _build_materialized_summary, has_target_reports,
and private helpers (_module_id, _find_target_report, _parse_json_object, _artifact_payload).

Complements test_report_repository_materialized.py (which covers latest_materialized_findings).
Uses the shared PostgreSQL `test_db` fixture and mock artifact stores to exercise
the uncovered branches without filesystem I/O. Seeding is performed via the sync
`session_scope()` helper (mirroring tests/test_mttr_tool.py) and repository calls
receive an `AsyncSession` from `async_session_scope()`, matching the async storage
contract (D-48/D-49).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from aila.platform.contracts.reporting import (
    LatestReportResult,
    LatestReportRowsResult,
    TargetReportReference,
    normalize_report_summary_payload,
)
from aila.platform.exceptions import NotFoundError
from aila.storage.database import async_session_scope, session_scope
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
# Factories / seeding helpers
# ---------------------------------------------------------------------------


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


def _seed(*records: object) -> None:
    """Insert rows into the shared test DB via sync session_scope (mirrors mttr reference)."""
    with session_scope() as s:
        for record in records:
            s.add(record)
        s.commit()


def _fleet_bundle(
    *,
    report_path: str | None = "/reports/fleet.csv",
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


def _mock_store(
    bundle: ReportArtifactBundle | None,
    target_refs: list[TargetReportReference] | None = None,
) -> MagicMock:
    """Build a MagicMock-specced ReportArtifactStore.

    `list_run_records` and `load_run_bundle` are async on the real store, so
    MagicMock(spec=...) auto-creates AsyncMock attributes for them. Setting
    `return_value` on an AsyncMock makes `await mock(...)` resolve to that value.
    """
    store = MagicMock(spec=ReportArtifactStore)
    store.list_run_records.return_value = []
    store.target_report_references.return_value = target_refs or []
    store.load_run_bundle.return_value = bundle
    return store


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
#
# All cases operate on an in-memory WorkflowRunRecord and never touch the DB;
# no session fixture is required.
# ---------------------------------------------------------------------------


class TestModuleId:
    def test_from_route_json_selected_module(self):
        run = _make_run(route_json=json.dumps({"selected_module": "vulnerability"}))
        assert _module_id(run) == "vulnerability"

    def test_from_summary_json_module_id(self):
        run = _make_run(summary_json=json.dumps({"module_id": "compliance"}))
        assert _module_id(run) == "compliance"

    def test_route_json_takes_precedence_over_summary_json(self):
        run = _make_run(
            route_json=json.dumps({"selected_module": "vulnerability"}),
            summary_json=json.dumps({"module_id": "compliance"}),
        )
        assert _module_id(run) == "vulnerability"

    def test_from_action_id_prefix(self):
        run = _make_run(action_id="vulnerability.scan_report")
        assert _module_id(run) == "vulnerability"

    def test_action_id_no_dot_returns_none(self):
        run = _make_run(action_id="nodot")
        assert _module_id(run) is None

    def test_empty_action_id_returns_none(self):
        run = _make_run()
        assert _module_id(run) is None

    def test_whitespace_selected_module_ignored(self):
        """A whitespace-only selected_module should not be returned."""
        run = _make_run(route_json=json.dumps({"selected_module": "   "}))
        assert _module_id(run) is None

    def test_whitespace_summary_module_id_ignored(self):
        run = _make_run(summary_json=json.dumps({"module_id": "  "}))
        assert _module_id(run) is None

    def test_non_string_selected_module_falls_through(self):
        """Non-string selected_module should not match the isinstance check."""
        run = _make_run(route_json=json.dumps({"selected_module": 123}))
        assert _module_id(run) is None

    def test_invalid_route_json_falls_through(self):
        run = _make_run(route_json="not json")
        assert _module_id(run) is None

    def test_action_id_with_whitespace_prefix(self):
        """action_id ' vuln .scan' -- split on first dot gives ' vuln ', strip -> 'vuln'."""
        run = _make_run(action_id=" vuln .scan")
        assert _module_id(run) == "vuln"

    def test_action_id_with_empty_prefix(self):
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
    async def test_fleet_report_basic(self, test_db):
        _seed(_make_run(completed_at=datetime(2025, 1, 1, tzinfo=UTC)))
        repo = ReportRepository(artifact_store=_mock_store(_fleet_bundle()))

        async with async_session_scope() as session:
            result = await repo.latest_report(session)

        assert isinstance(result, LatestReportResult)
        assert result.report_scope == "fleet"
        assert result.run_id == "run-1"
        assert result.report_path == "/reports/fleet.csv"
        assert result.completed_at is not None
        assert result.completed_at.startswith("2025-01-01T00:00:00")

    async def test_fleet_report_skips_none_bundle(self, test_db):
        """If load_run_bundle returns None, skip the run and raise NotFoundError."""
        _seed(_make_run())
        repo = ReportRepository(artifact_store=_mock_store(None))

        async with async_session_scope() as session:
            with pytest.raises(NotFoundError, match="No completed reports"):
                await repo.latest_report(session)

    async def test_fleet_report_skips_bundle_without_report_path(self, test_db):
        """If bundle.report_path is None, skip the run."""
        _seed(_make_run())
        repo = ReportRepository(artifact_store=_mock_store(_fleet_bundle(report_path=None)))

        async with async_session_scope() as session:
            with pytest.raises(NotFoundError):
                await repo.latest_report(session)

    async def test_fleet_report_with_include_content(self, test_db):
        _seed(_make_run())
        bundle = _fleet_bundle(rows_doc=[{"cve": "CVE-2024-0001"}, {"cve": "CVE-2024-0002"}])
        repo = ReportRepository(artifact_store=_mock_store(bundle))

        async with async_session_scope() as session:
            result = await repo.latest_report(session, include_content=True)

        assert result.artifact_storage == "database"
        assert result.report_content == "col1,col2\na,b"
        assert result.summary_document is not None
        assert result.rows_document == [{"cve": "CVE-2024-0001"}, {"cve": "CVE-2024-0002"}]

    async def test_fleet_report_include_content_non_dict_rows_skipped(self, test_db):
        """rows_document with non-dict items should be filtered out."""
        _seed(_make_run())
        bundle = _fleet_bundle(rows_doc=[{"cve": "CVE-1"}, "not-a-dict", {"cve": "CVE-2"}])  # type: ignore[list-item]
        repo = ReportRepository(artifact_store=_mock_store(bundle))

        async with async_session_scope() as session:
            result = await repo.latest_report(session, include_content=True)

        assert result.rows_document == [{"cve": "CVE-1"}, {"cve": "CVE-2"}]

    async def test_fleet_report_include_content_non_list_rows(self, test_db):
        """If rows_document is not a list, result.rows_document should be None."""
        _seed(_make_run())
        bundle = _fleet_bundle()
        bundle.rows_document = "not a list"  # type: ignore[assignment]
        repo = ReportRepository(artifact_store=_mock_store(bundle))

        async with async_session_scope() as session:
            result = await repo.latest_report(session, include_content=True)

        assert result.rows_document is None

    async def test_fleet_report_summary_not_dict_fallback(self, test_db):
        """If summary_document is not a dict, fallback to empty dict."""
        _seed(_make_run())
        bundle = _fleet_bundle(summary_doc=None)
        bundle.summary_document = "not a dict"  # type: ignore[assignment]
        repo = ReportRepository(artifact_store=_mock_store(bundle))

        async with async_session_scope() as session:
            result = await repo.latest_report(session)

        assert result.summary == normalize_report_summary_payload({})

    async def test_fleet_module_id_filter(self, test_db):
        """When module_id is specified, runs with different module_id are skipped."""
        _seed(
            _make_run(
                run_id="run-vuln",
                route_json=json.dumps({"selected_module": "vulnerability"}),
                completed_at=datetime(2025, 1, 2, tzinfo=UTC),
            ),
            _make_run(
                run_id="run-comp",
                route_json=json.dumps({"selected_module": "compliance"}),
                completed_at=datetime(2025, 1, 1, tzinfo=UTC),
            ),
        )
        repo = ReportRepository(artifact_store=_mock_store(_fleet_bundle()))

        async with async_session_scope() as session:
            result = await repo.latest_report(session, module_id="vulnerability")

        assert result.run_id == "run-vuln"
        assert result.module_id == "vulnerability"

    async def test_fleet_target_reports_populated(self, test_db):
        _seed(_make_run())
        target_refs = [_target_ref(system_name="prod-01"), _target_ref(system_name="prod-02")]
        repo = ReportRepository(artifact_store=_mock_store(_fleet_bundle(), target_refs=target_refs))

        async with async_session_scope() as session:
            result = await repo.latest_report(session)

        assert len(result.target_reports) == 2

    async def test_no_completed_runs_raises(self, test_db):
        """If only non-completed runs exist, raise NotFoundError."""
        _seed(_make_run(status="running"))
        repo = ReportRepository(artifact_store=_mock_store(_fleet_bundle()))

        async with async_session_scope() as session:
            with pytest.raises(NotFoundError, match="No completed reports"):
                await repo.latest_report(session)

    async def test_notfound_includes_target_in_message(self, test_db):
        repo = ReportRepository(artifact_store=_mock_store(None))

        async with async_session_scope() as session:
            with pytest.raises(NotFoundError, match="for target 'webserver'"):
                await repo.latest_report(session, target="webserver")

    async def test_fleet_include_content_summary_none(self, test_db):
        """When bundle.summary_document is None, summary_document on result should be None."""
        _seed(_make_run())
        bundle = _fleet_bundle(summary_doc=None)
        bundle.summary_document = None
        repo = ReportRepository(artifact_store=_mock_store(bundle))

        async with async_session_scope() as session:
            result = await repo.latest_report(session, include_content=True)

        assert result.summary_document is None


# ---------------------------------------------------------------------------
# ReportRepository.latest_report -- target scope
# ---------------------------------------------------------------------------


class TestLatestReportTarget:
    async def test_target_report_basic(self, test_db):
        _seed(_make_run(completed_at=datetime(2025, 1, 1, tzinfo=UTC)))
        ref = _target_ref(system_name="prod-01", host="10.0.0.1")
        bundle = _target_bundle(summary_doc={"total_findings": 2})
        repo = ReportRepository(artifact_store=_mock_store(bundle, target_refs=[ref]))

        async with async_session_scope() as session:
            result = await repo.latest_report(session, target="prod-01")

        assert result.report_scope == "target"
        assert result.target is not None
        assert result.target.system_name == "prod-01"
        assert "target 'prod-01'" in result.message

    async def test_target_report_uses_bundle_summary_when_dict(self, test_db):
        """When summary_document is a dict, use it instead of the target reference summary."""
        _seed(_make_run())
        ref = _target_ref(summary={"from_ref": True})
        bundle = _target_bundle(summary_doc={"from_bundle": True})
        repo = ReportRepository(artifact_store=_mock_store(bundle, target_refs=[ref]))

        async with async_session_scope() as session:
            result = await repo.latest_report(session, target="prod-01")

        assert result.summary == normalize_report_summary_payload({"from_bundle": True})

    async def test_target_report_falls_back_to_ref_summary(self, test_db):
        """When summary_document is not a dict, fall back to target_report.summary."""
        _seed(_make_run())
        ref = _target_ref(summary={"from_ref": True})
        bundle = _target_bundle()
        bundle.summary_document = "not a dict"  # type: ignore[assignment]
        repo = ReportRepository(artifact_store=_mock_store(bundle, target_refs=[ref]))

        async with async_session_scope() as session:
            result = await repo.latest_report(session, target="prod-01")

        assert result.summary == normalize_report_summary_payload({"from_ref": True})

    async def test_target_not_found_skips_run(self, test_db):
        """When target doesn't match any target reference, skip the run."""
        _seed(_make_run())
        ref = _target_ref(system_name="prod-01", host="10.0.0.1")
        bundle = _target_bundle()
        repo = ReportRepository(artifact_store=_mock_store(bundle, target_refs=[ref]))

        async with async_session_scope() as session:
            with pytest.raises(NotFoundError, match="for target 'prod-99'"):
                await repo.latest_report(session, target="prod-99")

    async def test_target_bundle_none_skips_run(self, test_db):
        """When bundle is None for a target query, skip the run."""
        _seed(_make_run())
        ref = _target_ref()
        repo = ReportRepository(artifact_store=_mock_store(None, target_refs=[ref]))

        async with async_session_scope() as session:
            with pytest.raises(NotFoundError, match="for target 'prod-01'"):
                await repo.latest_report(session, target="prod-01")

    async def test_target_with_include_content(self, test_db):
        _seed(_make_run())
        ref = _target_ref()
        bundle = _target_bundle(rows_doc=[{"cve": "CVE-2024-0001"}])
        repo = ReportRepository(artifact_store=_mock_store(bundle, target_refs=[ref]))

        async with async_session_scope() as session:
            result = await repo.latest_report(session, target="prod-01", include_content=True)

        assert result.artifact_storage == "database"
        assert result.report_content == "col1,col2\nx,y"
        assert result.rows_document == [{"cve": "CVE-2024-0001"}]

    async def test_target_include_content_rows_non_list(self, test_db):
        """Non-list rows_document -> None."""
        _seed(_make_run())
        ref = _target_ref()
        bundle = _target_bundle()
        bundle.rows_document = "bad"  # type: ignore[assignment]
        repo = ReportRepository(artifact_store=_mock_store(bundle, target_refs=[ref]))

        async with async_session_scope() as session:
            result = await repo.latest_report(session, target="prod-01", include_content=True)

        assert result.rows_document is None

    async def test_target_completed_at_none(self, test_db):
        """When run.completed_at is None, result.completed_at should be None."""
        run = _make_run(completed_at=None)
        # The factory falls back to datetime.now(UTC) when completed_at is None; force None.
        run.completed_at = None
        _seed(run)
        ref = _target_ref()
        bundle = _target_bundle()
        repo = ReportRepository(artifact_store=_mock_store(bundle, target_refs=[ref]))

        async with async_session_scope() as session:
            result = await repo.latest_report(session, target="prod-01")

        assert result.completed_at is None


# ---------------------------------------------------------------------------
# ReportRepository.latest_report_rows
# ---------------------------------------------------------------------------


def _repo_returning_report(rows_doc: list[dict] | None, report_path: str | None = "/r.csv") -> ReportRepository:
    """Build a repo whose latest_report (through the artifact store mock) returns a known payload."""
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


class TestLatestReportRows:
    async def test_basic_pagination(self, test_db):
        _seed(_make_run())
        rows = [{"id": i} for i in range(10)]
        repo = _repo_returning_report(rows)

        async with async_session_scope() as session:
            result = await repo.latest_report_rows(session, offset=2, limit=3)

        assert isinstance(result, LatestReportRowsResult)
        assert result.total_rows == 10
        assert result.offset == 2
        assert result.limit == 3
        assert len(result.rows) == 3
        assert result.rows[0] == {"id": 2}

    async def test_offset_normalization_negative(self, test_db):
        _seed(_make_run())
        rows = [{"id": i} for i in range(5)]
        repo = _repo_returning_report(rows)

        async with async_session_scope() as session:
            result = await repo.latest_report_rows(session, offset=-10, limit=2)

        assert result.offset == 0
        assert len(result.rows) == 2

    async def test_limit_normalization_zero(self, test_db):
        _seed(_make_run())
        rows = [{"id": i} for i in range(5)]
        repo = _repo_returning_report(rows)

        async with async_session_scope() as session:
            result = await repo.latest_report_rows(session, offset=0, limit=0)

        assert result.limit == 1
        assert len(result.rows) == 1

    async def test_limit_capped_at_max(self, test_db):
        _seed(_make_run())
        rows = [{"id": 0}]
        repo = _repo_returning_report(rows)

        async with async_session_scope() as session:
            result = await repo.latest_report_rows(session, limit=MAX_ROW_PAGE_SIZE + 100)

        assert result.limit == MAX_ROW_PAGE_SIZE

    async def test_rows_document_none_raises(self, test_db):
        _seed(_make_run())
        repo = _repo_returning_report(None, report_path="/some/report.csv")

        async with async_session_scope() as session:
            with pytest.raises(NotFoundError, match="Structured report rows are unavailable"):
                await repo.latest_report_rows(session)

    async def test_rows_document_none_with_run_id_in_message(self, test_db):
        """When rows_document is None, the error message includes the run_id (which is
        the actual identifier surfaced by the current source)."""
        _seed(_make_run())
        repo = _repo_returning_report(None, report_path="/some/report.csv")

        async with async_session_scope() as session:
            with pytest.raises(NotFoundError, match="for run 'run-1'"):
                await repo.latest_report_rows(session)

    async def test_rows_document_none_without_run_id_in_message(self):
        """When run_id is empty on the report payload, the error message has no run tag."""
        report_result = LatestReportResult(
            message="test",
            run_id="",  # empty run_id -> no trailing "for run '...'"
            report_scope="fleet",
            report_path="",
            rows_document=None,
        )
        repo = ReportRepository()
        # latest_report is async in the current API; use AsyncMock so `await repo.latest_report(...)`
        # resolves to the crafted result without hitting the DB.
        repo.latest_report = AsyncMock(return_value=report_result)  # type: ignore[method-assign]

        with pytest.raises(NotFoundError, match=r"unavailable\.$"):
            await repo.latest_report_rows(MagicMock())

    async def test_row_filter_applied(self, test_db):
        _seed(_make_run())
        rows = [{"sev": "high"}, {"sev": "low"}, {"sev": "high"}]
        repo = _repo_returning_report(rows)

        def filter_high(rows_list, filters):
            return [r for r in rows_list if r["sev"] == "high"]

        async with async_session_scope() as session:
            result = await repo.latest_report_rows(session, row_filter=filter_high)

        assert result.total_rows == 2
        assert all(r["sev"] == "high" for r in result.rows)

    async def test_row_filter_with_filters_dict(self, test_db):
        """Filters dict is passed through to row_filter."""
        _seed(_make_run())
        rows = [{"sev": "high"}, {"sev": "low"}]
        repo = _repo_returning_report(rows)

        received_filters: dict[str, object] = {}

        def capture_filter(rows_list, filters):
            received_filters.update(filters or {})
            return rows_list

        async with async_session_scope() as session:
            await repo.latest_report_rows(session, row_filter=capture_filter, filters={"sev": "high"})

        assert received_filters == {"sev": "high"}

    async def test_module_id_forwarded(self, test_db):
        """module_id is forwarded to latest_report for filtering."""
        _seed(_make_run(route_json=json.dumps({"selected_module": "vulnerability"})))
        rows = [{"id": 1}]
        repo = _repo_returning_report(rows)

        async with async_session_scope() as session:
            result = await repo.latest_report_rows(session, module_id="vulnerability")

        assert result.module_id == "vulnerability"

    async def test_offset_beyond_rows(self, test_db):
        """Offset past the end of rows returns empty slice."""
        _seed(_make_run())
        rows = [{"id": 0}, {"id": 1}]
        repo = _repo_returning_report(rows)

        async with async_session_scope() as session:
            result = await repo.latest_report_rows(session, offset=100, limit=10)

        assert result.total_rows == 2
        assert result.rows == []

    async def test_result_inherits_report_fields(self, test_db):
        """The rows result carries metadata from the parent report result."""
        _seed(_make_run())
        rows = [{"id": 0}]
        repo = _repo_returning_report(rows)

        async with async_session_scope() as session:
            result = await repo.latest_report_rows(session)

        assert result.run_id == "run-1"
        assert result.report_path == "/r.csv"
        assert result.summary_artifact_id == 2
        assert result.rows_artifact_id == 3


# ---------------------------------------------------------------------------
# ReportRepository.has_target_reports
# ---------------------------------------------------------------------------


class TestHasTargetReports:
    async def test_no_records_returns_false(self, test_db):
        repo = ReportRepository()

        async with async_session_scope() as session:
            assert await repo.has_target_reports(session) is False

    async def test_target_record_exists(self, test_db):
        """A target-scoped artifact record should make has_target_reports True."""
        _seed(
            ReportArtifactRecord(
                run_id="run-1",
                scope="target",
                system_name="prod-01",
                host="10.0.0.1",
                artifact_type="csv",
                path="/reports/target.csv",
            )
        )
        repo = ReportRepository()

        async with async_session_scope() as session:
            assert await repo.has_target_reports(session) is True

    async def test_fleet_only_returns_false(self, test_db):
        """Only fleet-scoped records should return False."""
        _seed(
            ReportArtifactRecord(
                run_id="run-1",
                scope="fleet",
                artifact_type="csv",
                path="/reports/fleet.csv",
            )
        )
        repo = ReportRepository()

        async with async_session_scope() as session:
            assert await repo.has_target_reports(session) is False

    async def test_with_module_id_matching(self, test_db):
        _seed(
            _make_run(
                run_id="run-vuln",
                route_json=json.dumps({"selected_module": "vulnerability"}),
            ),
            ReportArtifactRecord(
                run_id="run-vuln",
                scope="target",
                system_name="prod-01",
                host="10.0.0.1",
                artifact_type="csv",
                path="/reports/target.csv",
            ),
        )
        repo = ReportRepository()

        async with async_session_scope() as session:
            assert await repo.has_target_reports(session, module_id="vulnerability") is True

    async def test_with_module_id_not_matching(self, test_db):
        _seed(
            _make_run(
                run_id="run-comp",
                route_json=json.dumps({"selected_module": "compliance"}),
            ),
            ReportArtifactRecord(
                run_id="run-comp",
                scope="target",
                system_name="prod-01",
                host="10.0.0.1",
                artifact_type="csv",
                path="/reports/target.csv",
            ),
        )
        repo = ReportRepository()

        async with async_session_scope() as session:
            assert await repo.has_target_reports(session, module_id="vulnerability") is False

    async def test_with_module_id_no_completed_runs(self, test_db):
        _seed(_make_run(status="running", run_id="run-running"))
        repo = ReportRepository()

        async with async_session_scope() as session:
            assert await repo.has_target_reports(session, module_id="vulnerability") is False

    async def test_with_module_id_run_has_only_fleet_records(self, test_db):
        """module_id matches but no target-scoped records for that run."""
        _seed(
            _make_run(
                run_id="run-vuln",
                route_json=json.dumps({"selected_module": "vulnerability"}),
            ),
            ReportArtifactRecord(
                run_id="run-vuln",
                scope="fleet",
                artifact_type="csv",
                path="/reports/fleet.csv",
            ),
        )
        repo = ReportRepository()

        async with async_session_scope() as session:
            assert await repo.has_target_reports(session, module_id="vulnerability") is False


# ---------------------------------------------------------------------------
# ReportRepository.register_materialized_query
# ---------------------------------------------------------------------------


class TestRegisterMaterializedQuery:
    def test_register_and_use(self):
        repo = ReportRepository()

        async def fake_query(sess, target):
            return [{"criticality": "High", "last_scanned_at": "2025-01-01"}]

        repo.register_materialized_query(fake_query)
        assert repo._materialized_query is fake_query

    def test_overwrite_previous(self):
        async def q1(s, t):
            return []

        async def q2(s, t):
            return []

        repo = ReportRepository(materialized_query=q1)
        assert repo._materialized_query is q1
        repo.register_materialized_query(q2)
        assert repo._materialized_query is q2


# ---------------------------------------------------------------------------
# latest_report -- multiple runs iteration
# ---------------------------------------------------------------------------


class TestLatestReportMultipleRuns:
    async def test_skips_first_run_continues_to_second(self, test_db):
        """When the first run's bundle has no report_path, skip it and try the next."""
        _seed(
            _make_run(run_id="run-1", completed_at=datetime(2025, 1, 2, tzinfo=UTC)),
            _make_run(run_id="run-2", completed_at=datetime(2025, 1, 1, tzinfo=UTC)),
        )

        call_count = {"n": 0}

        def load_bundle_side_effect(session, run_id, target=None, records=None):
            call_count["n"] += 1
            if run_id == "run-1":
                # First run: no report_path -> repository skips it.
                return ReportArtifactBundle(storage="database", report_path=None)
            return _fleet_bundle()

        store = MagicMock(spec=ReportArtifactStore)
        store.list_run_records.return_value = []
        store.target_report_references.return_value = []
        store.load_run_bundle.side_effect = load_bundle_side_effect

        repo = ReportRepository(artifact_store=store)

        async with async_session_scope() as session:
            result = await repo.latest_report(session)

        assert result.run_id == "run-2"
        assert call_count["n"] == 2

    async def test_module_id_filter_skips_non_matching_runs(self, test_db):
        """module_id filter skips runs with different module identifiers."""
        _seed(
            _make_run(
                run_id="run-comp",
                route_json=json.dumps({"selected_module": "compliance"}),
                completed_at=datetime(2025, 1, 3, tzinfo=UTC),
            ),
            _make_run(
                run_id="run-vuln",
                route_json=json.dumps({"selected_module": "vulnerability"}),
                completed_at=datetime(2025, 1, 2, tzinfo=UTC),
            ),
        )
        repo = ReportRepository(artifact_store=_mock_store(_fleet_bundle()))

        async with async_session_scope() as session:
            result = await repo.latest_report(session, module_id="vulnerability")

        assert result.run_id == "run-vuln"
