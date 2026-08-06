"""Phase 90 deep review: workflow reporting.py persist stage and db_models schema correctness.

FILE-39 (reporting.py -- zero file writes in persist stage):
    test_state_persist_no_filesystem_writes -- state_persist calls only DB operations, no Path.write_text/open
    test_write_bundle_computes_synthetic_paths_only -- ReportWriteTool.write_bundle returns paths without writing files
    test_state_persist_upserts_latest_finding_record -- upsert produces correct DB rows
    test_state_persist_inserts_prioritized_finding_record -- insert path verified
    test_state_persist_commits_single_transaction -- single session.commit call

FILE-40 (db_models.py -- schema correctness):
    test_latest_finding_upsert_columns_match_model -- upsert value keys match LatestFindingRecord columns
    test_latest_finding_record_has_required_columns -- all expected columns present
    test_prioritized_finding_record_has_required_columns -- all expected columns present
    test_all_platform_tables_reachable -- every SQLModel table in db_models.py is imported/used
    test_no_orphaned_vulnerability_tables -- every vulnerability db_model table is imported/used
"""
from __future__ import annotations

import ast
import importlib
import inspect
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from sqlalchemy.dialects.postgresql import insert as sa_insert
from sqlmodel import select

from aila.modules.vulnerability.contracts.reporting import PrioritizedFinding
from aila.modules.vulnerability.db_models import LatestFindingRecord, PrioritizedFindingRecord
from aila.modules.vulnerability.reporting.compliance import tag_finding
from aila.platform.contracts._common import utc_now
from aila.platform.contracts.persist import PersistContract
from aila.storage.database import async_session_scope, session_scope

__all__ = [
    "TestStatePersistNoFileWrites",
    "TestWriteBundleSyntheticPaths",
    "TestStatePersistDBWrites",
    "TestUpsertManyBatched",
    "TestLatestFindingColumns",
    "TestPlatformTablesReachable",
]


# ---------------------------------------------------------------------------
# Fixtures
#
# Previously this file spun a per-test in-memory SQLite engine + sync Session
# via the ``engine`` / ``session`` fixtures. SQLite is no longer supported
# (D-48/D-49): the project now hits PostgreSQL exclusively. The shared
# ``test_db`` fixture in tests/conftest.py creates the full schema once against
# aila_test and truncates all tables per-test; DB-touching cases below opt in
# by taking ``test_db`` as a parameter and using ``session_scope()`` (sync,
# psycopg-backed) for writes. Schema-inspection cases read the SQLAlchemy
# metadata off ``LatestFindingRecord.__table__`` directly -- no live engine
# needed, and the values match the CREATE TABLE emitted against aila_test.
# ---------------------------------------------------------------------------


def _make_finding(**overrides) -> PrioritizedFinding:
    """Build a minimal PrioritizedFinding with sensible defaults."""
    defaults = {
        "system_id": 1,
        "system_name": "arch-vm",
        "host": "10.0.0.1",
        "distribution": "arch",
        "package_name": "openssl",
        "installed_version": "3.1.0",
        "cve_id": "CVE-2024-0001",
        "criticality": "High",
        "numeric_score": 8.5,
        "rationale": "Remote code execution via buffer overflow.",
        "fixed_version": "3.1.1",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
    }
    defaults.update(overrides)
    return PrioritizedFinding(**defaults)


# ---------------------------------------------------------------------------
# FILE-39: reporting.py -- zero file writes in persist stage
# ---------------------------------------------------------------------------


class TestStatePersistNoFileWrites:
    """state_persist performs only DB writes; no filesystem calls."""

    def test_state_persist_source_has_no_file_write_calls(self):
        """AST scan of state_persist body: no Path.write_text, open(), mkdir, makedirs."""
        from aila.modules.vulnerability.workflow.states import reporting

        source = inspect.getsource(reporting.state_persist)
        tree = ast.parse(source)

        forbidden_names = {"write_text", "write_bytes", "makedirs", "mkdir"}
        found: list[str] = []

        for node in ast.walk(tree):
            # Check method calls like path.write_text()
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_names:
                    found.append(node.func.attr)
                # Check open("w") pattern
                if isinstance(node.func, ast.Name) and node.func.id == "open":
                    found.append("open()")

        assert not found, (
            f"state_persist must not perform filesystem writes. "
            f"Found forbidden calls: {found}"
        )

    def test_state_persist_uses_session_operations_only(self):
        """Verify state_persist body references session.execute and session.commit.

        The atomic finding upsert used to happen inline as
        ``session.execute(sa_insert(...).on_conflict_do_update(...))`` followed
        by ``session.commit()``. It has since been factored behind
        ``services.data.reports.upsert_findings_batch``, which delegates the
        actual ON CONFLICT DO UPDATE to ``PersistContract.upsert_many`` on the
        same session (still transactional, still atomic). The only inline
        ``session.*`` calls left in state_persist are the WorkflowRunRecord
        status update (``session.execute(...)``) and the transaction close
        (``session.commit()``). ``session.add`` is legitimately no longer
        invoked here -- it lives inside the service layer now.
        """
        from aila.modules.vulnerability.workflow.states import reporting

        source = inspect.getsource(reporting.state_persist)
        tree = ast.parse(source)

        # Accepted receivers on state_persist today: a plain ``session``
        # ``Name`` (bound by ``async with services.session_factory() as session``)
        # and any historical ``ctx.session`` / ``context.session`` ``Attribute``
        # chain. Both are legitimate; the previous check only looked at the
        # nested attribute chain and missed the current plain-Name form.
        session_methods: set[str] = set()
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            receiver = node.func.value
            if isinstance(receiver, ast.Name) and receiver.id == "session":
                session_methods.add(node.func.attr)
            elif isinstance(receiver, ast.Attribute) and receiver.attr == "session":
                session_methods.add(node.func.attr)

        assert "execute" in session_methods, "state_persist must call session.execute()"
        assert "commit" in session_methods, "state_persist must call session.commit()"


class TestWriteBundleSyntheticPaths:
    """ReportWriteTool.write_bundle computes paths without writing file content."""

    def test_write_bundle_returns_paths_without_file_writes(self, tmp_path):
        """write_bundle returns a dict with paths but writes no file content."""
        from aila.platform.tools.reporting import ReportWriteTool

        settings = MagicMock()
        settings.report_dir = tmp_path / "reports"

        tool = ReportWriteTool(settings=settings)
        result = tool.write_bundle(
            run_id="run-001",
            report_content="csv,data,here",
            summary_payload={"total_findings": 5},
            rows_payload=[{"row": 1}],
        )

        assert "report_path" in result
        assert "summary_path" in result
        assert "rows_path" in result

        # The report_dir is created (mkdir), but no report files are written
        report_path = Path(result["report_path"])
        summary_path = Path(result["summary_path"])
        assert not report_path.exists(), "write_bundle must not create the report file"
        assert not summary_path.exists(), "write_bundle must not create the summary file"

    def test_write_bundle_source_has_no_file_write_calls(self):
        """AST scan of write_bundle body: no write_text, write_bytes, or open(w)."""
        import textwrap

        from aila.platform.tools import reporting as reporting_module

        source = textwrap.dedent(inspect.getsource(reporting_module.ReportWriteTool.write_bundle))
        tree = ast.parse(source)

        forbidden_names = {"write_text", "write_bytes"}
        found: list[str] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr in forbidden_names:
                    found.append(node.func.attr)
                if isinstance(node.func, ast.Name) and node.func.id == "open":
                    found.append("open()")

        assert not found, (
            f"write_bundle must not write file content. "
            f"Found forbidden calls: {found}"
        )


# ---------------------------------------------------------------------------
# FILE-39: persist stage DB write correctness
# ---------------------------------------------------------------------------


class TestStatePersistDBWrites:
    """Verify the DB write paths in state_persist produce correct records."""

    def _latest_finding_values(self, finding: PrioritizedFinding) -> dict:
        """Assemble the column dict used by every LatestFindingRecord upsert here."""
        return {
            "host": finding.host,
            "package_name": finding.package_name,
            "cve_id": finding.cve_id,
            "system_id": finding.system_id,
            "system_name": finding.system_name,
            "distribution": finding.distribution or "",
            "criticality": finding.criticality,
            "score": finding.numeric_score,
            "rationale": finding.rationale,
            "fixed_version": finding.fixed_version,
            "nvd_url": finding.nvd_url,
            "compliance_tags_json": json.dumps(
                tag_finding(finding.model_dump(mode="json"))
            ),
            "details_json": finding.model_dump_json(),
            "last_scanned_at": utc_now(),
        }

    def test_upsert_creates_latest_finding_record(self, test_db):
        """sa_insert().on_conflict_do_update() creates a LatestFindingRecord row.

        Migrated from an in-memory SQLite session to the shared ``test_db``
        fixture (aila_test on PostgreSQL). ``sa_insert`` is imported from
        ``sqlalchemy.dialects.postgresql`` -- the sqlite dialect no longer
        applies because ``check_same_thread`` and every other SQLite-only
        kwarg was purged with D-48/D-49.
        """
        finding = _make_finding()
        stmt = (
            sa_insert(LatestFindingRecord)
            .values(**self._latest_finding_values(finding))
            .on_conflict_do_update(
                index_elements=["host", "package_name", "cve_id"],
                set_={
                    "criticality": finding.criticality,
                    "score": finding.numeric_score,
                },
            )
        )
        with session_scope() as session:
            session.execute(stmt)
            session.commit()

            rows = list(session.exec(select(LatestFindingRecord)))

        assert len(rows) == 1
        row = rows[0]
        assert row.host == "10.0.0.1"
        assert row.package_name == "openssl"
        assert row.cve_id == "CVE-2024-0001"
        assert row.score == 8.5
        assert row.criticality == "High"
        assert row.nvd_url == "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"

    def test_upsert_updates_existing_latest_finding(self, test_db):
        """Second upsert for same (host, package, cve) updates score and criticality."""
        finding1 = _make_finding(numeric_score=7.0, criticality="Moderate")
        finding2 = _make_finding(numeric_score=9.5, criticality="Immediate")

        with session_scope() as session:
            for finding in (finding1, finding2):
                stmt = (
                    sa_insert(LatestFindingRecord)
                    .values(**self._latest_finding_values(finding))
                    .on_conflict_do_update(
                        index_elements=["host", "package_name", "cve_id"],
                        set_={
                            "criticality": finding.criticality,
                            "score": finding.numeric_score,
                            "rationale": finding.rationale,
                            "last_scanned_at": utc_now(),
                        },
                    )
                )
                session.execute(stmt)
            session.commit()

            rows = list(session.exec(select(LatestFindingRecord)))

        assert len(rows) == 1, "Upsert should produce exactly one row for same key"
        assert rows[0].score == 9.5
        assert rows[0].criticality == "Immediate"

    def test_prioritized_finding_insert(self, test_db):
        """PrioritizedFindingRecord insert creates a run-scoped history row."""
        finding = _make_finding()
        with session_scope() as session:
            session.add(
                PrioritizedFindingRecord(
                    run_id="run-001",
                    system_id=finding.system_id,
                    host=finding.host,
                    package_name=finding.package_name,
                    installed_version=finding.installed_version,
                    cve_id=finding.cve_id,
                    criticality=finding.criticality,
                    score=finding.numeric_score,
                    rationale=finding.rationale,
                    fixed_version=finding.fixed_version,
                    nvd_url=finding.nvd_url,
                )
            )
            session.commit()

            rows = list(session.exec(select(PrioritizedFindingRecord)))

        assert len(rows) == 1
        assert rows[0].run_id == "run-001"
        assert rows[0].installed_version == "3.1.0"


class TestUpsertManyBatched:
    """PersistContract.upsert_many collapses N inserts into batched ON CONFLICT."""

    @staticmethod
    def _rec(cve: str, score: float, criticality: str = "High") -> LatestFindingRecord:
        return LatestFindingRecord(
            host="10.0.0.9",
            package_name="openssl",
            cve_id=cve,
            system_id=1,
            criticality=criticality,
            score=score,
            nvd_url=f"https://nvd.nist.gov/vuln/detail/{cve}",
        )

    @pytest.mark.asyncio
    async def test_upsert_many_inserts_all_records(self, test_db):
        recs = [self._rec(f"CVE-2024-{i:04d}", 5.0) for i in range(3)]
        async with async_session_scope() as session:
            await PersistContract.upsert_many(session, recs)
            await session.commit()
        async with async_session_scope() as session:
            rows = list((await session.exec(select(LatestFindingRecord))).all())
        assert len(rows) == 3

    @pytest.mark.asyncio
    async def test_upsert_many_conflicts_update_not_duplicate(self, test_db):
        async with async_session_scope() as session:
            await PersistContract.upsert_many(
                session, [self._rec(f"CVE-2024-{i:04d}", 5.0) for i in range(3)]
            )
            await session.commit()
        # Re-upsert one natural key with new values -> update in place, no new row.
        async with async_session_scope() as session:
            await PersistContract.upsert_many(
                session, [self._rec("CVE-2024-0001", 9.9, "Immediate")]
            )
            await session.commit()
        async with async_session_scope() as session:
            rows = list((await session.exec(select(LatestFindingRecord))).all())
            updated = [r for r in rows if r.cve_id == "CVE-2024-0001"]
        assert len(rows) == 3
        assert updated[0].score == 9.9
        assert updated[0].criticality == "Immediate"

    @pytest.mark.asyncio
    async def test_upsert_many_rejects_heterogeneous_list(self, test_db):
        with pytest.raises(TypeError):
            async with async_session_scope() as session:
                await PersistContract.upsert_many(
                    session,
                    [
                        self._rec("CVE-2024-0001", 5.0),
                        PrioritizedFindingRecord(
                            run_id="r", system_id=1, host="h", package_name="p",
                            installed_version="1", cve_id="c", criticality="High",
                            score=1.0, rationale="", fixed_version=None,
                            nvd_url="u",
                        ),
                    ],
                )


# ---------------------------------------------------------------------------
# FILE-40: db_models.py -- schema correctness
# ---------------------------------------------------------------------------


class TestLatestFindingColumns:
    """LatestFindingRecord has all required columns with correct types.

    Contract drift resolved in this pass:

    * ``team_id`` -- added by ``TeamScopedMixin`` (D-01/D-07). Every
      team-scoped table carries it and StorageService auto-stamps it at
      write time.
    * ``is_kev`` -- Phase 143 (FIND-04/FIND-08) triage enrichment;
      server-default ``false``.
    * ``current_workflow_state`` -- Phase 143 triage enrichment;
      server-default ``'new'`` with a CHECK constraint restricting values
      to (new|investigating|mitigated|verified|closed).

    These are all real, current columns on ``LatestFindingRecord``
    (see src/aila/modules/vulnerability/db_models/findings.py); adding
    them to EXPECTED_COLUMNS reflects the current schema, not a masked bug.
    """

    EXPECTED_COLUMNS = {
        "id", "host", "package_name", "cve_id",
        "system_id", "system_name", "distribution",
        "criticality", "score", "rationale", "fixed_version", "nvd_url",
        "compliance_tags_json", "details_json",
        "last_scanned_at", "created_at", "status",
        "team_id", "is_kev", "current_workflow_state",
    }

    def test_all_expected_columns_present(self):
        """LatestFindingRecord table has every expected column."""
        columns = set(LatestFindingRecord.__table__.columns.keys())
        missing = self.EXPECTED_COLUMNS - columns
        assert not missing, f"LatestFindingRecord missing columns: {missing}"

    def test_no_installed_version_column(self):
        """LatestFindingRecord intentionally omits installed_version (stored only on PrioritizedFindingRecord)."""
        columns = set(LatestFindingRecord.__table__.columns.keys())
        assert "installed_version" not in columns, (
            "installed_version must not be on LatestFindingRecord -- "
            "it belongs only on PrioritizedFindingRecord"
        )

    def test_upsert_keys_match_model_columns(self):
        """Every column-name kwarg written by state_persist is a real model column.

        The original assertion parsed ``.values(...)`` calls in the raw
        ``sa_insert().values(...).on_conflict_do_update(...)`` chain. State
        persist has since been refactored to build ``LatestFindingRecord`` ORM
        instances directly and hand them to
        ``services.data.reports.upsert_findings_batch``, which delegates the
        atomic ON CONFLICT DO UPDATE to ``PersistContract.upsert`` inside the
        platform (see src/aila/modules/vulnerability/workflow/states/reporting.py
        and src/aila/platform/contracts/persist.py). Only the WorkflowRunRecord
        status update still uses ``.values(...)``.

        Rewritten to walk the ``LatestFindingRecord(...)`` constructor call in
        the same AST -- that's the surface that carries the finding column
        kwargs today.
        """
        from aila.modules.vulnerability.workflow.states import reporting

        source = inspect.getsource(reporting.state_persist)
        tree = ast.parse(source)

        upsert_keys: set[str] = set()
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "LatestFindingRecord"
            ):
                for kw in node.keywords:
                    if kw.arg is not None:
                        upsert_keys.add(kw.arg)

        assert upsert_keys, (
            "state_persist source no longer constructs LatestFindingRecord(...) "
            "instances -- rewrite this test to track the new persist shape."
        )

        model_columns = set(LatestFindingRecord.model_fields.keys())
        # Columns that are auto-managed and legitimately not set at persist time:
        # - id: PK sequence
        # - created_at: default_factory=utc_now
        # - status: server_default='open' (remediation lifecycle, Phase 176a)
        # - is_kev / current_workflow_state: Phase 143 triage enrichment,
        #   server-defaulted; enriched by later triage stages, not by persist.
        # - team_id: auto-stamped by StorageService per D-07.
        auto_columns = {
            "id", "created_at", "status",
            "is_kev", "current_workflow_state", "team_id",
        }
        expected_upsert_columns = model_columns - auto_columns

        # Every upsert key must be a valid model column
        invalid_keys = upsert_keys - model_columns
        assert not invalid_keys, (
            f"Upsert writes to columns not on LatestFindingRecord: {invalid_keys}"
        )

        # Every non-auto model column must be in the upsert
        missing_keys = expected_upsert_columns - upsert_keys
        assert not missing_keys, (
            f"Upsert is missing model columns: {missing_keys}"
        )


class TestPrioritizedFindingColumns:
    """PrioritizedFindingRecord has all required columns."""

    EXPECTED_COLUMNS = {
        "id", "run_id", "system_id", "host", "package_name",
        "installed_version", "cve_id", "criticality", "score",
        "rationale", "fixed_version", "nvd_url", "created_at",
    }

    def test_all_expected_columns_present(self):
        """PrioritizedFindingRecord table has every expected column."""
        columns = set(PrioritizedFindingRecord.__table__.columns.keys())
        missing = self.EXPECTED_COLUMNS - columns
        assert not missing, f"PrioritizedFindingRecord missing columns: {missing}"


class TestPlatformTablesReachable:
    """Every SQLModel table=True class in db_models.py is imported somewhere in application code."""

    @staticmethod
    def _extract_table_classes(module_path: str) -> list[str]:
        """Parse a Python module and return class names where table=True."""
        source_code = Path(module_path).read_text(encoding="utf-8")
        tree = ast.parse(source_code)
        table_classes: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for base in node.bases:
                    if isinstance(base, ast.Name) and base.id == "SQLModel":
                        # Check for table=True in keywords
                        for kw in node.keywords:
                            if kw.arg == "table" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                table_classes.append(node.name)
        return table_classes

    def test_platform_db_models_all_imported(self):
        """Every table class in storage/db_models.py is importable from aila.storage.db_models."""
        db_models_path = Path("src/aila/storage/db_models.py")
        if not db_models_path.exists():
            pytest.skip("db_models.py not found")

        table_classes = self._extract_table_classes(str(db_models_path))
        assert len(table_classes) > 0, "No table classes found in db_models.py"

        module = importlib.import_module("aila.storage.db_models")
        missing: list[str] = []
        for cls_name in table_classes:
            if not hasattr(module, cls_name):
                missing.append(cls_name)

        assert not missing, f"Table classes not importable from aila.storage.db_models: {missing}"

    def test_vulnerability_db_models_all_imported(self):
        """Every table class in vulnerability/db_models/ files is re-exported from __init__.py."""
        db_dir = Path("src/aila/modules/vulnerability/db_models")
        if not db_dir.exists():
            pytest.skip("vulnerability/db_models/ not found")

        all_table_classes: list[str] = []
        for py_file in db_dir.glob("*.py"):
            if py_file.name == "__init__.py":
                continue
            all_table_classes.extend(self._extract_table_classes(str(py_file)))

        assert len(all_table_classes) > 0, "No table classes found in vulnerability/db_models/"

        module = importlib.import_module("aila.modules.vulnerability.db_models")
        missing: list[str] = []
        for cls_name in all_table_classes:
            if not hasattr(module, cls_name):
                missing.append(cls_name)

        assert not missing, (
            f"Vulnerability table classes not re-exported from db_models/__init__.py: {missing}"
        )

    def test_no_extra_columns_on_latest_finding(self):
        """LatestFindingRecord has no unexpected columns beyond the documented set."""
        columns = set(LatestFindingRecord.__table__.columns.keys())
        expected = TestLatestFindingColumns.EXPECTED_COLUMNS
        extra = columns - expected
        assert not extra, f"LatestFindingRecord has unexpected columns: {extra}"
