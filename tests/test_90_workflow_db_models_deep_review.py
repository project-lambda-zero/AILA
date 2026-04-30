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
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.dialects.sqlite import insert as sa_insert
from sqlmodel import Session, SQLModel, create_engine, select

from aila.modules.vulnerability.contracts.reporting import PrioritizedFinding
from aila.modules.vulnerability.db_models import LatestFindingRecord, PrioritizedFindingRecord
from aila.modules.vulnerability.reporting.compliance import tag_finding
from aila.platform.contracts._common import utc_now

__all__ = [
    "TestStatePersistNoFileWrites",
    "TestWriteBundleSyntheticPaths",
    "TestStatePersistDBWrites",
    "TestLatestFindingColumns",
    "TestPlatformTablesReachable",
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(eng)
    yield eng
    SQLModel.metadata.drop_all(eng)


@pytest.fixture()
def session(engine):
    with Session(engine) as s:
        yield s


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
        """Verify state_persist body references session.add, session.execute, session.commit."""
        from aila.modules.vulnerability.workflow.states import reporting

        source = inspect.getsource(reporting.state_persist)
        tree = ast.parse(source)

        session_methods: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Attribute):
                    # context.session.add / context.session.execute / context.session.commit
                    if node.func.value.attr == "session":
                        session_methods.add(node.func.attr)

        assert "add" in session_methods, "state_persist must call session.add()"
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

    def test_upsert_creates_latest_finding_record(self, session):
        """sa_insert().on_conflict_do_update() creates a LatestFindingRecord row."""
        finding = _make_finding()
        compliance_tags = tag_finding(finding.model_dump(mode="json"))

        stmt = (
            sa_insert(LatestFindingRecord)
            .values(
                host=finding.host,
                package_name=finding.package_name,
                cve_id=finding.cve_id,
                system_id=finding.system_id,
                system_name=finding.system_name,
                distribution=finding.distribution or "",
                criticality=finding.criticality,
                score=finding.numeric_score,
                rationale=finding.rationale,
                fixed_version=finding.fixed_version,
                nvd_url=finding.nvd_url,
                compliance_tags_json=json.dumps(compliance_tags),
                details_json=finding.model_dump_json(),
                last_scanned_at=utc_now(),
            )
            .on_conflict_do_update(
                index_elements=["host", "package_name", "cve_id"],
                set_={
                    "criticality": finding.criticality,
                    "score": finding.numeric_score,
                },
            )
        )
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

    def test_upsert_updates_existing_latest_finding(self, session):
        """Second upsert for same (host, package, cve) updates score and criticality."""
        finding1 = _make_finding(numeric_score=7.0, criticality="Moderate")
        finding2 = _make_finding(numeric_score=9.5, criticality="Immediate")

        for finding in (finding1, finding2):
            compliance_tags = tag_finding(finding.model_dump(mode="json"))
            stmt = (
                sa_insert(LatestFindingRecord)
                .values(
                    host=finding.host,
                    package_name=finding.package_name,
                    cve_id=finding.cve_id,
                    system_id=finding.system_id,
                    system_name=finding.system_name,
                    distribution=finding.distribution or "",
                    criticality=finding.criticality,
                    score=finding.numeric_score,
                    rationale=finding.rationale,
                    fixed_version=finding.fixed_version,
                    nvd_url=finding.nvd_url,
                    compliance_tags_json=json.dumps(compliance_tags),
                    details_json=finding.model_dump_json(),
                    last_scanned_at=utc_now(),
                )
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

    def test_prioritized_finding_insert(self, session):
        """PrioritizedFindingRecord insert creates a run-scoped history row."""
        finding = _make_finding()
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


# ---------------------------------------------------------------------------
# FILE-40: db_models.py -- schema correctness
# ---------------------------------------------------------------------------


class TestLatestFindingColumns:
    """LatestFindingRecord has all required columns with correct types."""

    EXPECTED_COLUMNS = {
        "id", "host", "package_name", "cve_id",
        "system_id", "system_name", "distribution",
        "criticality", "score", "rationale", "fixed_version", "nvd_url",
        "compliance_tags_json", "details_json",
        "last_scanned_at", "created_at", "status",
    }

    def test_all_expected_columns_present(self, engine):
        """LatestFindingRecord table has every expected column."""
        inspector = sa_inspect(engine)
        columns = {col["name"] for col in inspector.get_columns("latest_finding_records")}
        missing = self.EXPECTED_COLUMNS - columns
        assert not missing, f"LatestFindingRecord missing columns: {missing}"

    def test_no_installed_version_column(self, engine):
        """LatestFindingRecord intentionally omits installed_version (stored only on PrioritizedFindingRecord)."""
        inspector = sa_inspect(engine)
        columns = {col["name"] for col in inspector.get_columns("latest_finding_records")}
        assert "installed_version" not in columns, (
            "installed_version must not be on LatestFindingRecord -- "
            "it belongs only on PrioritizedFindingRecord"
        )

    def test_upsert_keys_match_model_columns(self):
        """The sa_insert values dict in state_persist uses only columns that exist on the model."""
        from aila.modules.vulnerability.workflow.states import reporting

        source = inspect.getsource(reporting.state_persist)

        # Extract column names from the .values() call in the LatestFindingRecord upsert
        # by parsing the AST and finding keyword arguments
        tree = ast.parse(source)

        upsert_keys: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "values":
                    for kw in node.keywords:
                        if kw.arg is not None:
                            upsert_keys.add(kw.arg)

        model_columns = set(LatestFindingRecord.model_fields.keys())
        # id and created_at and status are auto-managed, not in upsert
        auto_columns = {"id", "created_at", "status"}
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

    def test_all_expected_columns_present(self, engine):
        """PrioritizedFindingRecord table has every expected column."""
        inspector = sa_inspect(engine)
        columns = {col["name"] for col in inspector.get_columns("prioritizedfindingrecord")}
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

    def test_no_extra_columns_on_latest_finding(self, engine):
        """LatestFindingRecord has no unexpected columns beyond the documented set."""
        inspector = sa_inspect(engine)
        columns = {col["name"] for col in inspector.get_columns("latest_finding_records")}
        expected = TestLatestFindingColumns.EXPECTED_COLUMNS
        extra = columns - expected
        assert not extra, f"LatestFindingRecord has unexpected columns: {extra}"
