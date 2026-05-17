"""Cross-cutting verification: export format correctness (XCUT-07).

Proves JSON, CSV, and PDF exports produce valid, correctly structured output:
  1. JSON: valid JSON array with all expected schema fields
  2. CSV: correct FIELDNAMES header, correct row count, parseable rows
  3. PDF: renders successfully OR raises ImportError with clear message
  4. Empty data: JSON yields [], CSV yields header-only

All tests operate at the generator level (no HTTP) to isolate export logic
from router concerns.  HTTP-level export tests exist in test_57_export.py.
"""
from __future__ import annotations

import csv
import io
import json

import pytest

from aila.modules.vulnerability.reporting.builder import VulnerabilityReportBuilder


def _weasyprint_available() -> bool:
    """Return True if weasyprint imports successfully."""
    try:
        import weasyprint  # noqa: F401
    except (ImportError, OSError):
        return False
    return True


# ---------------------------------------------------------------------------
# JSON export correctness
# ---------------------------------------------------------------------------


class TestJsonExportCorrectness:
    """stream_findings_json produces valid JSON with all expected fields."""

    @pytest.mark.asyncio
    async def test_json_is_valid_json_array(self, seeded_findings):
        """Concatenated chunks form a valid JSON array."""
        from aila.modules.vulnerability.reporting.export_service import stream_findings_json

        chunks = []
        async for chunk in stream_findings_json():
            chunks.append(chunk)

        raw = b"".join(chunks)
        data = json.loads(raw.decode("utf-8"))
        assert isinstance(data, list), f"Expected JSON array, got {type(data).__name__}"

    @pytest.mark.asyncio
    async def test_json_has_all_expected_fields(self, seeded_findings):
        """Each JSON row contains the expected schema fields from LatestFindingRecord."""
        from aila.modules.vulnerability.reporting.export_service import stream_findings_json

        chunks = []
        async for chunk in stream_findings_json():
            chunks.append(chunk)

        data = json.loads(b"".join(chunks).decode("utf-8"))
        assert len(data) == 3, f"Expected 3 rows, got {len(data)}"

        expected_fields = {
            "system_name", "host", "package_name", "cve_id",
            "criticality", "score", "nvd_url",
        }
        for row in data:
            missing = expected_fields - set(row.keys())
            assert not missing, f"Missing fields in JSON row: {missing}"

    @pytest.mark.asyncio
    async def test_json_field_values_match_seeded_data(self, seeded_findings):
        """JSON field values correspond to seeded LatestFindingRecord data."""
        from aila.modules.vulnerability.reporting.export_service import stream_findings_json

        chunks = []
        async for chunk in stream_findings_json():
            chunks.append(chunk)

        data = json.loads(b"".join(chunks).decode("utf-8"))
        cve_ids = {row["cve_id"] for row in data}
        assert cve_ids == {"CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003"}

        # Verify score values are numeric
        for row in data:
            assert isinstance(row["score"], (int, float)), (
                f"score should be numeric, got {type(row['score']).__name__}"
            )

    @pytest.mark.asyncio
    async def test_json_empty_yields_empty_array(self, test_db):
        """Empty LatestFindingRecord table yields valid JSON: []."""
        from aila.modules.vulnerability.reporting.export_service import stream_findings_json

        chunks = []
        async for chunk in stream_findings_json():
            chunks.append(chunk)

        data = json.loads(b"".join(chunks).decode("utf-8"))
        assert data == [], f"Expected empty array for empty table, got {data!r}"


# ---------------------------------------------------------------------------
# CSV export correctness
# ---------------------------------------------------------------------------


class TestCsvExportCorrectness:
    """stream_findings_csv produces parseable CSV with correct structure."""

    @pytest.mark.asyncio
    async def test_csv_header_matches_fieldnames(self, seeded_findings):
        """CSV header row matches VulnerabilityReportBuilder.FIELDNAMES exactly."""
        from aila.modules.vulnerability.reporting.export_service import stream_findings_csv

        chunks = []
        async for chunk in stream_findings_csv():
            chunks.append(chunk)

        text = b"".join(chunks).decode("utf-8")
        reader = csv.reader(io.StringIO(text))
        header = next(reader)
        assert header == VulnerabilityReportBuilder.FIELDNAMES, (
            f"CSV header mismatch.\nExpected: {VulnerabilityReportBuilder.FIELDNAMES}\nGot: {header}"
        )

    @pytest.mark.asyncio
    async def test_csv_row_count_matches_seeded_data(self, seeded_findings):
        """CSV data rows match the number of seeded findings."""
        from aila.modules.vulnerability.reporting.export_service import stream_findings_csv

        chunks = []
        async for chunk in stream_findings_csv():
            chunks.append(chunk)

        text = b"".join(chunks).decode("utf-8")
        reader = csv.DictReader(io.StringIO(text))
        rows = list(reader)
        assert len(rows) == 3, f"Expected 3 CSV data rows, got {len(rows)}"

    @pytest.mark.asyncio
    async def test_csv_rows_are_parseable(self, seeded_findings):
        """Every CSV row is parseable and has the correct number of columns."""
        from aila.modules.vulnerability.reporting.export_service import stream_findings_csv

        chunks = []
        async for chunk in stream_findings_csv():
            chunks.append(chunk)

        text = b"".join(chunks).decode("utf-8")
        reader = csv.reader(io.StringIO(text))
        header = next(reader)
        expected_col_count = len(header)

        for i, row in enumerate(reader):
            assert len(row) == expected_col_count, (
                f"Row {i} has {len(row)} columns, expected {expected_col_count}"
            )

    @pytest.mark.asyncio
    async def test_csv_cve_ids_match_seeded_data(self, seeded_findings):
        """CSV cve_id column values match seeded data."""
        from aila.modules.vulnerability.reporting.export_service import stream_findings_csv

        chunks = []
        async for chunk in stream_findings_csv():
            chunks.append(chunk)

        text = b"".join(chunks).decode("utf-8")
        reader = csv.DictReader(io.StringIO(text))
        cve_ids = {row["cve_id"] for row in reader}
        assert cve_ids == {"CVE-2023-0001", "CVE-2023-0002", "CVE-2023-0003"}

    @pytest.mark.asyncio
    async def test_csv_numeric_score_populated(self, seeded_findings):
        """CSV numeric_score column is populated (mapped from score)."""
        from aila.modules.vulnerability.reporting.export_service import stream_findings_csv

        chunks = []
        async for chunk in stream_findings_csv():
            chunks.append(chunk)

        text = b"".join(chunks).decode("utf-8")
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            assert row["numeric_score"] != "", (
                f"numeric_score must be populated; row cve_id={row['cve_id']}"
            )

    @pytest.mark.asyncio
    async def test_csv_empty_yields_header_only(self, test_db):
        """Empty LatestFindingRecord table yields only the header row."""
        from aila.modules.vulnerability.reporting.export_service import stream_findings_csv

        chunks = []
        async for chunk in stream_findings_csv():
            chunks.append(chunk)

        text = b"".join(chunks).decode("utf-8")
        reader = csv.reader(io.StringIO(text))
        rows = list(reader)
        assert len(rows) == 1, f"Expected only header row for empty table, got {len(rows)}"
        assert rows[0] == VulnerabilityReportBuilder.FIELDNAMES


# ---------------------------------------------------------------------------
# PDF export correctness
# ---------------------------------------------------------------------------


class TestPdfExportCorrectness:
    """PDF export either succeeds (weasyprint installed) or fails clearly."""

    @pytest.mark.asyncio
    async def test_pdf_renders_or_raises_import_error(self, seeded_findings):
        """PDFReportRenderer.render_bytes_async either returns PDF bytes or raises ImportError."""
        from aila.modules.vulnerability.reporting.pdf import PDFReportRenderer

        if _weasyprint_available():
            result = await PDFReportRenderer.render_bytes_async("run-001")
            assert isinstance(result, bytes), f"Expected bytes, got {type(result).__name__}"
            assert result[:5] == b"%PDF-", (
                f"Expected PDF magic bytes, got {result[:10]!r}"
            )
        else:
            with pytest.raises(ImportError, match="PDF rendering requires optional"):
                await PDFReportRenderer.render_bytes_async("run-001")
    @pytest.mark.asyncio
    async def test_pdf_import_error_message_is_helpful(self, test_db):
        """ImportError message tells user to install aila[pdf]."""
        if _weasyprint_available():
            pytest.skip("weasyprint is installed -- cannot test ImportError path")

        from aila.modules.vulnerability.reporting.pdf import PDFReportRenderer

        with pytest.raises(ImportError, match=r"pip install aila\[pdf\]"):
            await PDFReportRenderer.render_bytes_async("run-001")
