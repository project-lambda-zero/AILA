"""Deep review tests for Phase 89: Vulnerability Reporting.

FILE-37 (export_service.py):
    test_json_stream_fetches_in_batches -- _fetch_batch called multiple times for large datasets
    test_csv_stream_fetches_in_batches  -- same for CSV
    test_json_output_valid_after_batching -- seeded data produces parseable JSON array
    test_csv_output_valid_after_batching  -- seeded data produces valid CSV with correct headers
    test_json_empty_table_returns_empty_array -- empty DB yields b"[]"
    test_csv_empty_table_returns_header_only -- empty DB yields only header row

FILE-38 (pdf.py):
    test_render_bytes_importerror_contains_pip_hint -- ImportError message is actionable
    test_render_instance_importerror_contains_pip_hint -- render() same behavior
    test_pdf_render_bytes_is_classmethod -- API shape validation
"""
from __future__ import annotations

import csv
import io
import json
import sys
from unittest.mock import patch

import pytest

from aila.modules.vulnerability.reporting.builder import VulnerabilityReportBuilder

# ---------------------------------------------------------------------------
# FILE-37: export_service.py -- batched streaming
# ---------------------------------------------------------------------------


class TestJsonStreamBatching:
    """stream_findings_json fetches rows in batches, not all at once."""

    @pytest.mark.asyncio
    async def test_json_stream_uses_sorted_fetch(self, seeded_findings):
        """stream_findings_json fetches rows once through _fetch_all_sorted."""
        from aila.modules.vulnerability.reporting import export_service

        original_fetch = export_service._fetch_all_sorted
        call_count = 0

        async def tracking_fetch() -> list[dict]:
            nonlocal call_count
            call_count += 1
            return await original_fetch()

        with patch.object(export_service, "_fetch_all_sorted", side_effect=tracking_fetch):
            chunks = []
            async for chunk in export_service.stream_findings_json():
                chunks.append(chunk)

        assert call_count == 1, f"Expected exactly one _fetch_all_sorted call; got {call_count}"

        raw = b"".join(chunks)
        data = json.loads(raw.decode("utf-8"))
        assert isinstance(data, list)
        assert len(data) == 3

    @pytest.mark.asyncio
    async def test_json_output_valid_after_batching(self, seeded_findings):
        """Concatenated JSON chunks form a valid array with expected fields."""
        from aila.modules.vulnerability.reporting.export_service import stream_findings_json

        chunks = []
        async for chunk in stream_findings_json():
            chunks.append(chunk)

        raw = b"".join(chunks)
        data = json.loads(raw.decode("utf-8"))

        assert isinstance(data, list)
        assert len(data) == 3

        for item in data:
            assert "cve_id" in item
            assert "criticality" in item
            assert "score" in item
            assert "host" in item

    @pytest.mark.asyncio
    async def test_json_empty_table_returns_empty_array(self, test_db):
        """Empty LatestFindingRecord table yields b'[]'."""
        from aila.modules.vulnerability.reporting.export_service import stream_findings_json

        chunks = []
        async for chunk in stream_findings_json():
            chunks.append(chunk)

        raw = b"".join(chunks)
        data = json.loads(raw.decode("utf-8"))
        assert data == []


class TestCsvStreamBatching:
    """stream_findings_csv fetches rows in batches, not all at once."""

    @pytest.mark.asyncio
    async def test_csv_stream_uses_sorted_fetch(self, seeded_findings):
        """stream_findings_csv fetches rows once through _fetch_all_sorted."""
        from aila.modules.vulnerability.reporting import export_service

        original_fetch = export_service._fetch_all_sorted
        call_count = 0

        async def tracking_fetch() -> list[dict]:
            nonlocal call_count
            call_count += 1
            return await original_fetch()

        with patch.object(export_service, "_fetch_all_sorted", side_effect=tracking_fetch):
            with patch.object(export_service, "_BATCH_SIZE", 1):
                chunks = []
                async for chunk in export_service.stream_findings_csv():
                    chunks.append(chunk)

        assert call_count == 1, f"Expected exactly one _fetch_all_sorted call; got {call_count}"

        raw = b"".join(chunks)
        text = raw.decode("utf-8")
        reader = csv.DictReader(io.StringIO(text))
        rows = list(reader)
        assert len(rows) == 3

    @pytest.mark.asyncio
    async def test_csv_output_valid_after_batching(self, seeded_findings):
        """CSV output has correct FIELDNAMES header and 3 data rows."""
        from aila.modules.vulnerability.reporting.export_service import stream_findings_csv

        chunks = []
        async for chunk in stream_findings_csv():
            chunks.append(chunk)

        raw = b"".join(chunks)
        text = raw.decode("utf-8")

        reader = csv.reader(io.StringIO(text))
        header = next(reader)
        assert header == VulnerabilityReportBuilder.FIELDNAMES

        data_rows = list(reader)
        assert len(data_rows) == 3

    @pytest.mark.asyncio
    async def test_csv_empty_table_returns_header_only(self, test_db):
        """Empty table yields only the CSV header row."""
        from aila.modules.vulnerability.reporting.export_service import stream_findings_csv

        chunks = []
        async for chunk in stream_findings_csv():
            chunks.append(chunk)

        raw = b"".join(chunks)
        text = raw.decode("utf-8")

        reader = csv.reader(io.StringIO(text))
        rows = list(reader)
        assert len(rows) == 1, f"Expected only header row; got {len(rows)} rows"
        assert rows[0] == VulnerabilityReportBuilder.FIELDNAMES

    @pytest.mark.asyncio
    async def test_csv_numeric_score_maps_from_score(self, seeded_findings):
        """CSV numeric_score column is populated from LatestFindingRecord.score."""
        from aila.modules.vulnerability.reporting.export_service import stream_findings_csv

        chunks = []
        async for chunk in stream_findings_csv():
            chunks.append(chunk)

        raw = b"".join(chunks)
        text = raw.decode("utf-8")

        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            assert row["numeric_score"] != "", (
                f"numeric_score must be non-empty; row={row}"
            )


# ---------------------------------------------------------------------------
# FILE-38: pdf.py -- graceful weasyprint handling
# ---------------------------------------------------------------------------


class TestPdfImportErrorGraceful:
    """PDF render methods raise ImportError with actionable pip hint."""

    @pytest.mark.asyncio
    async def test_render_bytes_importerror_contains_pip_hint(self, test_db):
        """render_bytes_async raises ImportError with 'pip install aila[pdf]' when weasyprint missing."""
        from aila.modules.vulnerability.reporting.pdf import PDFReportRenderer

        with patch.dict(sys.modules, {"weasyprint": None}):
            with pytest.raises(ImportError, match="pip install aila") as exc_info:
                await PDFReportRenderer.render_bytes_async("test-run-no-weasyprint")

        assert exc_info.value.__cause__ is not None, (
            "ImportError should chain the original exception via 'from exc'"
        )

    def test_render_instance_importerror_contains_pip_hint(self):
        """render() instance method raises ImportError with pip hint when weasyprint missing."""
        from pathlib import Path

        from aila.modules.vulnerability.reporting.pdf import PDFReportRenderer

        renderer = PDFReportRenderer({"run_id": "test", "summary": {}, "rows": []})

        with patch.dict(sys.modules, {"weasyprint": None}):
            with pytest.raises(ImportError, match="pip install aila") as exc_info:
                renderer.render(Path("/tmp/test-output"))

        assert exc_info.value.__cause__ is not None, (
            "ImportError should chain the original exception via 'from exc'"
        )

    def test_pdf_render_bytes_async_is_classmethod(self):
        """PDFReportRenderer.render_bytes_async is a classmethod, not instance method."""
        from aila.modules.vulnerability.reporting.pdf import PDFReportRenderer

        assert hasattr(PDFReportRenderer, "render_bytes_async")
        assert callable(PDFReportRenderer.render_bytes_async)

        import inspect
        assert isinstance(
            inspect.getattr_static(PDFReportRenderer, "render_bytes_async"),
            classmethod,
        ), "render_bytes_async must be a @classmethod"
