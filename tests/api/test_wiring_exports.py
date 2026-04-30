"""Wiring verification: export endpoint format validation (WIRE-09).

Tests prove that GET /vulnerability/reports/{run_id}?format= returns
correct Content-Type, Content-Disposition, and parseable content for
each supported export format.

Endpoints under test:
  GET /vulnerability/reports/{run_id}            -- summary (no format param)
  GET /vulnerability/reports/{run_id}?format=json -- streaming JSON array
  GET /vulnerability/reports/{run_id}?format=csv  -- streaming CSV attachment
  GET /vulnerability/reports/{run_id}?format=pdf  -- PDF (or 503 if weasyprint missing)
  GET /vulnerability/reports/{run_id}?format=xlsx -- invalid format -> 422
"""
from __future__ import annotations

import csv
import json
from io import StringIO

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.anyio


async def test_export_json_returns_valid_content(
    async_client: AsyncClient,
    admin_token: str,
    seeded_run,
    seeded_findings,
) -> None:
    """JSON export returns application/json with a valid JSON array of 3 findings."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    resp = await async_client.get(
        f"/vulnerability/reports/{seeded_run.id}",
        params={"format": "json"},
        headers=headers,
    )
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    assert resp.headers["content-type"].startswith("application/json")
    assert "content-disposition" in resp.headers
    assert seeded_run.id in resp.headers["content-disposition"]

    # Parse response body as JSON -- must be a valid JSON array
    data = json.loads(resp.content)
    assert isinstance(data, list), f"Expected JSON array, got {type(data)}"
    assert len(data) == 3, f"Expected 3 findings, got {len(data)}"

    # Verify each item has key fields
    for item in data:
        assert "cve_id" in item
        assert "criticality" in item


async def test_export_csv_returns_valid_content(
    async_client: AsyncClient,
    admin_token: str,
    seeded_run,
    seeded_findings,
) -> None:
    """CSV export returns text/csv with a header row + 3 data rows."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    resp = await async_client.get(
        f"/vulnerability/reports/{seeded_run.id}",
        params={"format": "csv"},
        headers=headers,
    )
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    assert resp.headers["content-type"].startswith("text/csv")
    assert "content-disposition" in resp.headers
    assert seeded_run.id in resp.headers["content-disposition"]

    # Parse response body as CSV
    text = resp.content.decode("utf-8")
    reader = csv.reader(StringIO(text))
    rows = list(reader)

    # First row is the header
    assert len(rows) >= 4, f"Expected header + 3 data rows, got {len(rows)} rows total"
    header = rows[0]
    assert "cve_id" in header
    assert "criticality" in header

    # 3 data rows (matching 3 seeded findings)
    data_rows = rows[1:]
    assert len(data_rows) == 3, f"Expected 3 data rows, got {len(data_rows)}"


async def test_export_pdf_returns_valid_content_or_503(
    async_client: AsyncClient,
    admin_token: str,
    seeded_run,
    seeded_findings,
) -> None:
    """PDF export returns application/pdf (if weasyprint installed) or 503."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    resp = await async_client.get(
        f"/vulnerability/reports/{seeded_run.id}",
        params={"format": "pdf"},
        headers=headers,
    )
    assert resp.status_code in (200, 503), f"Expected 200 or 503, got {resp.status_code}: {resp.text}"

    if resp.status_code == 200:
        assert resp.headers["content-type"].startswith("application/pdf")
        # PDF magic bytes
        assert resp.content[:5] == b"%PDF-"
    # 503 is acceptable -- weasyprint is an optional dependency


async def test_export_report_summary_default(
    async_client: AsyncClient,
    admin_token: str,
    seeded_run,
    seeded_findings,
) -> None:
    """GET /vulnerability/reports/{run_id} without format returns summary metadata."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    resp = await async_client.get(
        f"/vulnerability/reports/{seeded_run.id}",
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["run_id"] == seeded_run.id
    assert body["status"] == "completed"
    assert body["total_findings"] == 3
    assert "severity_breakdown" in body
    # severity_breakdown should have our seeded criticality levels
    breakdown = body["severity_breakdown"]
    assert breakdown.get("CRITICAL", 0) >= 1
    assert breakdown.get("HIGH", 0) >= 1
    assert breakdown.get("MEDIUM", 0) >= 1


async def test_export_invalid_format_returns_422(
    async_client: AsyncClient,
    admin_token: str,
    seeded_run,
) -> None:
    """Invalid export format returns 422."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    resp = await async_client.get(
        f"/vulnerability/reports/{seeded_run.id}",
        params={"format": "xlsx"},
        headers=headers,
    )
    assert resp.status_code == 422, f"Expected 422, got {resp.status_code}: {resp.text}"
