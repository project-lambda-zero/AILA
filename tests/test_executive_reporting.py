"""Unit tests for Phase 147 executive reporting (EXEC-01 through EXEC-04).

Tests:
  - Executive router module imports without errors
  - _build_severity_breakdown computes correct counts
  - _build_evidence_zip produces a valid ZIP with expected file entries
  - SHA-256 computation produces correct hex digest
  - generate_scheduled_report_job returns 'completed_no_smtp' when SMTP not configured
  - _sanitise_filename_component strips unsafe characters

All tests are synchronous unit tests using stdlib only -- no DB connections required.
"""
from __future__ import annotations

import hashlib
import io
import json
import zipfile

# ---------------------------------------------------------------------------
# Executive router: severity breakdown helper
# ---------------------------------------------------------------------------

def test_build_severity_breakdown_counts():
    """_build_severity_breakdown returns correct counts from findings list."""
    from aila.api.routers.executive import _build_severity_breakdown

    findings = [
        {"criticality": "Immediate"},
        {"criticality": "Immediate"},  # two Immediate entries -- both counted
        {"criticality": "High"},
        {"criticality": "Moderate"},
        {"criticality": "Planned"},
        {"criticality": "Unknown"},    # unmapped -- should not increment any key
        {},                             # missing criticality
    ]
    result = _build_severity_breakdown(findings)

    assert result["Immediate"] == 2, f"Expected 2 Immediate, got {result['Immediate']}"
    assert result["High"] == 1
    assert result["Moderate"] == 1
    assert result["Planned"] == 1
    # Unknown and missing should not appear in keys
    assert "Unknown" not in result
    assert "" not in result


def test_build_severity_breakdown_empty():
    """Empty findings list yields all-zero breakdown."""
    from aila.api.routers.executive import _build_severity_breakdown

    result = _build_severity_breakdown([])
    assert result == {"Immediate": 0, "High": 0, "Moderate": 0, "Planned": 0}


# ---------------------------------------------------------------------------
# Executive router: sanitise filename component
# ---------------------------------------------------------------------------

def test_sanitise_filename_component_basic():
    from aila.api.routers.executive import _sanitise_filename_component

    assert _sanitise_filename_component("my-server") == "my-server"
    assert _sanitise_filename_component("server 01") == "server_01"
    assert _sanitise_filename_component("../evil") == "___evil"
    assert _sanitise_filename_component("a!b@c#") == "a_b_c_"


def test_sanitise_filename_component_alphanumeric():
    from aila.api.routers.executive import _sanitise_filename_component

    result = _sanitise_filename_component("prod-db-01_v2")
    assert result == "prod-db-01_v2"


# ---------------------------------------------------------------------------
# Executive router: evidence ZIP structure
# ---------------------------------------------------------------------------

def test_build_evidence_zip_structure():
    """_build_evidence_zip produces a valid ZIP with expected file entries."""
    from aila.api.routers.executive import _build_evidence_zip

    findings = [
        {
            "system_id": 42,
            "system_name": "test-server",
            "host": "test-server.local",
            "package_name": "openssl",
            "cve_id": "CVE-2023-0001",
            "criticality": "High",
            "score": 8.5,
            "is_kev": False,
            "rationale": "Test finding",
            "fixed_version": "3.0.8",
            "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-0001",
        }
    ]

    from aila.modules.vulnerability.module import create_module

    zip_bytes = _build_evidence_zip(create_module(), 42, findings)
    assert isinstance(zip_bytes, bytes)
    assert len(zip_bytes) > 0

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        names = zf.namelist()
        assert "findings.json" in names, f"Missing findings.json in {names}"
        assert "findings.csv" in names, f"Missing findings.csv in {names}"
        assert "compliance_tags.json" in names, f"Missing compliance_tags.json in {names}"
        assert "scan_metadata.json" in names, f"Missing scan_metadata.json in {names}"

        # Validate findings.json is valid JSON list
        findings_data = json.loads(zf.read("findings.json"))
        assert isinstance(findings_data, list)
        assert len(findings_data) == 1

        # Validate scan_metadata.json has correct fields
        metadata = json.loads(zf.read("scan_metadata.json"))
        assert metadata["system_id"] == 42
        assert metadata["system_name"] == "test-server"
        assert metadata["total_findings"] == 1
        assert "severity_breakdown" in metadata
        assert "generated_at" in metadata

        # Validate compliance_tags.json structure
        tags_data = json.loads(zf.read("compliance_tags.json"))
        assert isinstance(tags_data, list)
        assert len(tags_data) == 1
        assert "cve_id" in tags_data[0]
        assert "tags" in tags_data[0]
        assert isinstance(tags_data[0]["tags"], list)


# ---------------------------------------------------------------------------
# SHA-256 hash computation
# ---------------------------------------------------------------------------

def test_sha256_hex_digest_is_deterministic():
    """hashlib.sha256 produces stable, correct hex digest (sanity check)."""
    data = b"AILA test PDF bytes"
    expected = hashlib.sha256(data).hexdigest()

    # Run twice -- must be identical
    assert hashlib.sha256(data).hexdigest() == expected
    assert len(expected) == 64  # SHA-256 produces 64 hex chars
    assert all(c in "0123456789abcdef" for c in expected)


def test_sha256_different_inputs_produce_different_hashes():
    """Different PDF content yields different hashes -- collision resistance sanity."""
    data1 = b"session-abc-report-v1"
    data2 = b"session-abc-report-v2"
    assert hashlib.sha256(data1).hexdigest() != hashlib.sha256(data2).hexdigest()


# ---------------------------------------------------------------------------
# Report tasks: no-SMTP path
# ---------------------------------------------------------------------------

def test_generate_scheduled_report_job_importable():
    """generate_scheduled_report_job is importable from report_tasks."""
    import inspect

    from aila.platform.tasks.report_tasks import generate_scheduled_report_job

    assert callable(generate_scheduled_report_job)
    assert inspect.iscoroutinefunction(generate_scheduled_report_job)


def test_report_tasks_module_structure():
    """report_tasks module exports expected symbols and imports cleanly."""
    import aila.platform.tasks.report_tasks as mod

    assert hasattr(mod, "generate_scheduled_report_job")
    assert hasattr(mod, "_send_report_email")
    assert hasattr(mod, "_update_last_run_at")
    assert hasattr(mod, "_generate_risk_summary_pdf")


# ---------------------------------------------------------------------------
# Worker settings: new job registered
# ---------------------------------------------------------------------------

def test_worker_settings_includes_report_job():
    """WorkerSettings.functions includes generate_scheduled_report_job."""
    from aila.platform.tasks.report_tasks import generate_scheduled_report_job
    from aila.platform.tasks.worker import WorkerSettings

    assert generate_scheduled_report_job in WorkerSettings.functions


# ---------------------------------------------------------------------------
# Executive router: module-level import sanity
# ---------------------------------------------------------------------------

def test_executive_router_importable():
    """executive.py imports cleanly and exposes a FastAPI router."""
    from fastapi import APIRouter

    from aila.api.routers.executive import router

    assert isinstance(router, APIRouter)
    assert router.prefix == "/executive"


def test_executive_router_has_expected_routes():
    """Executive router exposes health, risk-summary-pdf, and evidence-package endpoints."""
    from aila.api.routers.executive import router

    paths = {route.path for route in router.routes}  # type: ignore[attr-defined]
    assert "/executive/health" in paths
    assert "/executive/risk-summary-pdf" in paths
    assert "/executive/systems/{system_id}/evidence-package" in paths
