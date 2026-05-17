"""
End-to-end live infrastructure tests.

Run with: pytest -m e2e
Requires: ubuntu-vm system registered in the platform DB with SSH credentials configured.
These tests make real SSH connections, real HTTP calls to NVD/OSV/EPSS/KEV, and write real DB records.
They are intentionally slow (minutes). Do not include in default pytest run.
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Module-level skip guard — live DB query, not an env var check.
# ---------------------------------------------------------------------------


def _ubuntu_vm_registered() -> bool:
    """Returns True if a system named 'ubuntu-vm' exists in the platform DB."""
    try:
        from sqlmodel import select

        from aila.config import get_settings
        from aila.platform.config import build_platform_settings
        from aila.storage.database import init_db, session_scope
        from aila.storage.db_models import ManagedSystemRecord

        settings = get_settings()
        platform_settings = build_platform_settings(settings)
        init_db(platform_settings)
        with session_scope(platform_settings) as session:
            result = session.exec(
                select(ManagedSystemRecord).where(ManagedSystemRecord.name == "ubuntu-vm")
            ).first()
            return result is not None
    except Exception:
        return False


if not _ubuntu_vm_registered():
    pytest.skip(
        "ubuntu-vm not registered — skipping e2e suite",
        allow_module_level=True,
    )


# ---------------------------------------------------------------------------
# Module-scoped platform fixture — expensive init happens once per session.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def platform():
    """
    Instantiate AILAPlatform once for this module.

    scope="module" because platform startup (DB init, migration, LLM load) is
    expensive. All 5 test functions share one instance.
    """
    from aila.platform.runtime import AILAPlatform

    return AILAPlatform()


# ---------------------------------------------------------------------------
# E2E test functions — ordered intentionally.
#
# test_full_analysis_real_infrastructure runs FIRST because the four
# report-mode tests (summary, count, findings, explain) all depend on a
# persisted report produced by that scan. pytest executes tests in file-order
# by default, so definition order here is sufficient. If the test runner is
# configured to randomize order, prepend `pytest-ordering` and annotate with
# @pytest.mark.run(order=N).
# ---------------------------------------------------------------------------


@pytest.mark.e2e
def test_full_analysis_real_infrastructure(platform):
    """
    Runs a complete vulnerability scan against ubuntu-vm:
    SSH inventory -> OSV/Arch/Alpine advisories -> NVD/EPSS/KEV enrichment
    -> risk scoring -> report written to disk.
    No mocks. Real SSH, real APIs, real DB writes.
    Run first — subsequent report-mode tests depend on this report existing.
    """
    response = platform.handle("run a full vulnerability analysis on ubuntu-vm")
    assert response.action_id == "vulnerability.analyze_fleet"
    assert response.message  # non-empty
    # Report artifact written
    assert any("report" in k for k in response.artifacts), (
        f"Expected a report artifact, got: {response.artifacts}"
    )
    # State history shows key stages completed
    stage_names = [e.state for e in response.state_history]
    assert any("inventory" in s for s in stage_names), f"inventory stage missing: {stage_names}"
    assert any("report" in s for s in stage_names), f"report stage missing: {stage_names}"


@pytest.mark.e2e
def test_report_summary_uses_persisted_data(platform):
    """
    Queries a text summary of the latest vulnerability report.
    Requires full_analysis to have run first (persisted report in DB).
    Real DB read, no SSH, no external APIs.
    """
    response = platform.handle("give me a summary of the latest vulnerability report")
    assert response.action_id == "vulnerability.analyze_fleet"
    assert response.message
    # Summary payload must contain some structured data
    payload = response.module_payload
    assert payload, f"Expected non-empty module_payload, got: {payload}"


@pytest.mark.e2e
def test_report_count_returns_integer(platform):
    """
    Queries the CVE count from the latest persisted report.
    Result must be a non-negative integer.
    """
    response = platform.handle("how many CVEs are in the latest vulnerability report")
    assert response.action_id == "vulnerability.analyze_fleet"
    payload = response.module_payload
    # Count must be present and numeric
    count_value = None
    for key in ("count", "cve_count", "total"):
        if key in payload:
            count_value = payload[key]
            break
    assert count_value is not None, f"No count key found in payload: {payload}"
    assert isinstance(count_value, int) and count_value >= 0, (
        f"CVE count must be non-negative int, got: {count_value!r}"
    )


@pytest.mark.e2e
def test_report_findings_returns_ranked_list(platform):
    """
    Queries ranked findings from the latest report.
    Must return a non-empty list of findings with CVE identifiers.
    """
    response = platform.handle("show me the most exploitable CVEs from the last report")
    assert response.action_id == "vulnerability.analyze_fleet"
    payload = response.module_payload
    findings = payload.get("findings") or payload.get("items") or payload.get("rows") or payload.get("results")
    assert findings is not None, f"No findings key found in payload: {payload}"
    assert len(findings) > 0, "Findings list must not be empty after a full_analysis run"
    # Each finding must have a CVE identifier
    first = findings[0]
    has_cve = any("cve" in str(k).lower() for k in (first.keys() if isinstance(first, dict) else []))
    assert has_cve, f"First finding has no CVE field: {first}"


@pytest.mark.e2e
def test_explain_cves_returns_explanations(platform):
    """
    Requests LLM explanations for top CVEs from the latest report.
    Must return non-empty explanation text for at least one CVE.
    """
    response = platform.handle("explain the top 3 CVEs from the last vulnerability report")
    assert response.action_id == "vulnerability.analyze_fleet"
    assert response.message, "explain_cves response must contain explanation text"
    # Message must mention at least one CVE ID
    assert "CVE-" in response.message or "cve" in response.message.lower(), (
        f"Explanation must reference CVE IDs, got: {response.message[:200]}"
    )
