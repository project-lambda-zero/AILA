"""Tests for what_if_patch() and WhatIfTool (AUTO-02 / plan 36-01, Task 2)."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.dialects.sqlite import insert as sa_insert

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_settings(tmp_path):
    from aila.config import Settings
    return Settings(database_url=f"sqlite:///{(tmp_path / 'test.db').as_posix()}")


def _setup_db(settings):
    from aila.storage.database import init_db
    init_db(settings)


def _insert_finding(
    settings,
    *,
    host: str,
    package_name: str,
    cve_id: str,
    system_id: int = 1,
    criticality: str = "High",
    score: float = 7.5,
    distribution: str = "ubuntu-22.04",
    fixed_version: str | None = "1.0.0",
) -> None:
    from aila.modules.vulnerability.db_models import LatestFindingRecord
    from aila.storage.database import session_scope

    now = datetime.now(UTC)
    stmt = (
        sa_insert(LatestFindingRecord)
        .values(
            host=host,
            package_name=package_name,
            cve_id=cve_id,
            system_id=system_id,
            system_name=host,
            distribution=distribution,
            criticality=criticality,
            score=score,
            rationale="test",
            fixed_version=fixed_version,
            nvd_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            compliance_tags_json="[]",
            details_json="{}",
            last_scanned_at=now,
            created_at=now,
        )
        .prefix_with("OR REPLACE")
    )
    with session_scope(settings) as session:
        session.exec(stmt)  # type: ignore[arg-type]
        session.commit()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_empty_db_returns_unchanged(tmp_path):
    """No findings -> current_score=0.0, simulated_score=0.0, delta=0.0, removed_finding_count=0."""
    from aila.modules.vulnerability.tools.what_if import what_if_patch

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    result = what_if_patch(package_name="openssl", settings=settings)

    assert result["current_score"] == 0.0
    assert result["simulated_score"] == 0.0
    assert result["delta"] == 0.0
    assert result["removed_finding_count"] == 0


def test_patch_reduces_score(tmp_path):
    """Fleet has openssl findings plus curl findings; patching openssl lowers score."""
    from aila.modules.vulnerability.tools.what_if import what_if_patch

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    # openssl findings with high criticality
    _insert_finding(settings, host="host-a", package_name="openssl", cve_id="CVE-2024-0001",
                    criticality="Immediate", score=9.0)
    _insert_finding(settings, host="host-b", package_name="openssl", cve_id="CVE-2024-0002",
                    criticality="Immediate", score=9.0)
    # curl findings with lower criticality
    _insert_finding(settings, host="host-a", package_name="curl", cve_id="CVE-2024-0003",
                    criticality="Moderate", score=5.0)

    result = what_if_patch(package_name="openssl", settings=settings)

    assert result["simulated_score"] < result["current_score"]
    assert result["removed_finding_count"] > 0
    assert result["delta"] > 0.0


def test_unrelated_package_no_change(tmp_path):
    """Patching 'nonexistent-pkg' -> removed_finding_count=0, delta=0.0."""
    from aila.modules.vulnerability.tools.what_if import what_if_patch

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(settings, host="host-a", package_name="openssl", cve_id="CVE-2024-0001",
                    criticality="High", score=8.0)

    result = what_if_patch(package_name="nonexistent-pkg", settings=settings)

    assert result["removed_finding_count"] == 0
    assert result["delta"] == 0.0
    assert result["simulated_score"] == result["current_score"]


def test_version_filter_applied(tmp_path):
    """Providing a version removes all findings for that package (LatestFindingRecord has no installed_version)."""
    from aila.modules.vulnerability.tools.what_if import what_if_patch

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    # Two openssl findings
    _insert_finding(settings, host="host-a", package_name="openssl", cve_id="CVE-2024-0001",
                    criticality="High", score=8.0, fixed_version="3.0.14")
    _insert_finding(settings, host="host-b", package_name="openssl", cve_id="CVE-2024-0002",
                    criticality="Moderate", score=5.0, fixed_version="3.0.14")

    # When version is provided and no installed_version available, removes all matching package findings
    result = what_if_patch(package_name="openssl", version="3.0.14", settings=settings)

    # Both openssl findings should be removed
    assert result["removed_finding_count"] == 2


def test_score_computation_matches_risk_posture(tmp_path):
    """current_score computed identically to risk_posture.py weighted formula."""
    from aila.modules.vulnerability.tools.what_if import what_if_patch

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    # 2 Immediate (weight 4) + 1 Moderate (weight 2) = 10 / (3*4) * 100 = 83.3
    _insert_finding(settings, host="host-a", package_name="pkg-a", cve_id="CVE-2024-0001",
                    criticality="Immediate", score=9.0)
    _insert_finding(settings, host="host-a", package_name="pkg-b", cve_id="CVE-2024-0002",
                    criticality="Immediate", score=8.0)
    _insert_finding(settings, host="host-a", package_name="pkg-c", cve_id="CVE-2024-0003",
                    criticality="Moderate", score=5.0)

    result = what_if_patch(package_name="nonexistent", settings=settings)

    expected = round((4 + 4 + 2) / (3 * 4) * 100, 1)
    assert result["current_score"] == pytest.approx(expected, abs=0.1)


def test_tool_forward_action_simulate(tmp_path):
    """WhatIfTool().forward(action='simulate', package_name='openssl') returns dict with required keys."""
    from aila.modules.vulnerability.tools.what_if import WhatIfTool

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    tool = WhatIfTool(settings=settings)
    result = tool.forward(action="simulate", package_name="openssl")

    assert isinstance(result, dict)
    assert "current_score" in result
    assert "simulated_score" in result


def test_tool_rejects_bad_action(tmp_path):
    """WhatIfTool().forward(action='bad') raises ValueError."""
    from aila.modules.vulnerability.tools.what_if import WhatIfTool

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    tool = WhatIfTool(settings=settings)
    with pytest.raises(ValueError):
        tool.forward(action="bad", package_name="openssl")


def test_tool_requires_package_name(tmp_path):
    """WhatIfTool().forward(action='simulate', package_name='') raises ValueError."""
    from aila.modules.vulnerability.tools.what_if import WhatIfTool

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    tool = WhatIfTool(settings=settings)
    with pytest.raises(ValueError):
        tool.forward(action="simulate", package_name="")
