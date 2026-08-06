"""Tests for what_if_patch() and WhatIfTool (AUTO-02 / plan 36-01, Task 2)."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _insert_finding(
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
    with session_scope() as session:
        session.add(
            LatestFindingRecord(
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
        )
        session.commit()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_empty_db_returns_unchanged(test_db):
    """No findings -> current_score=0.0, simulated_score=0.0, delta=0.0, removed_finding_count=0."""
    from aila.modules.vulnerability.tools.what_if import what_if_patch

    result = await what_if_patch(package_name="openssl")

    assert result["current_score"] == 0.0
    assert result["simulated_score"] == 0.0
    assert result["delta"] == 0.0
    assert result["removed_finding_count"] == 0


async def test_patch_reduces_score(test_db):
    """Fleet has openssl findings plus curl findings; patching openssl lowers score."""
    from aila.modules.vulnerability.tools.what_if import what_if_patch

    # openssl findings with high criticality
    _insert_finding(host="host-a", package_name="openssl", cve_id="CVE-2024-0001",
                    criticality="Immediate", score=9.0)
    _insert_finding(host="host-b", package_name="openssl", cve_id="CVE-2024-0002",
                    criticality="Immediate", score=9.0)
    # curl findings with lower criticality
    _insert_finding(host="host-a", package_name="curl", cve_id="CVE-2024-0003",
                    criticality="Moderate", score=5.0)

    result = await what_if_patch(package_name="openssl")

    assert result["simulated_score"] < result["current_score"]
    assert result["removed_finding_count"] > 0
    assert result["delta"] > 0.0


async def test_unrelated_package_no_change(test_db):
    """Patching 'nonexistent-pkg' -> removed_finding_count=0, delta=0.0."""
    from aila.modules.vulnerability.tools.what_if import what_if_patch

    _insert_finding(host="host-a", package_name="openssl", cve_id="CVE-2024-0001",
                    criticality="High", score=8.0)

    result = await what_if_patch(package_name="nonexistent-pkg")

    assert result["removed_finding_count"] == 0
    assert result["delta"] == 0.0
    assert result["simulated_score"] == result["current_score"]


async def test_version_filter_applied(test_db):
    """Providing a version removes all findings for that package (LatestFindingRecord has no installed_version)."""
    from aila.modules.vulnerability.tools.what_if import what_if_patch

    # Two openssl findings
    _insert_finding(host="host-a", package_name="openssl", cve_id="CVE-2024-0001",
                    criticality="High", score=8.0, fixed_version="3.0.14")
    _insert_finding(host="host-b", package_name="openssl", cve_id="CVE-2024-0002",
                    criticality="Moderate", score=5.0, fixed_version="3.0.14")

    # When version is provided and no installed_version available, removes all matching package findings
    result = await what_if_patch(package_name="openssl", version="3.0.14")

    # Both openssl findings should be removed
    assert result["removed_finding_count"] == 2


async def test_score_computation_matches_risk_posture(test_db):
    """current_score computed identically to risk_posture.py weighted formula."""
    from aila.modules.vulnerability.tools.what_if import what_if_patch

    # 2 Immediate (weight 4) + 1 Moderate (weight 2) = 10 / (3*4) * 100 = 83.3
    _insert_finding(host="host-a", package_name="pkg-a", cve_id="CVE-2024-0001",
                    criticality="Immediate", score=9.0)
    _insert_finding(host="host-a", package_name="pkg-b", cve_id="CVE-2024-0002",
                    criticality="Immediate", score=8.0)
    _insert_finding(host="host-a", package_name="pkg-c", cve_id="CVE-2024-0003",
                    criticality="Moderate", score=5.0)

    result = await what_if_patch(package_name="nonexistent")

    expected = round((4 + 4 + 2) / (3 * 4) * 100, 1)
    assert result["current_score"] == pytest.approx(expected, abs=0.1)


async def test_tool_forward_action_simulate(test_db):
    """WhatIfTool().forward(action='simulate', package_name='openssl') returns dict with required keys."""
    from aila.modules.vulnerability.tools.what_if import WhatIfTool

    tool = WhatIfTool()
    result = await tool.forward(action="simulate", package_name="openssl")

    assert isinstance(result, dict)
    assert "current_score" in result
    assert "simulated_score" in result


async def test_tool_rejects_bad_action(test_db):
    """WhatIfTool().forward(action='bad') raises ValueError."""
    from aila.modules.vulnerability.tools.what_if import WhatIfTool

    tool = WhatIfTool()
    with pytest.raises(ValueError):
        await tool.forward(action="bad", package_name="openssl")


async def test_tool_requires_package_name(test_db):
    """WhatIfTool().forward(action='simulate', package_name='') raises ValueError."""
    from aila.modules.vulnerability.tools.what_if import WhatIfTool

    tool = WhatIfTool()
    with pytest.raises(ValueError):
        await tool.forward(action="simulate", package_name="")
