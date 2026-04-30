"""Tests for blast_radius() query (INTEL-02 / plan 33-02, Task 1)."""
from __future__ import annotations

from datetime import datetime, timezone

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
    fixed_version: str | None = "1.0.0",
    last_scanned_at: datetime | None = None,
) -> None:
    from aila.modules.vulnerability.db_models import LatestFindingRecord
    from aila.storage.database import session_scope

    now = last_scanned_at or datetime.now(timezone.utc)
    stmt = (
        sa_insert(LatestFindingRecord)
        .values(
            host=host,
            package_name=package_name,
            cve_id=cve_id,
            system_id=system_id,
            system_name=host,
            distribution="ubuntu-22.04",
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


def _insert_tag(settings, *, system_id: int, tag_key: str, tag_value: str) -> None:
    from aila.modules.vulnerability.db_models import AssetTagRecord
    from aila.storage.database import session_scope

    now = datetime.now(timezone.utc)
    stmt = (
        sa_insert(AssetTagRecord)
        .values(system_id=system_id, tag_key=tag_key, tag_value=tag_value, created_at=now, updated_at=now)
        .on_conflict_do_update(
            index_elements=["system_id", "tag_key"],
            set_={"tag_value": tag_value, "updated_at": now},
        )
    )
    with session_scope(settings) as session:
        session.exec(stmt)  # type: ignore[arg-type]
        session.commit()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_multi_host_blast_radius(tmp_path):
    """CVE on 2 hosts with different env tags returns host_count=2 and correct tag_breakdown."""
    from aila.modules.vulnerability.tools.blast_radius import blast_radius

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(settings, host="host-a", package_name="libssl", cve_id="CVE-2024-1234", system_id=1)
    _insert_finding(settings, host="host-b", package_name="libssl", cve_id="CVE-2024-1234", system_id=2)
    _insert_tag(settings, system_id=1, tag_key="env", tag_value="production")
    _insert_tag(settings, system_id=2, tag_key="env", tag_value="staging")

    result = blast_radius(cve_id="CVE-2024-1234", settings=settings)

    assert result["cve_id"] == "CVE-2024-1234"
    assert result["host_count"] == 2
    assert len(result["hosts"]) == 2
    host_names = {h["host"] for h in result["hosts"]}
    assert host_names == {"host-a", "host-b"}
    assert result["tag_breakdown"]["env"]["production"] == 1
    assert result["tag_breakdown"]["env"]["staging"] == 1


def test_single_host_no_tags(tmp_path):
    """CVE on 1 host with no AssetTagRecord entries — tags={} on that host entry."""
    from aila.modules.vulnerability.tools.blast_radius import blast_radius

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(settings, host="host-c", package_name="openssl", cve_id="CVE-2024-5678", system_id=10)

    result = blast_radius(cve_id="CVE-2024-5678", settings=settings)

    assert result["host_count"] == 1
    assert result["hosts"][0]["tags"] == {}
    assert result["tag_breakdown"] == {}


def test_unknown_cve_returns_empty(tmp_path):
    """CVE not in DB returns host_count=0, empty hosts and tag_breakdown. No error raised."""
    from aila.modules.vulnerability.tools.blast_radius import blast_radius

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    result = blast_radius(cve_id="CVE-9999-9999", settings=settings)

    assert result["cve_id"] == "CVE-9999-9999"
    assert result["host_count"] == 0
    assert result["hosts"] == []
    assert result["tag_breakdown"] == {}


def test_multiple_packages_same_host(tmp_path):
    """CVE matching libssl + openssl on same host — both appear as separate host entries."""
    from aila.modules.vulnerability.tools.blast_radius import blast_radius

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(settings, host="host-d", package_name="libssl", cve_id="CVE-2024-MULTI", system_id=20)
    _insert_finding(settings, host="host-d", package_name="openssl", cve_id="CVE-2024-MULTI", system_id=20)

    result = blast_radius(cve_id="CVE-2024-MULTI", settings=settings)

    # host_count is distinct hosts — just 1
    assert result["host_count"] == 1
    # But hosts list has 2 entries (one per package)
    assert len(result["hosts"]) == 2
    packages = {h["package_name"] for h in result["hosts"]}
    assert packages == {"libssl", "openssl"}


def test_cve_id_normalized_to_uppercase(tmp_path):
    """CVE ID is normalized to uppercase before query."""
    from aila.modules.vulnerability.tools.blast_radius import blast_radius

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(settings, host="host-e", package_name="pkg", cve_id="CVE-2024-UPPER", system_id=30)

    result = blast_radius(cve_id="cve-2024-upper", settings=settings)

    assert result["cve_id"] == "CVE-2024-UPPER"
    assert result["host_count"] == 1


def test_host_entry_fields_present(tmp_path):
    """Each host entry has the required fields."""
    from aila.modules.vulnerability.tools.blast_radius import blast_radius

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_finding(
        settings,
        host="host-f",
        package_name="curl",
        cve_id="CVE-2024-FIELDS",
        system_id=40,
        criticality="Immediate",
        score=9.8,
        fixed_version="8.0.0",
    )
    _insert_tag(settings, system_id=40, tag_key="env", tag_value="production")
    _insert_tag(settings, system_id=40, tag_key="team", tag_value="platform")

    result = blast_radius(cve_id="CVE-2024-FIELDS", settings=settings)

    assert result["host_count"] == 1
    entry = result["hosts"][0]
    assert entry["host"] == "host-f"
    assert entry["system_id"] == 40
    assert entry["package_name"] == "curl"
    assert entry["criticality"] == "Immediate"
    assert entry["score"] == 9.8
    assert entry["fixed_version"] == "8.0.0"
    assert "last_scanned_at" in entry
    assert entry["tags"]["env"] == "production"
    assert entry["tags"]["team"] == "platform"
    assert result["tag_breakdown"]["env"]["production"] == 1
    assert result["tag_breakdown"]["team"]["platform"] == 1
