"""Tests for RemediationTool — rekeyed on (host, package_name, cve_id).

Verifies upsert/list/get actions against the current forward() signature
which no longer accepts run_id (removed during Phase 30 remediation rekeying).
"""
from __future__ import annotations

import pytest


def _make_tool(tmp_path):
    from aila.config import Settings
    from aila.modules.vulnerability.tools.remediation import RemediationTool

    settings = Settings(database_url=f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    return RemediationTool(settings=settings)


def test_upsert_creates_record_with_open_status(tmp_path):
    tool = _make_tool(tmp_path)
    result = tool.forward(
        action="upsert",
        host="host-a",
        package_name="openssl",
        cve_id="CVE-2024-0001",
        status="open",
    )
    assert result["count"] == 1
    record = result["records"][0]
    assert record["status"] == "open"
    assert record["host"] == "host-a"
    assert record["package_name"] == "openssl"
    assert record["cve_id"] == "CVE-2024-0001"


def test_upsert_updates_status_to_remediated(tmp_path):
    tool = _make_tool(tmp_path)
    tool.forward(
        action="upsert",
        host="host-a",
        package_name="openssl",
        cve_id="CVE-2024-0001",
        status="open",
    )
    result = tool.forward(
        action="upsert",
        host="host-a",
        package_name="openssl",
        cve_id="CVE-2024-0001",
        status="remediated",
        notes="Patched on 2024-01-10",
    )
    assert result["count"] == 1
    record = result["records"][0]
    assert record["status"] == "remediated"
    assert record["notes"] == "Patched on 2024-01-10"


def test_upsert_invalid_status_raises_value_error(tmp_path):
    tool = _make_tool(tmp_path)
    with pytest.raises(ValueError, match="status"):
        tool.forward(
            action="upsert",
            host="host-a",
            package_name="openssl",
            cve_id="CVE-2024-0001",
            status="unknown_status",
        )


def test_list_returns_all_records_for_host(tmp_path):
    tool = _make_tool(tmp_path)
    tool.forward(action="upsert", host="host-a", package_name="openssl", cve_id="CVE-2024-0001", status="open")
    tool.forward(action="upsert", host="host-a", package_name="curl", cve_id="CVE-2024-0002", status="deferred")
    tool.forward(action="upsert", host="host-b", package_name="zlib", cve_id="CVE-2024-0003", status="accepted")

    result = tool.forward(action="list", host="host-a")
    assert result["count"] == 2
    hosts = {r["host"] for r in result["records"]}
    assert hosts == {"host-a"}


def test_get_returns_single_matching_record(tmp_path):
    tool = _make_tool(tmp_path)
    tool.forward(action="upsert", host="host-a", package_name="openssl", cve_id="CVE-2024-0001", status="open")
    tool.forward(action="upsert", host="host-b", package_name="curl", cve_id="CVE-2024-0002", status="deferred")

    result = tool.forward(
        action="get",
        host="host-a",
        package_name="openssl",
        cve_id="CVE-2024-0001",
    )
    assert result["count"] == 1
    record = result["records"][0]
    assert record["host"] == "host-a"
    assert record["package_name"] == "openssl"
    assert record["cve_id"] == "CVE-2024-0001"


def test_get_returns_empty_when_not_found(tmp_path):
    tool = _make_tool(tmp_path)
    result = tool.forward(
        action="get",
        host="host-missing",
        package_name="libfoo",
        cve_id="CVE-2024-9999",
    )
    assert result["count"] == 0
    assert result["records"] == []
