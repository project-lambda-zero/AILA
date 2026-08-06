"""Tests for RemediationTool -- rekeyed on (host, package_name, cve_id).

Verifies upsert/list/get actions against the current forward() signature
which no longer accepts run_id (removed during Phase 30 remediation rekeying).
"""
from __future__ import annotations

import pytest


async def test_upsert_creates_record_with_open_status(test_db):
    from aila.modules.vulnerability.tools.remediation import RemediationTool

    tool = RemediationTool()
    result = await tool.forward(
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


async def test_upsert_updates_status_to_remediated(test_db):
    from aila.modules.vulnerability.tools.remediation import RemediationTool

    tool = RemediationTool()
    await tool.forward(
        action="upsert",
        host="host-a",
        package_name="openssl",
        cve_id="CVE-2024-0001",
        status="open",
    )
    result = await tool.forward(
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


async def test_upsert_invalid_status_raises_value_error(test_db):
    from aila.modules.vulnerability.tools.remediation import RemediationTool

    tool = RemediationTool()
    with pytest.raises(ValueError, match="status"):
        await tool.forward(
            action="upsert",
            host="host-a",
            package_name="openssl",
            cve_id="CVE-2024-0001",
            status="unknown_status",
        )


async def test_list_returns_all_records_for_host(test_db):
    from aila.modules.vulnerability.tools.remediation import RemediationTool

    tool = RemediationTool()
    await tool.forward(action="upsert", host="host-a", package_name="openssl", cve_id="CVE-2024-0001", status="open")
    await tool.forward(action="upsert", host="host-a", package_name="curl", cve_id="CVE-2024-0002", status="deferred")
    await tool.forward(action="upsert", host="host-b", package_name="zlib", cve_id="CVE-2024-0003", status="accepted")

    result = await tool.forward(action="list", host="host-a")
    assert result["count"] == 2
    hosts = {r["host"] for r in result["records"]}
    assert hosts == {"host-a"}


async def test_get_returns_single_matching_record(test_db):
    from aila.modules.vulnerability.tools.remediation import RemediationTool

    tool = RemediationTool()
    await tool.forward(action="upsert", host="host-a", package_name="openssl", cve_id="CVE-2024-0001", status="open")
    await tool.forward(action="upsert", host="host-b", package_name="curl", cve_id="CVE-2024-0002", status="deferred")

    result = await tool.forward(
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


async def test_get_returns_empty_when_not_found(test_db):
    from aila.modules.vulnerability.tools.remediation import RemediationTool

    tool = RemediationTool()
    result = await tool.forward(
        action="get",
        host="host-missing",
        package_name="libfoo",
        cve_id="CVE-2024-9999",
    )
    assert result["count"] == 0
    assert result["records"] == []
