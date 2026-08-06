"""Tests for inventory_drift() and InventoryDriftTool (INTEL-04 / plan 34-01, Task 2)."""
from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _insert_inventory(
    *,
    host: str,
    run_id: str,
    system_id: int = 1,
    packages: list[dict],
    collected_at: datetime,
    status: str = "collected",
) -> None:
    from aila.modules.vulnerability.db_models import InventoryArtifactRecord
    from aila.storage.database import session_scope

    payload = json.dumps({"packages": packages, "kernel": "", "os_release": {}})
    with session_scope() as session:
        session.add(
            InventoryArtifactRecord(
                run_id=run_id,
                system_id=system_id,
                host=host,
                distro="ubuntu-22.04",
                kernel="5.15",
                status=status,
                error_message=None,
                payload_json=payload,
                collected_at=collected_at,
            )
        )
        session.commit()


_TS_OLDER = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
_TS_NEWER = datetime(2026, 1, 2, 10, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_no_inventory_records(test_db):
    """Host has no InventoryArtifactRecord rows -> scans_compared=0, all lists empty, message present."""
    from aila.modules.vulnerability.tools.inventory_drift import inventory_drift

    result = await inventory_drift(target="ghost-host")

    assert result["host"] == "ghost-host"
    assert result["scans_compared"] == 0
    assert result["added"] == []
    assert result["removed"] == []
    assert result["upgraded"] == []
    assert result["downgraded"] == []
    assert "message" in result


async def test_only_one_scan(test_db):
    """Only one record for host -> scans_compared=1, all diff lists empty, message mentions one scan."""
    from aila.modules.vulnerability.tools.inventory_drift import inventory_drift

    _insert_inventory(
        host="host-single",
        run_id="run-001",
        packages=[{"name": "libssl", "version": "1.0"}],
        collected_at=_TS_NEWER,
    )

    result = await inventory_drift(target="host-single")

    assert result["scans_compared"] == 1
    assert result["added"] == []
    assert result["removed"] == []
    assert result["upgraded"] == []
    assert result["downgraded"] == []
    assert "one scan" in result["message"].lower()


async def test_package_added(test_db):
    """Older scan: [libssl:1.0], newer scan: [libssl:1.0, curl:7.88] -> added=[curl]."""
    from aila.modules.vulnerability.tools.inventory_drift import inventory_drift

    _insert_inventory(
        host="host-add",
        run_id="run-old",
        packages=[{"name": "libssl", "version": "1.0"}],
        collected_at=_TS_OLDER,
    )
    _insert_inventory(
        host="host-add",
        run_id="run-new",
        packages=[{"name": "libssl", "version": "1.0"}, {"name": "curl", "version": "7.88"}],
        collected_at=_TS_NEWER,
    )

    result = await inventory_drift(target="host-add")

    assert result["scans_compared"] == 2
    assert len(result["added"]) == 1
    assert result["added"][0] == {"name": "curl", "version": "7.88"}
    assert result["removed"] == []
    assert result["upgraded"] == []


async def test_package_removed(test_db):
    """Older: [libssl:1.0, curl:7.88], newer: [libssl:1.0] -> removed=[curl]."""
    from aila.modules.vulnerability.tools.inventory_drift import inventory_drift

    _insert_inventory(
        host="host-rem",
        run_id="run-old",
        packages=[{"name": "libssl", "version": "1.0"}, {"name": "curl", "version": "7.88"}],
        collected_at=_TS_OLDER,
    )
    _insert_inventory(
        host="host-rem",
        run_id="run-new",
        packages=[{"name": "libssl", "version": "1.0"}],
        collected_at=_TS_NEWER,
    )

    result = await inventory_drift(target="host-rem")

    assert result["scans_compared"] == 2
    assert result["added"] == []
    assert len(result["removed"]) == 1
    assert result["removed"][0] == {"name": "curl", "old_version": "7.88"}


async def test_package_upgraded(test_db):
    """Older: [libssl:1.0], newer: [libssl:1.1] -> upgraded=[libssl 1.0->1.1]."""
    from aila.modules.vulnerability.tools.inventory_drift import inventory_drift

    _insert_inventory(
        host="host-up",
        run_id="run-old",
        packages=[{"name": "libssl", "version": "1.0"}],
        collected_at=_TS_OLDER,
    )
    _insert_inventory(
        host="host-up",
        run_id="run-new",
        packages=[{"name": "libssl", "version": "1.1"}],
        collected_at=_TS_NEWER,
    )

    result = await inventory_drift(target="host-up")

    assert result["scans_compared"] == 2
    assert result["added"] == []
    assert result["removed"] == []
    assert len(result["upgraded"]) == 1
    assert result["upgraded"][0] == {"name": "libssl", "old_version": "1.0", "new_version": "1.1"}
    assert result["downgraded"] == []


async def test_package_downgraded(test_db):
    """Older: [libssl:1.1], newer: [libssl:1.0] -> downgraded=[libssl 1.1->1.0]."""
    from aila.modules.vulnerability.tools.inventory_drift import inventory_drift

    _insert_inventory(
        host="host-down",
        run_id="run-old",
        packages=[{"name": "libssl", "version": "1.1"}],
        collected_at=_TS_OLDER,
    )
    _insert_inventory(
        host="host-down",
        run_id="run-new",
        packages=[{"name": "libssl", "version": "1.0"}],
        collected_at=_TS_NEWER,
    )

    result = await inventory_drift(target="host-down")

    assert result["scans_compared"] == 2
    assert result["upgraded"] == []
    assert len(result["downgraded"]) == 1
    assert result["downgraded"][0] == {"name": "libssl", "old_version": "1.1", "new_version": "1.0"}


async def test_no_changes(test_db):
    """Identical package lists -> added=[], removed=[], upgraded=[], downgraded=[]."""
    from aila.modules.vulnerability.tools.inventory_drift import inventory_drift

    pkgs = [{"name": "libssl", "version": "1.0"}, {"name": "curl", "version": "7.88"}]
    _insert_inventory(host="host-same", run_id="run-old", packages=pkgs, collected_at=_TS_OLDER)
    _insert_inventory(host="host-same", run_id="run-new", packages=pkgs, collected_at=_TS_NEWER)

    result = await inventory_drift(target="host-same")

    assert result["scans_compared"] == 2
    assert result["added"] == []
    assert result["removed"] == []
    assert result["upgraded"] == []
    assert result["downgraded"] == []


async def test_tool_rejects_missing_target(test_db):
    """InventoryDriftTool().forward(action='drift', target='') raises ValueError."""
    from aila.modules.vulnerability.tools.inventory_drift import InventoryDriftTool

    tool = InventoryDriftTool()
    with pytest.raises(ValueError):
        await tool.forward(action="drift", target="")
