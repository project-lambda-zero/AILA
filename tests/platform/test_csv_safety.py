from __future__ import annotations

import csv
import io

from aila.modules.pentest.live.services.reports import _csv
from aila.platform.services.csv_safety import csv_safe_cell
from aila.platform.tasks.report_tasks import _build_fleet_health_payload
from aila.storage.db_models import ManagedSystemRecord


def _parse(data: bytes) -> list[list[str]]:
    return list(csv.reader(io.StringIO(data.decode("utf-8"))))


def test_formula_prefixes_are_neutralised_and_plain_values_pass_through() -> None:
    assert csv_safe_cell("=HYPERLINK(\"http://x\")") == "'=HYPERLINK(\"http://x\")"
    assert csv_safe_cell("+1") == "'+1"
    assert csv_safe_cell("-cmd") == "'-cmd"
    assert csv_safe_cell("@SUM(A1)") == "'@SUM(A1)"
    assert csv_safe_cell("web-01") == "web-01"
    assert csv_safe_cell(None) == ""
    assert csv_safe_cell(22) == "22"


def test_fleet_health_csv_neutralises_formula_cells() -> None:
    rows = [
        ManagedSystemRecord(
            name="=cmd|' /C calc'!A0", host="10.0.0.5", username="+admin", port=22,
            role="-db", distro="@ubuntu",
        ),
        ManagedSystemRecord(name="web-01", host="10.0.0.6", username="ops", port=2222, role=None, distro=None),
    ]
    _, data = _build_fleet_health_payload("role", rows)
    parsed = _parse(data)
    assert parsed[0] == ["name", "host", "username", "port", "role", "distro"]
    assert parsed[1] == ["'=cmd|' /C calc'!A0", "10.0.0.5", "'+admin", "22", "'-db", "'@ubuntu"]
    assert parsed[2] == ["web-01", "10.0.0.6", "ops", "2222", "", ""]


def test_campaign_findings_csv_keeps_formula_guard() -> None:
    data = {
        "findings": [{
            "id": "f-1", "title": "=1+1", "severity": "high", "status": "open", "poe_level": "1",
            "verification_status": "verified", "verification_note": "-note", "asset_id": "a-1",
            "fingerprint": "fp", "evidence": [{"artifact_id": "art-1", "quote": "@quote"}],
        }],
    }
    parsed = _parse(_csv(data))
    assert parsed[1][1] == "'=1+1"
    assert parsed[1][6] == "'-note"
    assert parsed[1][10] == "'@quote"
