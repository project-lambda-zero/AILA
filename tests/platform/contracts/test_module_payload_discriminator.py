"""#61: PlatformResponse.module_payload is a discriminated union keyed on query_mode.

A dict carrying a known ``query_mode`` validates as exactly that member (no
first-match guessing that let a dict silently satisfy the wrong model). A
free-form module result dict -- forensics, hello_world, and _template dump
arbitrary dicts with no ``query_mode`` -- passes through the ``dict[str, Any]``
arm untyped instead of being coerced into an unrelated member. An unknown or
malformed tag degrades to the raw-dict arm rather than raising.
"""
from __future__ import annotations

from typing import Any

import pytest

from aila.platform.contracts import (
    PlatformCommandPayload,
    PlatformRegistryPayload,
    PlatformResponse,
    UnroutablePayload,
    VulnAnalysisPayload,
    VulnCountPayload,
    VulnSummaryPayload,
)


def _payload(mp: Any) -> Any:
    return PlatformResponse(
        run_id="r",
        action_id="vulnerability.analyze",
        message="m",
        module_payload=mp,
    ).module_payload


@pytest.mark.parametrize(
    "mp,expected",
    [
        ({"query_mode": "report_summary", "report": {"a": 1}}, VulnSummaryPayload),
        (
            {
                "query_mode": "report_count",
                "count": 3,
                "count_type": "distinct_cve",
                "cve_count": 3,
                "row_count": 5,
                "rows_scanned": 5,
                "scan_truncated": False,
                "report": {},
            },
            VulnCountPayload,
        ),
        ({"query_mode": "report_analyze", "summary": {}, "analysis": {}, "notes": []}, VulnAnalysisPayload),
        ({"query_mode": "ssh_registry", "registry": {}}, PlatformRegistryPayload),
        ({"query_mode": "remote_command", "command": "ls"}, PlatformCommandPayload),
        ({"query_mode": "unroutable", "supported_actions": ["a.b"]}, UnroutablePayload),
    ],
)
def test_known_query_mode_routes_to_member(mp: dict[str, Any], expected: type) -> None:
    assert isinstance(_payload(mp), expected)


@pytest.mark.parametrize(
    "mp",
    [
        {"findings": [1, 2], "summary": "forensics-shaped free dict"},
        {"request": {}, "greeting": "hello"},
        {"query_mode": "totally-unknown-tag", "z": 1},
        # Degenerate missing-report count: tag matches but required fields absent.
        {"query_mode": "report_count", "report": None},
    ],
)
def test_freeform_and_unknown_fall_through_to_raw_dict(mp: dict[str, Any]) -> None:
    result = _payload(mp)
    assert isinstance(result, dict)
    assert result == mp  # preserved verbatim, not coerced/dropped


def test_none_stays_none() -> None:
    assert _payload(None) is None


def test_typed_member_round_trips() -> None:
    """Serialize a typed payload and re-validate -- the tag re-selects the member."""
    original = _payload({"query_mode": "ssh_registry", "registry": {"web01": {"host": "h"}}})
    assert isinstance(original, PlatformRegistryPayload)
    dumped = PlatformResponse(
        run_id="r", action_id="platform.list", message="m", module_payload=original,
    ).model_dump(mode="json")
    assert isinstance(_payload(dumped["module_payload"]), PlatformRegistryPayload)
