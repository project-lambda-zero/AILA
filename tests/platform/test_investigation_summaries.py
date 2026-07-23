"""Platform investigation summary builder.

``build_investigation_summary`` projects a record into either module's
field-identical ``*InvestigationSummary`` contract. It passes the raw
string columns (kind / status / pause_reason) and relies on each
contract to coerce them into its own module enum; ``live_cost_usd``
overrides the stored ``cost_actual_usd``. The builder is a pure
projection, so these tests construct a lightweight record stand-in with
no database.
"""
from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from aila.modules.malware.contracts.investigation import (
    InvestigationKind as MalwareKind,
)
from aila.modules.malware.contracts.investigation import (
    MalwareInvestigationSummary,
)
from aila.modules.vr.contracts.investigation import (
    InvestigationKind as VRKind,
)
from aila.modules.vr.contracts.investigation import (
    VRInvestigationSummary,
)
from aila.platform.services.investigation_summaries import (
    build_investigation_summary,
)

# (summary contract, a kind value valid for that contract's own enum)
_CASES = [
    (VRInvestigationSummary, next(iter(VRKind)).value),
    (MalwareInvestigationSummary, next(iter(MalwareKind)).value),
]


def _record(kind: str, **over: object) -> SimpleNamespace:
    base: dict[str, object] = {
        "id": "inv-1",
        "title": "t",
        "target_id": "tgt-1",
        "parent_investigation_id": None,
        "kind": kind,
        "status": "running",
        "pause_reason": "",
        "auto_pilot": False,
        "is_favorite": False,
        "strategy_family": "sf",
        "cost_budget_usd": 50.0,
        "cost_actual_usd": 0.0,
        "llm_tokens_cost_usd": 0.0,
        "mcp_calls_cost_usd": 0.0,
        "fuzz_infra_cost_usd": 0.0,
        "primary_outcome_id": None,
        "linked_campaign_ids_json": "[]",
        "linked_finding_ids_json": "[]",
        "started_at": None,
        "stopped_at": None,
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "updated_at": datetime(2026, 1, 1, tzinfo=UTC),
    }
    base.update(over)
    return SimpleNamespace(**base)


@pytest.mark.parametrize(("summary_cls", "kind"), _CASES)
def test_builds_both_contracts(summary_cls: type, kind: str) -> None:
    """One builder projects into either module's contract; raw string
    kind / status coerce to the module enum and empty pause_reason -> None."""
    summary = build_investigation_summary(
        _record(kind), summary_cls=summary_cls, branch_count=3,
    )
    assert summary.id == "inv-1"
    assert summary.kind.value == kind
    assert summary.status.value == "running"
    assert summary.pause_reason is None
    assert summary.branch_count == 3
    assert summary.cost_actual_usd == 0.0


@pytest.mark.parametrize(("summary_cls", "kind"), _CASES)
def test_live_cost_overrides_stored(summary_cls: type, kind: str) -> None:
    """live_cost_usd supersedes the stored cost_actual_usd."""
    summary = build_investigation_summary(
        _record(kind, cost_actual_usd=0.0),
        summary_cls=summary_cls,
        live_cost_usd=4.5,
    )
    assert summary.cost_actual_usd == 4.5
