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

from aila.modules.malware.contracts.branch import MalwareBranchSummary
from aila.modules.malware.contracts.investigation import (
    InvestigationKind as MalwareKind,
)
from aila.modules.malware.contracts.investigation import (
    MalwareInvestigationSummary,
)
from aila.modules.malware.contracts.message import MalwareMessageSummary
from aila.modules.malware.contracts.outcome import (
    MalwareOutcomeSummary,
)
from aila.modules.malware.contracts.outcome import (
    OutcomeKind as MalwareOutcomeKind,
)
from aila.modules.vr.contracts.branch import VRBranchSummary
from aila.modules.vr.contracts.investigation import (
    InvestigationKind as VRKind,
)
from aila.modules.vr.contracts.investigation import (
    VRInvestigationSummary,
)
from aila.modules.vr.contracts.message import VRMessageSummary
from aila.modules.vr.contracts.outcome import (
    OutcomeKind as VROutcomeKind,
)
from aila.modules.vr.contracts.outcome import (
    VROutcomeSummary,
)
from aila.platform.services.investigation_summaries import (
    build_branch_summary,
    build_investigation_summary,
    build_message_summary,
    build_outcome_summary,
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


# ---------------------------------------------------------------------------
# build_branch_summary
# ---------------------------------------------------------------------------


def _branch_record(**over: object) -> SimpleNamespace:
    base: dict[str, object] = {
        "id": "br-1",
        "investigation_id": "inv-1",
        "parent_branch_id": None,
        "status": "active",
        "persona_voice": "halvar",
        "fork_reason": "initial",
        "fork_at_turn": None,
        "turn_count": 0,
        "branch_cost_usd": 0.0,
        "closed_reason": "",
        "merged_into_branch_id": None,
        "promoted": False,
        "closed_at": None,
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "updated_at": datetime(2026, 1, 1, tzinfo=UTC),
        "strategy_family": "sf",
    }
    base.update(over)
    return SimpleNamespace(**base)


_BRANCH_CASES = [VRBranchSummary, MalwareBranchSummary]


@pytest.mark.parametrize("summary_cls", _BRANCH_CASES)
def test_build_branch_summary_projects_both_contracts(
    summary_cls: type,
) -> None:
    """Both module contracts accept the same projection; cursor pass-through."""
    summary = build_branch_summary(
        _branch_record(),
        summary_cls=summary_cls,
        cursor_state="investigation_loop",
        cursor_archived_state=None,
    )
    assert summary.id == "br-1"
    assert summary.investigation_id == "inv-1"
    assert summary.status.value == "active"
    assert summary.persona_voice is not None
    assert summary.persona_voice.value == "halvar"
    assert summary.fork_reason == "initial"
    assert summary.closed_reason == ""
    assert summary.cursor_state == "investigation_loop"
    assert summary.cursor_archived_state is None
    assert summary.strategy_family == "sf"


@pytest.mark.parametrize("summary_cls", _BRANCH_CASES)
def test_build_branch_summary_none_reason_coerces_to_empty(
    summary_cls: type,
) -> None:
    """Nullable DB columns (fork_reason / closed_reason) coerce to ''."""
    summary = build_branch_summary(
        _branch_record(fork_reason=None, closed_reason=None, persona_voice=""),
        summary_cls=summary_cls,
    )
    assert summary.fork_reason == ""
    assert summary.closed_reason == ""
    assert summary.persona_voice is None


# ---------------------------------------------------------------------------
# build_message_summary
# ---------------------------------------------------------------------------


def _message_record(**over: object) -> SimpleNamespace:
    base: dict[str, object] = {
        "id": "msg-1",
        "investigation_id": "inv-1",
        "branch_id": "br-1",
        "sender_kind": "engine",
        "sender_id": "halvar",
        "payload_kind": "text",
        "payload_json": '{"text": "hi"}',
        "operator_intent": "",
        "at_turn": 3,
        "evidence_refs_json": '["ref-1"]',
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "acked_at": None,
    }
    base.update(over)
    return SimpleNamespace(**base)


def test_build_message_summary_vr_omits_acked_at() -> None:
    """VR contract lacks ``acked_at``; the builder must not pass it.

    VR's ``VRMessageSummary`` has ``model_config = ConfigDict(extra='forbid')``;
    an unconditional ``acked_at=None`` kwarg would raise.
    """
    summary = build_message_summary(
        _message_record(), summary_cls=VRMessageSummary,
    )
    assert summary.id == "msg-1"
    assert summary.payload == {"text": "hi"}
    assert summary.evidence_refs == ["ref-1"]
    assert summary.operator_intent is None
    assert summary.at_turn == 3
    assert not hasattr(summary, "acked_at")


def test_build_message_summary_malware_forwards_acked_at() -> None:
    """Malware's contract declares ``acked_at``; the builder forwards it."""
    ts = datetime(2026, 2, 1, tzinfo=UTC)
    summary = build_message_summary(
        _message_record(acked_at=ts), summary_cls=MalwareMessageSummary,
    )
    assert summary.acked_at == ts


def test_build_message_summary_empty_json_defaults() -> None:
    """NULL payload_json / evidence_refs_json coerce to {} / []."""
    summary = build_message_summary(
        _message_record(payload_json=None, evidence_refs_json=None),
        summary_cls=MalwareMessageSummary,
    )
    assert summary.payload == {}
    assert summary.evidence_refs == []


# ---------------------------------------------------------------------------
# build_outcome_summary
# ---------------------------------------------------------------------------


def _outcome_record(outcome_kind: str, **over: object) -> SimpleNamespace:
    base: dict[str, object] = {
        "id": "out-1",
        "investigation_id": "inv-1",
        "branch_id": "br-1",
        "outcome_kind": outcome_kind,
        "payload_json": "{}",
        "confidence": "strong",
        "evidence_refs_json": "[]",
        "accepted_by_operator": False,
        "accepted_at": None,
        "dispatch_status": "pending",
        "dispatch_target": None,
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "state": "draft",
    }
    base.update(over)
    return SimpleNamespace(**base)


_OUTCOME_CASES = [
    (VROutcomeSummary, next(iter(VROutcomeKind)).value),
    (MalwareOutcomeSummary, next(iter(MalwareOutcomeKind)).value),
]


@pytest.mark.parametrize(("summary_cls", "kind"), _OUTCOME_CASES)
def test_build_outcome_summary_defaults_zero_counts(
    summary_cls: type, kind: str,
) -> None:
    """No review_counts -> every vote-count field defaults to 0."""
    summary = build_outcome_summary(
        _outcome_record(kind), summary_cls=summary_cls,
    )
    assert summary.id == "out-1"
    assert summary.outcome_kind.value == kind
    assert summary.state == "draft"
    assert summary.approve_count == 0
    assert summary.reject_count == 0
    assert summary.request_edit_count == 0
    assert summary.abstain_count == 0
    assert summary.quorum_k == 0


@pytest.mark.parametrize(("summary_cls", "kind"), _OUTCOME_CASES)
def test_build_outcome_summary_review_counts_forward(
    summary_cls: type, kind: str,
) -> None:
    """review_counts populates the sibling-review vote breakdown."""
    summary = build_outcome_summary(
        _outcome_record(kind),
        summary_cls=summary_cls,
        review_counts={
            "approve": 2,
            "reject": 1,
            "request_edit": 0,
            "abstain": 3,
            "quorum_k": 4,
        },
    )
    assert summary.approve_count == 2
    assert summary.reject_count == 1
    assert summary.abstain_count == 3
    assert summary.quorum_k == 4


@pytest.mark.parametrize(("summary_cls", "kind"), _OUTCOME_CASES)
def test_build_outcome_summary_legacy_null_state(
    summary_cls: type, kind: str,
) -> None:
    """NULL state on legacy rows falls back to 'dispatched'."""
    summary = build_outcome_summary(
        _outcome_record(kind, state=None),
        summary_cls=summary_cls,
    )
    assert summary.state == "dispatched"
