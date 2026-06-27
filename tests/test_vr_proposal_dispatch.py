"""Unit tests for the CAMPAIGN_LAUNCH → proposal-row dispatch path.

The reasoning agent emits a fully-prepared payload; the
``OutcomeDispatcher._dispatch_campaign_launch`` path persists it as
``vr_fuzz_campaign_proposals(status='pending')``. We exercise the
helpers directly here (no SQL); the integration test that actually
hits the table belongs in tests/api/test_vr_fuzz_proposals.py once
the test DB plumbing is needed.
"""
from __future__ import annotations

import pytest

from aila.modules.vr.agents.outcome_dispatcher import (
    _int_or_none,
    _str_or_none,
)
from aila.modules.vr.contracts import (
    FuzzProposalDecideAccept,
    FuzzProposalDecideReject,
    FuzzProposalStatus,
    SeedCorpusEntry,
)

__all__ = [
    "test_str_or_none_handles_blank_and_whitespace",
    "test_str_or_none_passes_through_non_strings",
    "test_int_or_none_parses_numerics_and_rejects_garbage",
]


def test_str_or_none_handles_blank_and_whitespace() -> None:
    """Empty / whitespace-only strings collapse to None.

    This matters because the LLM sometimes emits ``""`` or ``"  "``
    in optional fields; storing them as empty strings would defeat
    the IS NULL queries the UI uses to detect "missing prep".
    """
    assert _str_or_none(None) is None
    assert _str_or_none("") is None
    assert _str_or_none("   ") is None
    assert _str_or_none("\n\t") is None
    assert _str_or_none("clang -O2 …") == "clang -O2 …"


def test_str_or_none_passes_through_non_strings() -> None:
    """Numeric / bool inputs are stringified -- accepts whatever the
    LLM emits without raising."""
    assert _str_or_none(42) == "42"
    assert _str_or_none(True) == "True"


def test_int_or_none_parses_numerics_and_rejects_garbage() -> None:
    assert _int_or_none(None) is None
    assert _int_or_none(24) == 24
    assert _int_or_none("24") == 24
    # LLM sometimes emits the field as "24h" -- we don't try to be
    # clever, just reject. The proposal row keeps suggested_duration_hours
    # as NULL and the operator picks during accept.
    assert _int_or_none("24h") is None
    assert _int_or_none("forever") is None


def test_proposal_status_enum_values() -> None:
    """Verify the status enum carries the four lifecycle states the
    UI + migration encode."""

    assert {s.value for s in FuzzProposalStatus} == {
        "pending", "accepted", "rejected", "superseded",
    }


def test_seed_corpus_entry_validates_required_fields() -> None:
    """SeedCorpusEntry rejects empty filename / content."""


    # Happy path.
    entry = SeedCorpusEntry(
        filename="seed.bin",
        content_base64="QUJD",
        notes="minimal",
    )
    assert entry.filename == "seed.bin"
    assert entry.notes == "minimal"

    # Missing filename → ValidationError.
    with pytest.raises(Exception):
        SeedCorpusEntry(filename="", content_base64="QUJD")
    with pytest.raises(Exception):
        SeedCorpusEntry(filename="seed.bin", content_base64="")


def test_accept_body_defaults_auto_launch_true() -> None:
    """FuzzProposalDecideAccept defaults to auto_launch=True -- the
    whole point of the proposal flow is one-click prep + launch."""


    body = FuzzProposalDecideAccept()
    assert body.auto_launch is True
    assert body.skip_prepare is False
    assert body.engine_id is None
    assert body.analysis_system_id is None


def test_reject_body_requires_decision_reason() -> None:
    """Reject must carry a reason -- audit trail."""


    body = FuzzProposalDecideReject(decision_reason="not worth GPU hours")
    assert body.decision_reason == "not worth GPU hours"

    with pytest.raises(Exception):
        FuzzProposalDecideReject(decision_reason="")
