"""Veto-threshold and edit-outcome contract tests.

Two changes covered:

(1) ``services/outcome_review.VETO_K`` raised from 1 to 2. A single
    sibling reject no longer flips the outcome state to ``rejected``.
    Background: masson ANALYSIS_REPORT carried both Stage 1 + Stage 2
    RAT config correctly, but a sibling reject built on the
    encoding-filter false-negative bug (``list_strings(encoding=utf16le,
    section=.rsrc) returns total=0``, fixed in bridge ``6133103`` +
    ida-headless ``e189669``) vetoed it via the old 1-reject hard veto
    despite a 2-1 approve majority. Raising to 2 requires a chorus
    rather than a solo to kill an outcome.

(2) New ``edit_outcome`` action on :class:`ReasoningTurnDecision`.
    Counterpart to the deferred ``request_edit`` vote -- this path
    merges patches into the canonical outcome's payload immediately
    instead of waiting on a synthesis pass. Tests cover the validator
    surface (the DB-backed service-layer behavior is exercised by the
    live worker after restart).
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from aila.modules.malware.services.outcome_review import VETO_K
from aila.platform.contracts.mcp_payload import PayloadKind
from aila.platform.contracts.reasoning import ReasoningTurnDecision


class TestVetoThreshold:
    """Veto threshold raised to 2 (chorus, not solo)."""

    def test_veto_k_is_two(self) -> None:
        # Hard-coded check: any future tweak to the constant fires a
        # test failure that names the regression directly. Operator
        # observed the 1-veto rule killing a correct masson
        # ANALYSIS_REPORT; this test pins the new value.
        assert VETO_K == 2

    def test_veto_k_documented_rationale(self) -> None:
        # Sanity-check that the docstring on the service module
        # mentions the rationale + the threshold value -- prevents a
        # silent revert that drops the explanation along with the
        # constant change.
        from aila.modules.malware.services import outcome_review

        doc = outcome_review.__doc__ or ""
        assert "VETO_K" in doc, "module docstring must name VETO_K"
        assert "veto" in doc.lower(), (
            "module docstring must explain the veto semantics"
        )


class TestEditOutcomeAction:
    """``edit_outcome`` action validators on ReasoningTurnDecision."""

    def test_action_literal_includes_edit_outcome(self) -> None:
        # The Literal type behind ``ReasoningAction`` must accept the
        # new value. Round-trip through model construction so a typo
        # in the enum addition fails here, not at runtime in the
        # malware researcher's dispatch branch.
        d = ReasoningTurnDecision(
            reasoning="x",
            action="edit_outcome",
            edit_outcome_id="00000000-0000-0000-0000-000000000001",
            edit_patches={"summary": "patched"},
        )
        assert d.action == "edit_outcome"
        assert d.edit_outcome_id == "00000000-0000-0000-0000-000000000001"
        assert d.edit_patches == {"summary": "patched"}

    def test_edit_requires_outcome_id(self) -> None:
        with pytest.raises(ValidationError) as ei:
            ReasoningTurnDecision(
                reasoning="x",
                action="edit_outcome",
                edit_patches={"summary": "patched"},
            )
        assert "edit_outcome_id" in str(ei.value)

    def test_edit_requires_non_empty_patches(self) -> None:
        with pytest.raises(ValidationError) as ei:
            ReasoningTurnDecision(
                reasoning="x",
                action="edit_outcome",
                edit_outcome_id="00000000-0000-0000-0000-000000000001",
                edit_patches={},
            )
        msg = str(ei.value)
        assert "edit_patches" in msg
        # The error message must point the agent at the right
        # alternative (submit_outcome_review with vote=approve) when
        # there's actually nothing to change.
        assert "approve" in msg

    def test_non_edit_actions_unaffected_by_edit_fields(self) -> None:
        # The new validator must only fire on ``action == 'edit_outcome'``.
        # A ``reasoning`` action with empty edit_patches must still
        # parse cleanly -- otherwise every non-edit turn would trip
        # the new validator.
        d = ReasoningTurnDecision(
            reasoning="just thinking",
            action="reasoning",
            edit_outcome_id=None,
            edit_patches={},
        )
        assert d.action == "reasoning"

    def test_edit_payload_kind_exists(self) -> None:
        # ``OUTCOME_EDIT`` must be in PayloadKind so the message
        # mapper can persist edit_outcome turns with the right
        # discriminator. Without this entry the mapper would fall
        # through to TEXT and lose the structured patch info.
        assert PayloadKind.OUTCOME_EDIT == "outcome_edit"
        assert PayloadKind.OUTCOME_EDIT in set(PayloadKind)

    def test_edit_outcome_id_validation_error_names_field(self) -> None:
        # Error messages from the validator are what the LLM client's
        # retry-with-correction prompt sees. They MUST name the
        # missing field by exact key so the next-turn correction is
        # mechanical.
        with pytest.raises(ValidationError) as ei:
            ReasoningTurnDecision(
                reasoning="x",
                action="edit_outcome",
                edit_patches={"summary": "x"},
            )
        assert "edit_outcome_id" in str(ei.value)
        assert "DRAFT OUTCOME UP FOR REVIEW" in str(ei.value)


class TestEditOutcomeServiceImports:
    """``edit_outcome`` is exported from the service module so the
    researcher can import it. Sanity check the public surface."""

    def test_edit_outcome_in_all(self) -> None:
        from aila.modules.malware.services import outcome_review

        assert "edit_outcome" in outcome_review.__all__
        assert hasattr(outcome_review, "edit_outcome")
        # EditOutcomeResult is intentionally not exported (internal
        # return shape) but the function itself is callable.
        assert callable(outcome_review.edit_outcome)

    def test_protected_keys_pinned(self) -> None:
        # Sensitive write-once keys that the agent must never patch
        # via edit_outcome. Locking the set here so a future "let's
        # also allow X" change re-reads this test and updates the
        # rationale.
        from aila.modules.malware.services.outcome_review import (
            _EDIT_OUTCOME_PROTECTED_KEYS,
        )

        expected = {
            "panel_contributions",
            "panel_summary",
            "verifier_report",
            "applied_by_synthesis",
        }
        assert _EDIT_OUTCOME_PROTECTED_KEYS == expected
