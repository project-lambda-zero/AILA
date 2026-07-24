"""Pure-function tests for InfraDeathClassifier (RFC-07 first increment).

Verifies the finalizer's tail-death classifier collapses the three
signals (branch_turn_count, recent_turn_errors, llm_unhealthy_at_close)
into the correct verdict. No DB, no infra -- the classifier is
intentionally stateless so this suite runs in a few milliseconds.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from sqlmodel import select

from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.services.investigation_finalizers import (
    synthesize_no_finding_for_investigation as vr_synthesize_no_finding_for_investigation,
)
from aila.platform.contracts.enums import BranchStatus, InvestigationStatus
from aila.platform.services import investigation_finalizers as platform_fin
from aila.platform.services.infra_death import (
    RETRYABLE_INFRA_CLASSES,
    InfraDeathClassifier,
)
from aila.platform.uow import UnitOfWork


@pytest.fixture
def classifier() -> InfraDeathClassifier:
    """One classifier per test -- it holds no state, so identity does not matter."""
    return InfraDeathClassifier()


class TestClassifyInfraDeath:
    """Cases the caller MUST NOT synthesize a clean no-finding outcome for."""

    def test_llm_unhealthy_at_close_wins_over_clean_error_list(
        self, classifier: InfraDeathClassifier,
    ) -> None:
        """Live LLM outage at classification time is a hard infra-death signal."""
        verdict = classifier.classify(
            branch_turn_count=42,
            recent_turn_errors=[],
            llm_unhealthy_at_close=True,
        )
        assert verdict == "infra_death"

    def test_trailing_llm_error_class_flags_infra_death(
        self, classifier: InfraDeathClassifier,
    ) -> None:
        """A trailing LLMError from the retry-budget-exhausted path flips the verdict."""
        verdict = classifier.classify(
            branch_turn_count=7,
            recent_turn_errors=["LLMError"],
            llm_unhealthy_at_close=False,
        )
        assert verdict == "infra_death"

    def test_trailing_api_connection_error_flags_infra_death(
        self, classifier: InfraDeathClassifier,
    ) -> None:
        """openai APIConnectionError on the tail turn is a provider transport failure."""
        verdict = classifier.classify(
            branch_turn_count=3,
            recent_turn_errors=["APIConnectionError"],
            llm_unhealthy_at_close=False,
        )
        assert verdict == "infra_death"

    def test_trailing_rate_limit_flags_infra_death(
        self, classifier: InfraDeathClassifier,
    ) -> None:
        """429 exhaustion within the in-call budget still counts as infra death."""
        verdict = classifier.classify(
            branch_turn_count=15,
            recent_turn_errors=["RateLimitError"],
            llm_unhealthy_at_close=False,
        )
        assert verdict == "infra_death"

    def test_stale_no_progress_pseudo_class_flags_infra_death(
        self, classifier: InfraDeathClassifier,
    ) -> None:
        """The finalizer feeds ``stale_no_progress`` when a branch was killed for going dark."""
        verdict = classifier.classify(
            branch_turn_count=9,
            recent_turn_errors=["stale_no_progress"],
            llm_unhealthy_at_close=False,
        )
        assert verdict == "infra_death"

    def test_mixed_error_list_infra_class_anywhere_wins(
        self, classifier: InfraDeathClassifier,
    ) -> None:
        """One infra class buried in a list of otherwise-unknown strings still flips."""
        verdict = classifier.classify(
            branch_turn_count=20,
            recent_turn_errors=["ValueError", "AssertionError", "TimeoutError"],
            llm_unhealthy_at_close=False,
        )
        assert verdict == "infra_death"


class TestClassifyTerminal:
    """Cases the caller may proceed with the existing no-finding synthesis."""

    def test_all_clean_turns_return_terminal(
        self, classifier: InfraDeathClassifier,
    ) -> None:
        """Healthy LLM + no error signals = the run genuinely reached terminal."""
        verdict = classifier.classify(
            branch_turn_count=25,
            recent_turn_errors=[],
            llm_unhealthy_at_close=False,
        )
        assert verdict == "terminal"

    def test_zero_turns_returns_terminal_defers_to_outer_guard(
        self, classifier: InfraDeathClassifier,
    ) -> None:
        """Zero-turn is the outer function's job -- classifier defers by design."""
        verdict = classifier.classify(
            branch_turn_count=0,
            recent_turn_errors=[],
            llm_unhealthy_at_close=False,
        )
        assert verdict == "terminal"

    def test_zero_turns_even_with_llm_unhealthy_returns_terminal(
        self, classifier: InfraDeathClassifier,
    ) -> None:
        """Zero-turn short-circuits before every other signal.

        The outer zero-turn guard owns that shape and marks it FAILED
        via a distinct closed_reason. If the classifier relabelled it
        as infra_death the two paths would race on the same
        investigation.
        """
        verdict = classifier.classify(
            branch_turn_count=0,
            recent_turn_errors=["LLMError"],
            llm_unhealthy_at_close=True,
        )
        assert verdict == "terminal"

    def test_non_retryable_error_class_does_not_flip(
        self, classifier: InfraDeathClassifier,
    ) -> None:
        """An error class outside the retryable-infra set stays terminal.

        The operator sees the real no-finding outcome for a run that
        did finish cleanly despite one non-infra hiccup.
        """
        verdict = classifier.classify(
            branch_turn_count=12,
            recent_turn_errors=["ValueError", "AssertionError", "KeyError"],
            llm_unhealthy_at_close=False,
        )
        assert verdict == "terminal"

    def test_empty_string_error_class_ignored(
        self, classifier: InfraDeathClassifier,
    ) -> None:
        """An empty error-class string MUST NOT match anything in the frozenset."""
        verdict = classifier.classify(
            branch_turn_count=5,
            recent_turn_errors=[""],
            llm_unhealthy_at_close=False,
        )
        assert verdict == "terminal"


class TestRetryableInfraClasses:
    """Contract tests on the frozenset itself."""

    def test_frozen_and_non_empty(self) -> None:
        assert isinstance(RETRYABLE_INFRA_CLASSES, frozenset)
        assert len(RETRYABLE_INFRA_CLASSES) > 0

    def test_contains_expected_provider_classes(self) -> None:
        for expected in (
            "APIConnectionError",
            "APITimeoutError",
            "RateLimitError",
            "LLMError",
            "TimeoutError",
            "stale_no_progress",
        ):
            assert expected in RETRYABLE_INFRA_CLASSES, expected


# ---------------------------------------------------------------------------
# DB-backed integration test: proves the finalizer wires the classifier and
# downgrades a multi-turn all-stale investigation to FAILED with a distinct
# closed_reason. Guarded by test_db so a missing Postgres skips cleanly
# (the outer suite reports it rather than the classifier tests failing).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_finalizer_downgrades_stale_multi_turn_run_to_failed(
    test_db, monkeypatch,  # noqa: ARG001 -- fixture wires the test DB
) -> None:
    """Multi-turn investigation whose branches all closed stale => FAILED.

    Reproduces the RFC-07 gap: the outer LLM-health gate reads healthy at
    finalizer time, every branch is terminal via stale_no_progress_*, and
    without the classifier the previous behaviour would write a clean
    audit_memo outcome that reads as "we audited and found nothing".
    Expected new behaviour: investigation flips to FAILED, orphan branches
    close with reason=auto_closed_infra, no outcome row is written.
    """
    # Pin the outer LLM-health gate to healthy so we exercise the classifier
    # path -- otherwise the whole tick short-circuits with return 0 before
    # ever reaching the tail-death classification.
    monkeypatch.setattr(
        platform_fin, "is_llm_recently_unhealthy", lambda window_s=600.0: False,
    )

    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name="infra-death-fixture",
            slug="infra-death-fixture",
            description="",
            theme="custom",
            team_id="admin",
        )
        uow.session.add(ws)
        await uow.session.flush()

        target = VRTargetRecord(
            workspace_id=ws.id,
            team_id="admin",
            display_name="infra-death target",
            kind="android_apk",
            descriptor_json=json.dumps({"apk_path": "/tmp/x.apk"}),  # noqa: S108
            primary_language=None,
            secondary_languages_json="[]",
            tags_json="[]",
            mcp_handles_json="{}",
            status="active",
            capability_profile_json="{}",
        )
        uow.session.add(target)
        await uow.session.flush()

        inv = VRInvestigationRecord(
            target_id=target.id,
            team_id="admin",
            kind="variant_hunt",
            title="infra-death multi-turn",
            initial_question="multi-turn stale audit",
            status=InvestigationStatus.RUNNING.value,
            auto_pilot=False,
            strategy_family="vulnerability_research.test",
            cost_budget_usd=50.0,
        )
        uow.session.add(inv)
        await uow.session.flush()
        inv_id = inv.id

        for i, turn_count in enumerate((6, 8)):
            br = VRInvestigationBranchRecord(
                investigation_id=inv_id,
                status=BranchStatus.ABANDONED.value,
                turn_count=turn_count,
                fork_reason="primary" if i == 0 else "deliberation",
                persona_voice="halvar" if i == 0 else "noor",
                closed_reason="stale_no_progress_halted_120min",
                closed_at=datetime.now(UTC),
            )
            uow.session.add(br)
        await uow.session.commit()

    resolved = await vr_synthesize_no_finding_for_investigation(inv_id)
    assert resolved == 1, "finalizer should have resolved exactly one investigation"

    async with UnitOfWork() as uow:
        row = (
            await uow.session.exec(
                select(VRInvestigationRecord.status)
                .where(VRInvestigationRecord.id == inv_id),
            )
        ).first()
        status_value = row if isinstance(row, str) else row[0]
        assert status_value == InvestigationStatus.FAILED.value, (
            f"expected FAILED after infra_death downgrade, got {status_value!r}"
        )

        outcome_count_rows = (
            await uow.session.exec(
                select(VRInvestigationOutcomeRecord.id)
                .where(VRInvestigationOutcomeRecord.investigation_id == inv_id),
            )
        ).all()
        assert len(outcome_count_rows) == 0, (
            "infra_death path MUST NOT synthesize a no-finding outcome row"
        )
