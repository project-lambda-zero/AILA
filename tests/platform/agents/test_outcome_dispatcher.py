"""Characterization tests for the extracted OutcomeDispatcher base (RFC-03 Phase 6).

Pins two invariants shared by both module dispatchers now that the
skeleton lives on the platform:

1. ``dispatch(outcome_id)`` on a missing row returns SKIPPED with
   reason ``"outcome_not_found"`` -- both for the vr subclass and the
   malware subclass. The base skeleton owns this path; the pre-
   extraction vr code raised ValueError and the pre-extraction malware
   code returned SKIPPED; the extraction normalises both to the
   defensive SKIPPED shape so an ARQ worker never retries a
   permanently-missing row.

2. ``dispatch(outcome_id)`` on a winning claim routes to the correct
   per-kind handler. For vr this is the if/elif chain in
   :meth:`OutcomeDispatcher._handle_kind`; for malware this is the
   registry lookup in :meth:`OutcomeDispatcher._handle_kind`.

Neither test hits the DB. Both patch
``aila.platform.agents.outcome_dispatcher.claim_outcome_for_dispatch``
so the winning claim is synthesised in-memory. The subclass hooks
that DO touch the DB (``_load_outcome_row`` for vr,
``_persist_dispatch_status`` for both) are swapped for AsyncMock
no-ops on the instance under test.

The full DB integration path for each module is covered by
``tests/test_vr_outcome_dispatcher.py`` and
``tests/test_malware_outcome_dispatch_api.py``; those tests still pass
against the extraction unchanged.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from aila.modules.malware.agents.outcome_dispatcher import (
    OutcomeDispatcher as MalwareOutcomeDispatcher,
)
from aila.modules.malware.contracts import OutcomeKind as MalwareOutcomeKind
from aila.modules.vr.agents.outcome_dispatcher import (
    OutcomeDispatcher as VROutcomeDispatcher,
)
from aila.modules.vr.contracts import OutcomeKind as VROutcomeKind
from aila.platform.agents.outcome_dispatcher import (
    OutcomeDispatcherBase,
    OutcomeDispatchResult,
)
from aila.platform.contracts.enums import OutcomeDispatchStatus
from aila.platform.services.outcome_dispatch import OutcomeClaim

# ---------------------------------------------------------------------------
# Base wiring
# ---------------------------------------------------------------------------


def test_both_dispatchers_inherit_from_platform_base() -> None:
    """The extraction wires both module dispatchers through the same base."""
    assert issubclass(VROutcomeDispatcher, OutcomeDispatcherBase)
    assert issubclass(MalwareOutcomeDispatcher, OutcomeDispatcherBase)


def test_default_error_kinds_are_module_specific() -> None:
    """Each module stamps its own OutcomeKind on the SKIPPED not-found result."""
    assert VROutcomeDispatcher._default_error_kind is VROutcomeKind.ASSESSMENT_REPORT
    assert MalwareOutcomeDispatcher._default_error_kind \
        is MalwareOutcomeKind.ANALYSIS_REPORT


def test_handler_error_policy_differs_per_module() -> None:
    """VR re-raises fatal handler errors; malware folds them into FAILED."""
    assert VROutcomeDispatcher._catch_handler_errors is False
    assert MalwareOutcomeDispatcher._catch_handler_errors is True


# ---------------------------------------------------------------------------
# Missing outcome -- both dispatchers return SKIPPED outcome_not_found
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_vr_dispatch_missing_outcome_returns_skipped() -> None:
    """A missing outcome yields SKIPPED with reason ``outcome_not_found``."""
    dispatcher = VROutcomeDispatcher(knowledge=object())
    with patch(
        "aila.platform.agents.outcome_dispatcher.claim_outcome_for_dispatch",
        new=AsyncMock(return_value=OutcomeClaim(found=False, won=False)),
    ):
        result = await dispatcher.dispatch("does-not-exist")

    assert result.dispatch_status == OutcomeDispatchStatus.SKIPPED
    assert result.reason == "outcome_not_found"
    assert result.dispatch_target is None
    # Stamped with the module's default_error_kind so the enum is valid.
    assert result.outcome_kind == VROutcomeKind.ASSESSMENT_REPORT


@pytest.mark.asyncio
async def test_malware_dispatch_missing_outcome_returns_skipped() -> None:
    """Same shape as the vr case -- normalised skip path lives in the base."""
    dispatcher = MalwareOutcomeDispatcher(knowledge=None)
    with patch(
        "aila.platform.agents.outcome_dispatcher.claim_outcome_for_dispatch",
        new=AsyncMock(return_value=OutcomeClaim(found=False, won=False)),
    ):
        result = await dispatcher.dispatch("does-not-exist")

    assert result.dispatch_status == OutcomeDispatchStatus.SKIPPED
    assert result.reason == "outcome_not_found"
    assert result.dispatch_target is None
    assert result.outcome_kind == MalwareOutcomeKind.ANALYSIS_REPORT


# ---------------------------------------------------------------------------
# Winning claim -- routes to the correct per-kind handler
# ---------------------------------------------------------------------------


def _winning_claim(kind_value: str) -> OutcomeClaim:
    """Build an OutcomeClaim as if the platform service won a fresh claim."""
    return OutcomeClaim(
        found=True,
        won=True,
        skip_reason=None,
        outcome_kind=kind_value,
        payload_json='{"answer": "x"}',
        investigation_id="inv-test",
    )


@pytest.mark.asyncio
async def test_vr_dispatch_routes_direct_finding_to_correct_handler() -> None:
    """A winning DIRECT_FINDING claim routes to ``_dispatch_direct_finding``."""
    dispatcher = VROutcomeDispatcher(knowledge=object())

    # The DB-touching hooks are unrelated to routing; swap them out.
    dispatcher._load_outcome_row = AsyncMock(return_value=None)  # type: ignore[method-assign]
    dispatcher._persist_dispatch_status = AsyncMock(  # type: ignore[method-assign]
        return_value=None,
    )
    expected = OutcomeDispatchResult(
        outcome_id="oc-1",
        outcome_kind=VROutcomeKind.DIRECT_FINDING,
        dispatch_status=OutcomeDispatchStatus.DISPATCHED,
        dispatch_target="vr_finding:f-1",
        reason="handler_called",
    )
    handler_mock = AsyncMock(return_value=expected)
    dispatcher._dispatch_direct_finding = handler_mock  # type: ignore[method-assign]
    # Sibling handlers must NOT fire; wire them to a raise so an
    # accidental mis-route lands loudly instead of silently returning
    # a plausible-looking result.
    for other in (
        "_dispatch_audit_memo",
        "_dispatch_variant_hunt_order",
        "_dispatch_campaign_launch",
        "_dispatch_profile_spec_draft",
        "_dispatch_patch_assessment_report",
    ):
        setattr(dispatcher, other, AsyncMock(side_effect=AssertionError(
            f"sibling handler {other} must not run for DIRECT_FINDING",
        )))

    with patch(
        "aila.platform.agents.outcome_dispatcher.claim_outcome_for_dispatch",
        new=AsyncMock(return_value=_winning_claim(
            VROutcomeKind.DIRECT_FINDING.value,
        )),
    ):
        result = await dispatcher.dispatch("oc-1")

    handler_mock.assert_awaited_once()
    call_kwargs = handler_mock.await_args.args
    # Positional signature: (outcome_id, investigation_id, payload)
    assert call_kwargs[0] == "oc-1"
    assert call_kwargs[1] == "inv-test"
    assert call_kwargs[2] == {"answer": "x"}
    # The result comes back unchanged and _persist_dispatch_status was called.
    assert result is expected
    dispatcher._persist_dispatch_status.assert_awaited_once()


@pytest.mark.asyncio
async def test_vr_dispatch_routes_not_yet_dispatchable_to_skipped() -> None:
    """A kind in ``_NOT_YET_DISPATCHABLE`` skips WITHOUT invoking any handler."""
    dispatcher = VROutcomeDispatcher(knowledge=object())
    dispatcher._load_outcome_row = AsyncMock(return_value=None)  # type: ignore[method-assign]
    dispatcher._persist_dispatch_status = AsyncMock(  # type: ignore[method-assign]
        return_value=None,
    )
    for other in (
        "_dispatch_audit_memo",
        "_dispatch_direct_finding",
        "_dispatch_variant_hunt_order",
        "_dispatch_campaign_launch",
        "_dispatch_profile_spec_draft",
        "_dispatch_patch_assessment_report",
    ):
        setattr(dispatcher, other, AsyncMock(side_effect=AssertionError(
            "no per-kind handler should run for a not-yet-dispatchable kind",
        )))

    with patch(
        "aila.platform.agents.outcome_dispatcher.claim_outcome_for_dispatch",
        new=AsyncMock(return_value=_winning_claim(
            VROutcomeKind.STRATEGY_DESCRIPTOR.value,
        )),
    ):
        result = await dispatcher.dispatch("oc-2")

    assert result.dispatch_status == OutcomeDispatchStatus.SKIPPED
    assert result.reason == "no_strategy_registry_consumer_yet"
    assert result.outcome_kind == VROutcomeKind.STRATEGY_DESCRIPTOR


@pytest.mark.asyncio
async def test_malware_dispatch_routes_analysis_report_to_correct_handler(
) -> None:
    """A winning ANALYSIS_REPORT claim routes through the registry to
    ``_dispatch_analysis_report`` and no sibling handler runs.
    """
    dispatcher = MalwareOutcomeDispatcher(knowledge=None)
    dispatcher._persist_dispatch_status = AsyncMock(  # type: ignore[method-assign]
        return_value=None,
    )
    expected = OutcomeDispatchResult(
        outcome_id="oc-3",
        outcome_kind=MalwareOutcomeKind.ANALYSIS_REPORT,
        dispatch_status=OutcomeDispatchStatus.DISPATCHED,
        dispatch_target="malware_investigation:inv-test",
        reason="terminal_report",
    )
    handler_mock = AsyncMock(return_value=expected)
    dispatcher._dispatch_analysis_report = handler_mock  # type: ignore[method-assign]
    for other in (
        "_dispatch_terminal",
        "_dispatch_unpack_target",
        "_dispatch_config_extractor",
        "_dispatch_yara_rule",
        "_dispatch_family_verdict",
        "_dispatch_playbook_record",
        "_dispatch_stalled",
        "_dispatch_sub_investigation",
    ):
        setattr(dispatcher, other, AsyncMock(side_effect=AssertionError(
            f"sibling handler {other} must not run for ANALYSIS_REPORT",
        )))

    with patch(
        "aila.platform.agents.outcome_dispatcher.claim_outcome_for_dispatch",
        new=AsyncMock(return_value=_winning_claim(
            MalwareOutcomeKind.ANALYSIS_REPORT.value,
        )),
    ):
        result = await dispatcher.dispatch("oc-3")

    handler_mock.assert_awaited_once()
    handler_kwargs = handler_mock.await_args.kwargs
    # Malware handlers take keyword-only args.
    assert handler_kwargs == {
        "outcome_id": "oc-3",
        "investigation_id": "inv-test",
        "payload": {"answer": "x"},
    }
    assert result is expected
    dispatcher._persist_dispatch_status.assert_awaited_once()


@pytest.mark.asyncio
async def test_malware_dispatch_routes_yara_rule_to_correct_handler() -> None:
    """A second kind routes to the registry entry for that kind, not to
    the first entry -- pins the whole registry, not one lucky lookup.
    """
    dispatcher = MalwareOutcomeDispatcher(knowledge=None)
    dispatcher._persist_dispatch_status = AsyncMock(  # type: ignore[method-assign]
        return_value=None,
    )
    expected = OutcomeDispatchResult(
        outcome_id="oc-4",
        outcome_kind=MalwareOutcomeKind.YARA_RULE,
        dispatch_status=OutcomeDispatchStatus.DISPATCHED,
        dispatch_target="malware_target:tgt-a",
        reason="yara_rule_persisted",
    )
    handler_mock = AsyncMock(return_value=expected)
    dispatcher._dispatch_yara_rule = handler_mock  # type: ignore[method-assign]
    for other in (
        "_dispatch_analysis_report",
        "_dispatch_terminal",
        "_dispatch_unpack_target",
        "_dispatch_config_extractor",
        "_dispatch_family_verdict",
        "_dispatch_playbook_record",
        "_dispatch_stalled",
        "_dispatch_sub_investigation",
    ):
        setattr(dispatcher, other, AsyncMock(side_effect=AssertionError(
            f"sibling handler {other} must not run for YARA_RULE",
        )))

    with patch(
        "aila.platform.agents.outcome_dispatcher.claim_outcome_for_dispatch",
        new=AsyncMock(return_value=_winning_claim(
            MalwareOutcomeKind.YARA_RULE.value,
        )),
    ):
        result = await dispatcher.dispatch("oc-4")

    handler_mock.assert_awaited_once()
    assert result is expected


# ---------------------------------------------------------------------------
# Not-won claim -- SKIPPED with the guard's reason (regression pin)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_vr_dispatch_not_won_claim_skips_with_reason() -> None:
    """A refused claim (draft outcome) returns SKIPPED with the guard's reason."""
    dispatcher = VROutcomeDispatcher(knowledge=object())
    dispatcher._load_outcome_row = AsyncMock(return_value=None)  # type: ignore[method-assign]
    dispatcher._persist_dispatch_status = AsyncMock(  # type: ignore[method-assign]
        return_value=None,
    )
    for other in (
        "_dispatch_audit_memo",
        "_dispatch_direct_finding",
        "_dispatch_variant_hunt_order",
    ):
        setattr(dispatcher, other, AsyncMock(side_effect=AssertionError(
            "no handler should run for a refused claim",
        )))

    refused = OutcomeClaim(
        found=True,
        won=False,
        skip_reason="draft_awaiting_sibling_quorum",
        outcome_kind=VROutcomeKind.DIRECT_FINDING.value,
        payload_json="{}",
        investigation_id="inv-x",
    )
    with patch(
        "aila.platform.agents.outcome_dispatcher.claim_outcome_for_dispatch",
        new=AsyncMock(return_value=refused),
    ):
        result = await dispatcher.dispatch("oc-5")

    assert result.dispatch_status == OutcomeDispatchStatus.SKIPPED
    assert result.reason == "draft_awaiting_sibling_quorum"
    assert result.outcome_kind == VROutcomeKind.DIRECT_FINDING
    # The base does not call _persist_dispatch_status on a not-won path;
    # the row is untouched (no CLAIMED write, no DISPATCHED write).
    dispatcher._persist_dispatch_status.assert_not_awaited()


@pytest.mark.asyncio
async def test_malware_dispatch_unknown_kind_lands_as_failed() -> None:
    """The guard's ``unknown_outcome_kind:X`` reason maps to FAILED, not SKIPPED.

    The guard runs inside the FOR UPDATE transaction and refuses the
    claim when the row's ``outcome_kind`` does not parse as a member
    of the module's OutcomeKind enum. The row stays PENDING; the
    result surfaces as FAILED so the operator dashboard shows a data-
    shape bug rather than an ordinary skip.
    """
    dispatcher = MalwareOutcomeDispatcher(knowledge=None)
    dispatcher._persist_dispatch_status = AsyncMock(  # type: ignore[method-assign]
        return_value=None,
    )
    refused = OutcomeClaim(
        found=True,
        won=False,
        skip_reason="unknown_outcome_kind:not_a_real_kind",
        outcome_kind="not_a_real_kind",
        payload_json="{}",
        investigation_id="inv-x",
    )
    with patch(
        "aila.platform.agents.outcome_dispatcher.claim_outcome_for_dispatch",
        new=AsyncMock(return_value=refused),
    ):
        result = await dispatcher.dispatch("oc-6")

    assert result.dispatch_status == OutcomeDispatchStatus.FAILED
    assert result.reason == "unknown_outcome_kind:not_a_real_kind"
    # Unparseable outcome_kind falls back to the module's default_error_kind.
    assert result.outcome_kind == MalwareOutcomeKind.ANALYSIS_REPORT
