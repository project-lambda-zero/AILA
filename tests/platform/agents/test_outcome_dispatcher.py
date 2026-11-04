"""Characterization tests for the extracted OutcomeDispatcher base (RFC-03 Phase 6).

Pins three invariants shared by both module dispatchers now that the
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

3. The pre-dispatch claim verification gate and the finalize
   aggregate's polarity read are driven by the ``claim_verification``
   hook each module binds on its dispatcher class (issue #286). The
   platform base never imports a module: vr binds its polarity contract
   and claim verifier, malware binds none and is never gated.

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

import ast
import inspect
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

import aila.platform.agents.outcome_dispatcher as platform_dispatcher
from aila.modules.malware.agents.outcome_dispatcher import (
    OutcomeDispatcher as MalwareOutcomeDispatcher,
)
from aila.modules.malware.contracts import OutcomeKind as MalwareOutcomeKind
from aila.modules.vr.agents.outcome_dispatcher import (
    OutcomeDispatcher as VROutcomeDispatcher,
)
from aila.modules.vr.contracts import OutcomeKind as VROutcomeKind
from aila.modules.vr.contracts.outcome import outcome_polarity as vr_outcome_polarity
from aila.platform.agents.outcome_dispatcher import (
    ClaimVerificationHook,
    OutcomeDispatcherBase,
    OutcomeDispatchResult,
    _select_strongest_positive,
)
from aila.platform.contracts.enums import OutcomeDispatchStatus
from aila.platform.services.outcome_dispatch import OutcomeClaim

# ---------------------------------------------------------------------------
# Base wiring
# ---------------------------------------------------------------------------


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


def _vr_hook_with(verifier: AsyncMock) -> ClaimVerificationHook:
    """VR's real polarity contract with its claim verifier swapped for ``verifier``."""
    return ClaimVerificationHook(
        polarity=vr_outcome_polarity,
        verify_evidence=verifier,
    )


def _vr_dispatcher() -> VROutcomeDispatcher:
    """A VR dispatcher with the DB-touching hooks stubbed out."""
    dispatcher = VROutcomeDispatcher(knowledge=object())
    dispatcher._load_outcome_row = AsyncMock(return_value=None)  # type: ignore[method-assign]
    dispatcher._persist_dispatch_status = AsyncMock(  # type: ignore[method-assign]
        return_value=None,
    )
    return dispatcher


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

    # The pre-dispatch verifier gate (issue #13/#14/#249 W13) fires for
    # every positive-polarity outcome kind, DIRECT_FINDING included, and
    # VR's bound hook would run a real DB-touching adversarial check
    # unless its verifier is stubbed. Swapping only ``verify_evidence``
    # for a confirming stub (VR's real polarity stays) keeps the routing
    # assertion pure -- does the winning claim reach the matching
    # per-kind handler? -- while the gate still runs: the verifier is
    # awaited once. The gate's blocking behaviour is covered by the
    # dedicated hook tests below.
    verifier = AsyncMock(return_value={"verdict": "confirmed"})
    with patch(
        "aila.platform.agents.outcome_dispatcher.claim_outcome_for_dispatch",
        new=AsyncMock(return_value=_winning_claim(
            VROutcomeKind.DIRECT_FINDING.value,
        )),
    ), patch.object(
        VROutcomeDispatcher, "claim_verification", _vr_hook_with(verifier),
    ):
        result = await dispatcher.dispatch("oc-1")

    verifier.assert_awaited_once()
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
        "_dispatch_strategy_descriptor",
        "_dispatch_crash_triage_report",
        "_dispatch_config_delta",
        "_dispatch_sub_investigation",
    ):
        setattr(dispatcher, other, AsyncMock(side_effect=AssertionError(
            "no per-kind handler should run for a not-yet-dispatchable kind",
        )))

    with patch(
        "aila.platform.agents.outcome_dispatcher.claim_outcome_for_dispatch",
        new=AsyncMock(return_value=_winning_claim(
            VROutcomeKind.ASSESSMENT_REPORT.value,
        )),
    ):
        result = await dispatcher.dispatch("oc-2")

    assert result.dispatch_status == OutcomeDispatchStatus.SKIPPED
    assert result.reason == "assessment_reports_are_terminal_no_downstream"
    assert result.outcome_kind == VROutcomeKind.ASSESSMENT_REPORT


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


# ---------------------------------------------------------------------------
# Claim verification hook (issue #286) -- the platform base imports no module
# ---------------------------------------------------------------------------


def test_platform_dispatcher_imports_no_module() -> None:
    """The platform dispatcher never imports a module package, even deferred.

    The verifier gate and the finalize aggregate reach a module only
    through the ``claim_verification`` hook bound on its dispatcher
    class. A module import anywhere in the file -- at module scope or
    inside a function -- puts back the platform -> module dependency
    issue #286 removed.
    """
    tree = ast.parse(inspect.getsource(platform_dispatcher))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module)
            imported.update(f"{node.module}.{alias.name}" for alias in node.names)
    offenders = sorted(
        name for name in imported
        if name == "aila.modules" or name.startswith("aila.modules.")
    )
    assert offenders == []


def test_vr_binds_its_polarity_contract_and_claim_verifier() -> None:
    """VR hands the platform base its polarity contract and claim verifier."""
    hook = VROutcomeDispatcher.claim_verification

    assert isinstance(hook, ClaimVerificationHook)
    assert hook.polarity is vr_outcome_polarity
    assert hook.polarity(VROutcomeKind.DIRECT_FINDING) == "positive"
    assert hook.polarity(VROutcomeKind.CRASH_TRIAGE_REPORT) == "positive"
    assert hook.polarity(VROutcomeKind.AUDIT_MEMO) == "negative"
    assert hook.polarity(VROutcomeKind.ASSESSMENT_REPORT) == "inconclusive"


def test_malware_binds_no_claim_verification_hook() -> None:
    """Malware has no truth-polarity contract, so the base default (no gate) stands."""
    assert OutcomeDispatcherBase.claim_verification is None
    assert MalwareOutcomeDispatcher.claim_verification is None


@pytest.mark.asyncio
async def test_vr_hook_verifier_delegates_to_the_claim_verifier() -> None:
    """VR's bound ``verify_evidence`` forwards the packet to the claim verifier.

    ``claim_verifier`` imports the VR dispatcher, so the hook resolves
    ``verify_evidence`` on each call rather than at import time;
    patching the module attribute therefore reaches the already-bound
    hook.
    """
    packet = {
        "claim": "x",
        "index_id": "idx-1",
        "case_state": {"investigation_id": "inv-test"},
        "citations": [],
        "tool_calls": [],
    }
    verdict = {"verdict": "confirmed"}
    with patch(
        "aila.modules.vr.agents.claim_verifier.verify_evidence",
        new=AsyncMock(return_value=verdict),
    ) as claim_verifier:
        result = await VROutcomeDispatcher.claim_verification.verify_evidence(packet)

    assert result is verdict
    claim_verifier.assert_awaited_once_with(packet)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("verdict", "expected_reason"),
    [
        (
            {"verdict": "refuted", "summary": "no reachable sink"},
            "verifier_blocked:refuted (no reachable sink)",
        ),
        ({}, "verifier_blocked:no_verdict"),
    ],
)
async def test_vr_positive_claim_is_blocked_unless_confirmed(
    verdict: dict[str, str], expected_reason: str,
) -> None:
    """A positive outcome the verifier does not confirm lands SKIPPED, handler unrun."""
    dispatcher = _vr_dispatcher()
    handler_mock = AsyncMock(side_effect=AssertionError(
        "an unconfirmed claim must not reach its handler",
    ))
    dispatcher._dispatch_direct_finding = handler_mock  # type: ignore[method-assign]
    verifier = AsyncMock(return_value=verdict)

    with patch(
        "aila.platform.agents.outcome_dispatcher.claim_outcome_for_dispatch",
        new=AsyncMock(return_value=_winning_claim(
            VROutcomeKind.DIRECT_FINDING.value,
        )),
    ), patch.object(
        VROutcomeDispatcher, "claim_verification", _vr_hook_with(verifier),
    ):
        result = await dispatcher.dispatch("oc-7")

    assert result.dispatch_status == OutcomeDispatchStatus.SKIPPED
    assert result.outcome_kind == VROutcomeKind.DIRECT_FINDING
    assert result.dispatch_target is None
    assert result.reason == expected_reason
    verifier.assert_awaited_once()
    handler_mock.assert_not_awaited()
    # The gate's verdict is persisted as the outcome's terminal status.
    dispatcher._persist_dispatch_status.assert_awaited_once_with(
        outcome_id="oc-7", result=result,
    )


@pytest.mark.asyncio
async def test_vr_verifier_failure_is_a_fail_safe_allow() -> None:
    """A verifier that raises is logged and the claim dispatches as if unchecked."""
    dispatcher = _vr_dispatcher()
    expected = OutcomeDispatchResult(
        outcome_id="oc-8",
        outcome_kind=VROutcomeKind.DIRECT_FINDING,
        dispatch_status=OutcomeDispatchStatus.DISPATCHED,
        dispatch_target="vr_finding:f-8",
        reason="handler_called",
    )
    handler_mock = AsyncMock(return_value=expected)
    dispatcher._dispatch_direct_finding = handler_mock  # type: ignore[method-assign]
    verifier = AsyncMock(side_effect=RuntimeError("audit-mcp unreachable"))

    with patch(
        "aila.platform.agents.outcome_dispatcher.claim_outcome_for_dispatch",
        new=AsyncMock(return_value=_winning_claim(
            VROutcomeKind.DIRECT_FINDING.value,
        )),
    ), patch.object(
        VROutcomeDispatcher, "claim_verification", _vr_hook_with(verifier),
    ):
        result = await dispatcher.dispatch("oc-8")

    assert result is expected
    verifier.assert_awaited_once()
    handler_mock.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind",
    [VROutcomeKind.DIRECT_FINDING, VROutcomeKind.CRASH_TRIAGE_REPORT],
)
async def test_vr_positive_kinds_are_verified_with_the_base_packet(
    kind: VROutcomeKind,
) -> None:
    """A positive kind is verified, and the verifier gets the base evidence packet."""
    dispatcher = _vr_dispatcher()
    verifier = AsyncMock(return_value={"verdict": "confirmed"})

    with patch.object(
        VROutcomeDispatcher, "claim_verification", _vr_hook_with(verifier),
    ):
        gate = await dispatcher._verify_before_dispatch(
            outcome_kind=kind,
            outcome_id="oc-9",
            investigation_id="inv-test",
            payload={"answer": "x"},
            outcome_row=None,
        )

    assert gate is None  # confirmed -> dispatch proceeds
    verifier.assert_awaited_once_with({
        "claim": "x",
        "index_id": "",
        "case_state": {
            "outcome_id": "oc-9",
            "investigation_id": "inv-test",
            "outcome_kind": kind.value,
            "payload": {"answer": "x"},
        },
        "citations": [],
        "tool_calls": [],
    })


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind",
    [
        VROutcomeKind.AUDIT_MEMO,
        VROutcomeKind.ASSESSMENT_REPORT,
        VROutcomeKind.VARIANT_HUNT_ORDER,
    ],
)
async def test_vr_non_positive_kinds_never_reach_the_verifier(
    kind: VROutcomeKind,
) -> None:
    """Only ``positive`` polarity is gated: negative and inconclusive kinds skip it."""
    dispatcher = _vr_dispatcher()
    verifier = AsyncMock(return_value={"verdict": "refuted"})

    with patch.object(
        VROutcomeDispatcher, "claim_verification", _vr_hook_with(verifier),
    ):
        gate = await dispatcher._verify_before_dispatch(
            outcome_kind=kind,
            outcome_id="oc-10",
            investigation_id="inv-test",
            payload={"answer": "x"},
            outcome_row=None,
        )

    assert gate is None
    verifier.assert_not_awaited()


@pytest.mark.asyncio
async def test_dispatcher_without_a_hook_runs_no_verifier_gate() -> None:
    """With no ``claim_verification`` bound the gate allows without building a packet."""
    dispatcher = MalwareOutcomeDispatcher(knowledge=None)
    dispatcher._build_evidence_packet = AsyncMock(  # type: ignore[method-assign]
        side_effect=AssertionError("no hook is bound, so no packet is built"),
    )

    gate = await dispatcher._verify_before_dispatch(
        outcome_kind=MalwareOutcomeKind.ANALYSIS_REPORT,
        outcome_id="oc-11",
        investigation_id="inv-test",
        payload={"answer": "x"},
        outcome_row=None,
    )

    assert gate is None
    dispatcher._build_evidence_packet.assert_not_awaited()


# ---------------------------------------------------------------------------
# Finalize aggregate -- strongest-positive selection reads the injected polarity
# ---------------------------------------------------------------------------


def _outcome_row(kind: str, confidence: str) -> SimpleNamespace:
    """The two columns ``_select_strongest_positive`` reads off an outcome row."""
    return SimpleNamespace(outcome_kind=kind, confidence=confidence)


def test_strongest_positive_follows_the_injected_polarity() -> None:
    """Promotion is decided by the module's polarity, not one the platform holds."""

    def polarity(kind: str) -> str:
        return "positive" if kind == "proven_widget" else "inconclusive"

    caveated = _outcome_row("proven_widget", "caveated")
    strong = _outcome_row("proven_widget", "strong")
    # Positive under VR's contract, inconclusive under this one: the
    # platform asks only the function it was handed.
    other_module_finding = _outcome_row("direct_finding", "exact")

    best, supporting = _select_strongest_positive(
        {"sig-a": [caveated, strong], "sig-b": [other_module_finding]},
        polarity,
    )

    assert best is strong
    assert supporting == [caveated]


def test_strongest_positive_uses_vr_polarity_from_its_bound_hook() -> None:
    """VR's bound polarity promotes a finding over a settled no-finding memo."""
    finding = _outcome_row("direct_finding", "strong")
    memo = _outcome_row("audit_memo", "exact")

    best, supporting = _select_strongest_positive(
        {"sig-a": [memo], "sig-b": [finding]},
        VROutcomeDispatcher.claim_verification.polarity,
    )

    assert best is finding
    assert supporting == []


def test_strongest_positive_without_a_polarity_promotes_nothing() -> None:
    """No hook means no polarity: every outcome counts as inconclusive."""
    groups = {"sig-a": [_outcome_row("direct_finding", "exact")]}

    assert _select_strongest_positive(groups, None) == (None, [])
