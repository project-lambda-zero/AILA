"""Explorer planner skips submit-locked branches (GitHub issue #311).

A branch inside a submit-rejection streak is already steered by a mandatory
gate directive. The planner must not run the explorer (no LLM call) and must
not inject a new top lead on those turns; any stale lead is cleared. Unlocked
branches and the flag-disabled path keep their existing behaviour.
"""
from __future__ import annotations

import logging

import pytest

import aila.modules.vr.agents.explorer_planner as ep
from aila.platform.contracts.reasoning import ReasoningCaseState

LOCK_KEYS: tuple[str, ...] = (
    "_unresolved_hyp_submit_rejected_count",
    "_draft_pending_reject_count",
    "_sibling_open_hyp_reject_count",
    "_promote_confirmed_submit_rejected_count",
    "_gate.positive_submit_refs.reject_count",
)


def _state(**observables: object) -> ReasoningCaseState:
    cs = ReasoningCaseState()
    cs.observables.update(observables)
    return cs


def _patch(monkeypatch: pytest.MonkeyPatch, *, enabled: bool) -> list[tuple[str, str]]:
    """Stub the flag and the explorer pass; return the list of explorer calls."""
    calls: list[tuple[str, str]] = []

    async def _enabled() -> bool:
        return enabled

    async def _explorer(*, investigation_id: str, branch_id: str, **_: object):
        calls.append((investigation_id, branch_id))
        return [
            ep.LateralDirection(
                score=1,
                origin="ledger",
                source="lateral_observation",
                file="src/parse.c",
                function="parse_hdr",
                reason="unchecked length",
            ),
        ]

    monkeypatch.setattr(ep, "_explorer_enabled", _enabled)
    monkeypatch.setattr(ep, "explorer_pass", _explorer)
    return calls


async def _run(cs: ReasoningCaseState) -> str | None:
    return await ep.maybe_run_explorer_planner(
        investigation_id="inv-1", branch_id="branch-1", case_state=cs,
        turn_number=1,
    )


@pytest.mark.parametrize("key", LOCK_KEYS)
async def test_locked_branch_skips_explorer_and_clears_stale_lead(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, key: str,
) -> None:
    calls = _patch(monkeypatch, enabled=True)
    cs = _state(**{key: 2, ep._TOP_LEAD_KEY: "stale lead"})
    caplog.set_level(logging.DEBUG, logger=ep.__name__)

    assert await _run(cs) is None
    assert calls == []
    assert ep._TOP_LEAD_KEY not in cs.observables
    assert not any(
        "injected top lead" in r.getMessage() for r in caplog.records
    )


async def test_unlocked_branch_runs_explorer_and_writes_directive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _patch(monkeypatch, enabled=True)
    cs = _state()

    directive = await _run(cs)

    assert calls == [("inv-1", "branch-1")]
    assert directive is not None
    assert "parse_hdr" in directive
    assert cs.observables[ep._TOP_LEAD_KEY] == directive


async def test_lead_resumes_after_counter_clears(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _patch(monkeypatch, enabled=True)
    cs = _state(_draft_pending_reject_count=1)

    assert await _run(cs) is None
    assert calls == []

    cs.observables.pop("_draft_pending_reject_count")
    directive = await _run(cs)

    assert calls == [("inv-1", "branch-1")]
    assert directive is not None
    assert cs.observables[ep._TOP_LEAD_KEY] == directive


async def test_disabled_flag_leaves_locked_branch_untouched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _patch(monkeypatch, enabled=False)
    cs = _state(_unresolved_hyp_submit_rejected_count=1, **{ep._TOP_LEAD_KEY: "stale lead"})

    assert await _run(cs) is None
    assert calls == []
    assert cs.observables[ep._TOP_LEAD_KEY] == "stale lead"
