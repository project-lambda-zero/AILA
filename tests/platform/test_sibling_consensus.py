"""Sibling-consensus injector (RFC-03 Phase 2).

Pure function -- no DB. Pins the 2-sibling threshold, the directive
payload shape, and the no-op guards so the turn runners can bind it
without silent drift.
"""
from __future__ import annotations

from types import SimpleNamespace

from aila.platform.agents.sibling_consensus import inject_sibling_consensus

_KEY = "_directive.sibling_consensus_rejection"


def _cs() -> SimpleNamespace:
    return SimpleNamespace(observables={})


def test_two_siblings_rejecting_sets_directive() -> None:
    cs = _cs()
    sibs = [
        {"persona_voice": "a", "rejected": [{"id": "h1", "claim": "no evidence"}]},
        {"persona_voice": "b", "rejected": [{"id": "h1", "claim": "refuted"}]},
    ]

    out = inject_sibling_consensus(cs, sibs, {"h1"})

    assert _KEY in out.observables
    directive = out.observables[_KEY]
    assert "SIBLING CONSENSUS REJECTION" in directive
    assert "id=h1" in directive
    assert "a: no evidence" in directive
    assert "b: refuted" in directive


def test_single_rejection_below_threshold_is_noop() -> None:
    cs = _cs()
    sibs = [
        {"persona_voice": "a", "rejected": [{"id": "h1", "claim": "no evidence"}]},
    ]

    out = inject_sibling_consensus(cs, sibs, {"h1"})

    assert _KEY not in out.observables


def test_rejections_of_ids_not_live_are_ignored() -> None:
    cs = _cs()
    sibs = [
        {"persona_voice": "a", "rejected": [{"id": "h9", "claim": "x"}]},
        {"persona_voice": "b", "rejected": [{"id": "h9", "claim": "y"}]},
    ]

    # h9 is not in my_live_ids -> nothing to confront this branch with.
    out = inject_sibling_consensus(cs, sibs, {"h1"})

    assert _KEY not in out.observables


def test_empty_inputs_are_noop() -> None:
    assert _KEY not in inject_sibling_consensus(_cs(), [], set()).observables
    assert _KEY not in inject_sibling_consensus(_cs(), [], {"h1"}).observables
    sibs = [{"persona_voice": "a", "rejected": [{"id": "h1", "claim": "x"}]}]
    assert _KEY not in inject_sibling_consensus(_cs(), sibs, set()).observables
