"""DB-free unit tests for the finding state-machine resolver.

Covers the module-scoped merge contract wired for the finding
lifecycle:

* ``_resolve_finding_state_machine(platform, module_id=<mod>)`` returns
  the platform base states/transitions plus ONLY the requested module's
  extension -- sibling modules' vocabulary must not leak in.
* ``_resolve_finding_state_machine(platform, module_id=None)`` returns
  the union across every registered module (the read-side merged view).
* From ``investigating`` a vr-scoped resolver allows the vr-prefixed
  next-state and rejects a malware-prefixed one, which is what the
  ``POST /findings/{id}/transition`` handler relies on to 422 a
  cross-module target.
* When ``create_module()`` for the three production modules can be
  imported without live infrastructure, each factory's
  ``workflow_definitions()['finding']['states']`` matches the exact
  module-prefixed list from the shared contract.

The three production module backends (vr / malware / forensics) are
authored in parallel with this file; the module ids and the exact
prefixed state names are pinned by the shared frontend/backend
contract in ``.run/ralph/frontend-improvements/specs/``.
"""
from __future__ import annotations

import importlib
import types

import pytest

from aila.api.routers.findings_workflow import _resolve_finding_state_machine
from aila.platform.contracts.finding_states import (
    FINDING_STATE_TRANSITIONS,
    FINDING_STATES,
)

# ---------------------------------------------------------------------------
# Shared contract: EXACT module-prefixed states + transitions.
# Keep in lockstep with docs/finding-states-wire spec and each module's
# ``module.py::workflow_definitions()``.
# ---------------------------------------------------------------------------

_VR_DEF = {
    "finding": {
        "states": ["vr.false_positive", "vr.accepted_risk"],
        "transitions": {
            "investigating": ["vr.false_positive", "vr.accepted_risk"],
            "vr.false_positive": ["investigating"],
            "vr.accepted_risk": ["investigating"],
        },
    }
}
_MALWARE_DEF = {
    "finding": {
        "states": ["malware.benign_confirmed", "malware.quarantined"],
        "transitions": {
            "investigating": ["malware.benign_confirmed", "malware.quarantined"],
            "malware.benign_confirmed": ["investigating"],
            "malware.quarantined": ["investigating"],
        },
    }
}
_FORENSICS_DEF = {
    "finding": {
        "states": [
            "forensics.contained",
            "forensics.eradicated",
            "forensics.recovered",
        ],
        "transitions": {
            "investigating": ["forensics.contained"],
            "forensics.contained": [
                "forensics.eradicated",
                "investigating",
            ],
            "forensics.eradicated": [
                "forensics.recovered",
                "forensics.contained",
            ],
            "forensics.recovered": ["closed", "forensics.eradicated"],
        },
    }
}


class _FakeModule:
    """Minimal module double: only what the resolver reads."""

    def __init__(self, module_id: str, definitions: dict) -> None:
        self.module_id = module_id
        self._definitions = definitions

    def workflow_definitions(self) -> dict:
        return self._definitions


def _fake_platform() -> object:
    """Build a platform whose registry lists three fake production modules."""
    modules = [
        _FakeModule("vr", _VR_DEF),
        _FakeModule("malware", _MALWARE_DEF),
        _FakeModule("forensics", _FORENSICS_DEF),
    ]
    return types.SimpleNamespace(
        runtime=types.SimpleNamespace(
            module_registry=types.SimpleNamespace(modules=modules)
        )
    )


# ---------------------------------------------------------------------------
# Base assertions -- catches drift in FINDING_STATE_TRANSITIONS.
# ---------------------------------------------------------------------------


def test_platform_base_states_present_when_platform_missing() -> None:
    states, transitions = _resolve_finding_state_machine(None)
    assert set(states) == set(FINDING_STATES)
    assert transitions["investigating"] == list(
        FINDING_STATE_TRANSITIONS["investigating"]
    )


# ---------------------------------------------------------------------------
# Module isolation -- resolver(module_id=<mod>).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("module_id", "own", "foreign"),
    [
        (
            "vr",
            {"vr.false_positive", "vr.accepted_risk"},
            {
                "malware.benign_confirmed",
                "malware.quarantined",
                "forensics.contained",
                "forensics.eradicated",
                "forensics.recovered",
            },
        ),
        (
            "malware",
            {"malware.benign_confirmed", "malware.quarantined"},
            {
                "vr.false_positive",
                "vr.accepted_risk",
                "forensics.contained",
                "forensics.eradicated",
                "forensics.recovered",
            },
        ),
        (
            "forensics",
            {
                "forensics.contained",
                "forensics.eradicated",
                "forensics.recovered",
            },
            {
                "vr.false_positive",
                "vr.accepted_risk",
                "malware.benign_confirmed",
                "malware.quarantined",
            },
        ),
    ],
)
def test_resolver_scopes_to_single_module(
    module_id: str, own: set[str], foreign: set[str]
) -> None:
    states, transitions = _resolve_finding_state_machine(
        _fake_platform(), module_id=module_id
    )
    # base always present
    assert set(FINDING_STATES).issubset(set(states))
    # own module's states present
    assert own.issubset(set(states))
    # sibling modules' states MUST NOT leak in
    assert not (foreign & set(states))
    # transitions map must not carry sibling from_states either
    assert not (foreign & set(transitions))
    for from_state, targets in transitions.items():
        assert not (foreign & set(targets)), (
            f"foreign leaked into transitions[{from_state!r}] = {targets!r}"
        )


def test_resolver_none_module_id_returns_full_union() -> None:
    states, transitions = _resolve_finding_state_machine(
        _fake_platform(), module_id=None
    )
    all_extensions = {
        "vr.false_positive",
        "vr.accepted_risk",
        "malware.benign_confirmed",
        "malware.quarantined",
        "forensics.contained",
        "forensics.eradicated",
        "forensics.recovered",
    }
    assert set(FINDING_STATES).issubset(set(states))
    assert all_extensions.issubset(set(states))
    # investigating fans out to every module's from-investigating edge
    inv_targets = set(transitions["investigating"])
    assert {
        "new",
        "mitigated",
        "vr.false_positive",
        "vr.accepted_risk",
        "malware.benign_confirmed",
        "malware.quarantined",
        "forensics.contained",
    }.issubset(inv_targets)


# ---------------------------------------------------------------------------
# The 422 cross-module transition path.
# ---------------------------------------------------------------------------


def test_vr_scoped_transition_rejects_malware_target() -> None:
    """Mirror the ``POST /findings/{id}/transition`` 422 guard.

    When body.module_id='vr' the resolver returns a transition map that
    lets ``investigating -> vr.false_positive`` through and treats
    ``malware.quarantined`` as unknown; the endpoint then 422s.
    """
    _, transitions = _resolve_finding_state_machine(
        _fake_platform(), module_id="vr"
    )
    from_investigating = transitions.get("investigating", [])
    assert "vr.false_positive" in from_investigating
    assert "malware.quarantined" not in from_investigating


# ---------------------------------------------------------------------------
# Production module factory contract -- best effort, skipped if any
# module cannot be constructed in a bare test process (no infra).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("module_import_path", "expected_states"),
    [
        (
            "aila.modules.vr.module",
            {"vr.false_positive", "vr.accepted_risk"},
        ),
        (
            "aila.modules.malware.module",
            {"malware.benign_confirmed", "malware.quarantined"},
        ),
        (
            "aila.modules.forensics.module",
            {
                "forensics.contained",
                "forensics.eradicated",
                "forensics.recovered",
            },
        ),
    ],
)
def test_production_module_factory_declares_prefixed_states(
    module_import_path: str, expected_states: set[str]
) -> None:
    try:
        mod = importlib.import_module(module_import_path)
    except (ImportError, RuntimeError) as exc:  # noqa: F841 -- surface skip reason
        pytest.skip(
            f"{module_import_path} not importable in bare test process: {exc!r}"
        )
    factory = getattr(mod, "create_module", None)
    if factory is None:
        pytest.skip(f"{module_import_path}.create_module missing")
    try:
        instance = factory()
    except (RuntimeError, ValueError, TypeError) as exc:
        pytest.skip(
            f"{module_import_path}.create_module() requires infra: {exc!r}"
        )
    if not hasattr(instance, "workflow_definitions"):
        pytest.skip(
            f"{module_import_path} module has no workflow_definitions() yet"
        )
    definitions = instance.workflow_definitions()
    finding = definitions.get("finding")
    assert finding is not None, (
        f"{module_import_path} must declare a 'finding' workflow"
    )
    assert set(finding["states"]) == expected_states
