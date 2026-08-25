"""AC3 lock: out-of-module transition targets report the transition phrasing.

specs/finding-states-wire.md AC3 (lines 138-140): POSTing
``{module_id: "vr", target_state: "malware.quarantined"}`` against a
finding in ``investigating`` must 422 with "Transition from
'investigating' to 'malware.quarantined' is not allowed."

The pre-fix branch order validated the target against the
module-scoped state list BEFORE loading the finding's current state, so
every out-of-module target died in the "Unknown state ..." branch and
the spec-asserted message was unreachable. These tests lock the reorder:
a real state from a sibling module reports the transition phrasing,
while a target known to no module keeps the unknown-state message with
the valid list.

Direct handler invocation (the ``test_p0_team_scoping_findings_specialists``
pattern) with a stub request whose platform carries fake production
modules declaring the same prefixed states the real modules declare in
``module.py::workflow_definitions()``.
"""
from __future__ import annotations

import types

import pytest
from fastapi import HTTPException

from aila.api.auth import AuthContext
from aila.api.routers.findings_workflow import router as fw_router
from aila.api.schemas.endpoints import FindingTransitionRequest
from aila.storage.database import async_session_scope
from aila.storage.db_models import FindingWorkflowRecord

_TRANSITION = "/findings/{finding_id}/transition"

# Module extensions mirror the production contracts in
# src/aila/modules/{vr,malware}/module.py::workflow_definitions().
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


class _FakeModule:
    """Minimal module double: only what the resolver reads."""

    def __init__(self, module_id: str, definitions: dict) -> None:
        self.module_id = module_id
        self._definitions = definitions

    def workflow_definitions(self) -> dict:
        return self._definitions


def _req() -> object:
    """Request stub whose platform registers fake production modules."""
    modules = [
        _FakeModule("vr", _VR_DEF),
        _FakeModule("malware", _MALWARE_DEF),
    ]
    return types.SimpleNamespace(
        app=types.SimpleNamespace(
            state=types.SimpleNamespace(
                platform=types.SimpleNamespace(
                    runtime=types.SimpleNamespace(
                        module_registry=types.SimpleNamespace(modules=modules)
                    )
                )
            )
        )
    )


def _auth() -> AuthContext:
    return AuthContext(
        user_id="u-god",
        role="operator",
        auth_type="user",
        team_id=None,
    )


def _transition_endpoint():
    for route in fw_router.routes:
        if getattr(route, "path", None) == _TRANSITION and "POST" in getattr(
            route, "methods", set()
        ):
            return route.endpoint
    raise AssertionError(f"route POST {_TRANSITION} not registered")


async def _seed_investigating(finding_id: str) -> None:
    """Insert one FindingWorkflowRecord so the finding reads as 'investigating'."""
    async with async_session_scope() as session:
        record = FindingWorkflowRecord(
            finding_id=finding_id,
            module_id="vr",
            current_state="investigating",
            previous_state="new",
            transitioned_by="seed",
            notes="",
            team_id=None,
        )
        session.add(record)
        await session.commit()


@pytest.mark.usefixtures("test_db")
async def test_cross_module_target_reports_transition_phrasing() -> None:
    """AC3: malware.quarantined against a vr finding 422s with the transition message."""
    await _seed_investigating("F-AC3")
    endpoint = _transition_endpoint()
    with pytest.raises(HTTPException) as exc:
        await endpoint(
            request=_req(),
            finding_id="F-AC3",
            body=FindingTransitionRequest(
                target_state="malware.quarantined", module_id="vr"
            ),
            auth=_auth(),
        )
    assert exc.value.status_code == 422
    assert (
        "Transition from 'investigating' to 'malware.quarantined' is not allowed."
        in exc.value.detail
    )


@pytest.mark.usefixtures("test_db")
async def test_genuinely_unknown_target_keeps_unknown_state_message() -> None:
    """A target known to no module keeps the vocabulary-error message + valid list."""
    await _seed_investigating("F-UNKNOWN")
    endpoint = _transition_endpoint()
    with pytest.raises(HTTPException) as exc:
        await endpoint(
            request=_req(),
            finding_id="F-UNKNOWN",
            body=FindingTransitionRequest(
                target_state="malware.quarantind", module_id="vr"
            ),
            auth=_auth(),
        )
    assert exc.value.status_code == 422
    detail = exc.value.detail
    assert "Unknown state 'malware.quarantind'" in detail
    assert "Valid:" in detail
    # The module-scoped valid list never leaks the malware vocabulary
    # (the typo'd target string itself starts with the module prefix).
    assert "malware.quarantined" not in detail
