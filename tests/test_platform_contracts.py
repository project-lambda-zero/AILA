"""Platform contract shape tests (issue #61).

RegisteredSystem is the DB read shape and MUST tolerate columns the contract
does not declare (team_id, private_key_secret_id, future columns), otherwise
construction from an ORM row raises at response-serialization time -- the same
class of latent 500 documented for MalwareTargetSummary.capability_profile.
SSHIntegrationInput is the write payload and MUST keep rejecting undeclared
fields so agents cannot smuggle extra keys.
"""
from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from aila.platform.contracts.platform import RegisteredSystem, SSHIntegrationInput
from aila.platform.contracts.reasoning import ReasoningCaseState, ReasoningTurnDecision


def test_registered_system_ignores_undeclared_db_columns() -> None:
    """A RegisteredSystem built from a row with extra columns does not raise."""
    row = {
        "id": 7,
        "name": "web-01",
        "host": "10.0.0.5",
        "username": "aila",
        # Columns present on ManagedSystemRecord but not declared on the contract:
        "team_id": 3,
        "private_key_secret_id": "sec_abc",
        "some_future_column": "value",
    }
    system = RegisteredSystem.model_validate(row)
    assert system.id == 7
    assert system.name == "web-01"
    # The undeclared columns are ignored, not surfaced as attributes.
    assert not hasattr(system, "team_id")
    assert not hasattr(system, "some_future_column")


def test_registered_system_extra_config_is_ignore() -> None:
    """The read shape overrides the parent's forbid with ignore."""
    assert RegisteredSystem.model_config.get("extra") == "ignore"


def test_ssh_integration_input_still_forbids_extra() -> None:
    """The write payload keeps rejecting undeclared fields (agent cannot smuggle)."""
    assert SSHIntegrationInput.model_config.get("extra") == "forbid"
    with pytest.raises(ValidationError):
        SSHIntegrationInput.model_validate(
            {
                "name": "web-01",
                "host": "10.0.0.5",
                "username": "aila",
                "team_id": 3,  # not a declared write field -> rejected
            }
        )


def test_ssh_integration_input_accepts_declared_fields() -> None:
    """A well-formed write payload still validates."""
    payload = SSHIntegrationInput.model_validate(
        {"name": "web-01", "host": "10.0.0.5", "username": "aila"}
    )
    assert payload.port == 22
    assert payload.distro == "unknown"


def test_case_state_rejects_non_json_observables() -> None:
    """A datetime in observables fails at construction, not later at json.dumps."""
    with pytest.raises(ValidationError):
        ReasoningCaseState(observables={"when": datetime(2026, 7, 19)})


def test_turn_decision_rejects_non_json_observables() -> None:
    """Bytes in observables fail at construction."""
    with pytest.raises(ValidationError):
        ReasoningTurnDecision(reasoning="x", observables={"raw": b"\x00\x01"})


def test_observables_accept_plain_json_values() -> None:
    """JSON-serializable observables still construct (regression guard)."""
    cs = ReasoningCaseState(observables={"k": "v", "n": 1, "nested": {"a": [1, 2]}})
    assert cs.observables["n"] == 1
    td = ReasoningTurnDecision(reasoning="x", observables={"k": "v"})
    assert td.observables["k"] == "v"
