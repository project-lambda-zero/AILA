"""Platform contract shape tests (issue #61).

RegisteredSystem is the DB read shape and MUST tolerate columns the contract
does not declare (team_id, private_key_secret_id, future columns), otherwise
construction from an ORM row raises at response-serialization time -- the same
class of latent 500 documented for MalwareTargetSummary.capability_profile.
SSHIntegrationInput is the write payload and MUST keep rejecting undeclared
fields so agents cannot smuggle extra keys.

Also pins the contract-hygiene residuals fixed alongside the listed items:

- ``BudgetConfig`` / ``BudgetState`` reject undeclared fields, so a caller
  typing ``max_turn=`` instead of ``max_turns=`` fails at construction,
  not silently at runtime with the default value.
- ``obligations.adjudicate`` returns the expected verdict for each of the
  four documented paths (accepted / downgraded on hedge / downgraded on
  unmet required / blocked on unmet critical) so the pure adjudicator
  contract has at least one caller-independent regression test.
- Public contract modules that had no ``__all__`` (``platform``, ``persist``,
  ``reporting``) now declare one, so ``from aila.platform.contracts.<mod>
  import *`` and static tooling both see the same public surface.
"""
from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from aila.platform.contracts import budget as budget_mod
from aila.platform.contracts import obligations as obligations_mod
from aila.platform.contracts import persist as persist_mod
from aila.platform.contracts import platform as platform_mod
from aila.platform.contracts import reporting as reporting_mod
from aila.platform.contracts.budget import BudgetConfig, BudgetState
from aila.platform.contracts.obligations import (
    EvidenceObligation,
    ObligationSet,
    ObligationSeverity,
    adjudicate,
)
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


# ---------------------------------------------------------------------------
# Budget contract hygiene (#61 residual): BudgetConfig / BudgetState carry
# ``extra="forbid"`` so a mistyped kwarg fails at construction.
# ---------------------------------------------------------------------------


def test_budget_config_rejects_undeclared_kwarg() -> None:
    """``max_turn`` (typo) MUST fail; without forbid the value would be
    silently dropped and ``max_turns`` would keep its default (30)."""
    assert BudgetConfig.model_config.get("extra") == "forbid"
    with pytest.raises(ValidationError):
        BudgetConfig(max_turn=100)  # type: ignore[call-arg]


def test_budget_state_rejects_undeclared_kwarg() -> None:
    """State tracker is equally strict -- typo in ``turns_used`` fails loudly."""
    assert BudgetState.model_config.get("extra") == "forbid"
    with pytest.raises(ValidationError):
        BudgetState(turns_use=5)  # type: ignore[call-arg]


def test_budget_config_accepts_declared_fields() -> None:
    """Regression guard: well-formed kwargs still construct."""
    cfg = BudgetConfig(max_turns=50, max_tool_time_seconds=1800.0)
    assert cfg.max_turns == 50
    assert cfg.max_tool_time_seconds == 1800.0


# ---------------------------------------------------------------------------
# Obligation adjudicator (#61 residual): pure-function contract has zero
# caller-independent test coverage -- pin the four documented verdict paths.
# ---------------------------------------------------------------------------


def _obligation(id_: str, severity: ObligationSeverity, *, satisfied: bool = False) -> EvidenceObligation:
    return EvidenceObligation(
        id=id_,
        claim=f"claim-{id_}",
        required_evidence="crash artifact",
        severity=severity,
        satisfied=satisfied,
    )


def test_adjudicate_accepts_when_no_obligations_and_no_signals() -> None:
    result = adjudicate(claim="buffer overflow at foo", reasoning_text="crash log shows RIP overwrite", obligations=ObligationSet())
    assert result.verdict == "accepted"
    assert result.adjusted_claim == "buffer overflow at foo"


def test_adjudicate_blocks_on_unmet_critical() -> None:
    obs = ObligationSet(obligations=[_obligation("ob-crit", ObligationSeverity.CRITICAL)])
    result = adjudicate(claim="c", reasoning_text="", obligations=obs)
    assert result.verdict == "blocked"
    assert "ob-crit" in result.unmet_obligations


def test_adjudicate_downgrades_on_unmet_required() -> None:
    obs = ObligationSet(obligations=[_obligation("ob-req", ObligationSeverity.REQUIRED)])
    result = adjudicate(claim="c", reasoning_text="", obligations=obs)
    assert result.verdict == "downgraded"
    assert result.adjusted_claim == "[advisory withheld] c"


def test_adjudicate_downgrades_on_hedge_signal() -> None:
    result = adjudicate(
        claim="c",
        reasoning_text="This might be possible under certain conditions.",
        obligations=ObligationSet(),
    )
    assert result.verdict == "downgraded"
    assert result.adjusted_claim == "[hedged] c"
    # Both hedge phrases surface -- the case-insensitive scan catches them.
    assert "might be possible" in result.contradiction_signals
    assert "under certain conditions" in result.contradiction_signals


# ---------------------------------------------------------------------------
# Public-module ``__all__`` hygiene (#61 residual): every non-underscore
# contract module MUST declare its public surface so ``import *`` and
# static tooling agree with the intended exports.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mod,expected",
    [
        (
            platform_mod,
            {
                "PLATFORM_CONFIG_KEY_REDIS_URL",
                "PLATFORM_CONFIG_NS",
                "AddIntegrationPayload",
                "AsyncTaskQueue",
                "DeleteIntegrationsPayload",
                "ExecuteRemoteCommandPayload",
                "ProgressUpdate",
                "RegisteredSystem",
                "RegistryResponse",
                "RemoteCommandSelection",
                "RouteCandidate",
                "RouteDecision",
                "RoutedCandidate",
                "RoutingCandidateProfile",
                "RoutingSelection",
                "SSHIntegrationInput",
                "WorkflowEvent",
            },
        ),
        (persist_mod, {"PersistContract", "Persistable"}),
        (
            reporting_mod,
            {
                "LatestReportResult",
                "LatestReportRowsResult",
                "ReportRowsSourceReference",
                "TargetReportReference",
                "normalize_report_summary_payload",
            },
        ),
        (budget_mod, {"BudgetConfig", "BudgetState"}),
        (
            obligations_mod,
            {
                "AdjudicationResult",
                "CONTRADICTION_SIGNALS",
                "EvidenceObligation",
                "ObligationSet",
                "ObligationSeverity",
                "adjudicate",
            },
        ),
    ],
)
def test_public_module_declares_all(mod: object, expected: set[str]) -> None:
    declared = set(getattr(mod, "__all__"))
    assert declared == expected
