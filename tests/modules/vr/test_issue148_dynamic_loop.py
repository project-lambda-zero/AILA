"""Issue #148: close the fuzz/symbolic/dynamic -> kill-criteria loop.

Function-level tests (no live Redis, no agent, no DB):

* the kill-criteria evaluator's observable-prefix allowlist now accepts
  ``fuzz:`` / ``symbolic:`` / ``dynamic:`` keys, so a fabricated case_state
  carrying one of those observables fires a kill_criterion signal;
* a consumed SYSTEM ``fuzz_coverage`` / OPERATOR ``fuzz_crash`` message
  projects into ``case_state.observables`` under the ``fuzz:<campaign>:*``
  key (``_fuzz_observable_for_row`` + the stash applied by
  ``_inject_promotion_directives``);
* the ``symbolic.explore`` / ``dynamic.run_dynamic`` tools are registered
  and discoverable in the VR tool registry, invoking symbolic when miasm
  is unavailable returns a clean status with no exception, and the tool
  adapters project the colon-keyed observable the evaluator scans.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

import aila.platform.services.symbolic as sym
from aila.modules.vr.agents.tool_executor import ToolExecutor
from aila.modules.vr.agents.vuln_researcher import (
    HonestVulnResearcher,
    _fuzz_observable_for_row,
)
from aila.modules.vr.tools.dynamic_analysis import (
    DynamicRunTool,
    SymbolicExploreTool,
)
from aila.platform.contracts.reasoning import (
    Hypothesis,
    ReasoningCaseState,
)
from aila.platform.mcp.adapters.base import AdapterContext
from aila.platform.mcp.adapters.dynamic_symbolic import (
    adapt_dynamic_run,
    adapt_symbolic_explore,
)
from aila.platform.mcp.adapters.known_tools import KNOWN_TOOLS
from aila.platform.mcp.adapters.registry import get_adapter, registered_tools


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _make_researcher() -> HonestVulnResearcher:
    """Instantiate a researcher with the kill-criteria knobs enabled.

    ``__init__`` only stores its arguments; no engine call at construction
    time, so passing ``None`` for the engine is safe for the pure
    gate/evaluator methods.
    """
    r = HonestVulnResearcher(
        reasoning_engine=None,  # type: ignore[arg-type]
        investigation_id="inv-148",
        branch_id="br-148",
    )
    r._promote_confirmed_findings = True
    r._kill_criterion_scan_cap = 20
    r._kill_criterion_overlap_threshold = 0.5
    return r


class _FakeLedger:
    """Records append calls instead of hitting the shared ledger DB."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def append_general(
        self, investigation_id: str, branch_id: str, kind: str,
        payload: dict[str, Any], **kwargs: Any,
    ) -> int:
        self.calls.append((kind, payload))
        return 1

    async def append_adjudication(
        self, investigation_id: str, branch_id: str, **kwargs: Any,
    ) -> int:
        self.calls.append(("adjudication", {
            "verdict": kwargs.get("verdict"),
            "target": kwargs.get("target_hypothesis_id"),
            "cites": list(kwargs.get("cited_evidence") or []),
        }))
        return 1


# ---------------------------------------------------------------------------
# Gap B -- consumer: kill-criteria sees fuzz/symbolic/dynamic observables.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "obs_key",
    [
        "fuzz:camp1:crash",
        "fuzz:camp1:coverage_delta",
        "symbolic:parse_header:reached",
        "dynamic:probe-x:coverage_delta",
        "dynamic:probe-x:crash",
    ],
)
@pytest.mark.asyncio
async def test_kill_criteria_fires_on_dynamic_analysis_observable(
    monkeypatch: pytest.MonkeyPatch, obs_key: str,
) -> None:
    """A fuzz/symbolic/dynamic observable whose body overlaps a live
    hypothesis' kill_criterion fires a kill_criterion ledger signal."""
    r = _make_researcher()
    case = ReasoningCaseState()
    case.hypotheses = [
        Hypothesis(
            id="h1",
            claim="parser mishandles length field",
            kill_criterion="parser handles length field correctly",
        ),
    ]
    case.observables[obs_key] = (
        "the parser handles the length field correctly with a size cap"
    )
    ledger = _FakeLedger()
    monkeypatch.setattr(
        "aila.modules.vr.agents.vuln_researcher.LedgerService",
        lambda: ledger,
    )

    await r._evaluate_kill_criteria_this_turn(case_state=case, turn_number=3)

    assert ledger.calls, f"no kill_criterion signal fired for {obs_key!r}"
    kind, payload = ledger.calls[0]
    assert kind == "discovery"
    assert payload["hypothesis_id"] == "h1"
    assert payload["matched_observable"] == obs_key


@pytest.mark.asyncio
async def test_kill_criteria_ignores_non_allowlisted_observable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A plain agent-scratchpad observable (no allowlisted prefix) is not
    scanned, so no signal fires -- the allowlist stays a closed set."""
    r = _make_researcher()
    case = ReasoningCaseState()
    case.hypotheses = [
        Hypothesis(
            id="h1",
            claim="parser mishandles length field",
            kill_criterion="parser handles length field correctly",
        ),
    ]
    case.observables["scratch_note"] = (
        "the parser handles the length field correctly with a size cap"
    )
    ledger = _FakeLedger()
    monkeypatch.setattr(
        "aila.modules.vr.agents.vuln_researcher.LedgerService",
        lambda: ledger,
    )

    await r._evaluate_kill_criteria_this_turn(case_state=case, turn_number=3)

    assert ledger.calls == []


# ---------------------------------------------------------------------------
# Gap A -- producer (fuzz): message -> case_state.observables projection.
# ---------------------------------------------------------------------------


def test_fuzz_coverage_message_projects_coverage_delta_observable() -> None:
    row = SimpleNamespace(sender_id="fuzz_coverage", auto_steering_key=None)
    out = _fuzz_observable_for_row(
        row,
        {"campaign_id": "camp1", "coverage_pct": 12.3},
        "Fuzz campaign 'c' coverage advanced to 12.30%",
    )
    assert out is not None
    key, body = out
    assert key == "fuzz:camp1:coverage_delta"
    assert "coverage advanced" in body


def test_fuzz_crash_message_projects_crash_observable() -> None:
    row = SimpleNamespace(
        sender_id="auto_steering",
        auto_steering_key="fuzz_crash:camp1:deadbeefcafe",
    )
    out = _fuzz_observable_for_row(
        row, {}, "produced a security-relevant crash stack_hash deadbeefcafe",
    )
    assert out is not None
    key, body = out
    assert key == "fuzz:camp1:crash"
    assert "security-relevant crash" in body


def test_non_fuzz_message_projects_nothing() -> None:
    row = SimpleNamespace(
        sender_id="auto_steering",
        auto_steering_key="read_lines_eof:parser.c",
    )
    assert _fuzz_observable_for_row(row, {}, "corrective steering text") is None
    # Empty body never projects regardless of sender.
    cov = SimpleNamespace(sender_id="fuzz_coverage", auto_steering_key=None)
    assert _fuzz_observable_for_row(cov, {"campaign_id": "c"}, "   ") is None
    # Coverage message missing a campaign id projects nothing.
    assert _fuzz_observable_for_row(cov, {}, "coverage advanced") is None


def test_inject_promotion_directives_merges_pending_fuzz_into_case_state() -> None:
    """The stash populated by _consume_pending_operator_messages is merged
    into the live case_state BEFORE the kill-criteria scan is scheduled,
    then cleared so a later turn does not re-project."""
    r = _make_researcher()
    case = ReasoningCaseState()
    r._pending_fuzz_observables = {
        "fuzz:camp1:crash": "security-relevant crash on camp1",
    }

    # Sync call: no running loop -> the fire-and-forget scan is skipped
    # (RuntimeError path), but the stash merge happens first.
    r._inject_promotion_directives(case, turn_number=1)

    assert case.observables["fuzz:camp1:crash"] == (
        "security-relevant crash on camp1"
    )
    # Stash cleared so the next turn without new feedback does not re-fire.
    assert r._pending_fuzz_observables == {}


# ---------------------------------------------------------------------------
# Gap A -- producer (symbolic + dynamic): registry + clean unavailable.
# ---------------------------------------------------------------------------


def test_symbolic_and_dynamic_tools_registered_in_vr_registry() -> None:
    # Known-tools catalog.
    assert "symbolic" in KNOWN_TOOLS
    assert "explore" in KNOWN_TOOLS["symbolic"]
    assert "dynamic" in KNOWN_TOOLS
    assert "run_dynamic" in KNOWN_TOOLS["dynamic"]
    # Adapter resolution (specialised adapters).
    assert get_adapter("symbolic", "explore") is adapt_symbolic_explore
    assert get_adapter("dynamic", "run_dynamic") is adapt_dynamic_run
    assert "symbolic.explore" in registered_tools()
    assert "dynamic.run_dynamic" in registered_tools()
    # Agent allowlist + wired bridges on the executor.
    assert "symbolic" in ToolExecutor._AGENT_ALLOWED_SERVERS
    assert "dynamic" in ToolExecutor._AGENT_ALLOWED_SERVERS
    te = ToolExecutor()
    assert isinstance(te._bridge_overrides["symbolic"], SymbolicExploreTool)
    assert isinstance(te._bridge_overrides["dynamic"], DynamicRunTool)


@pytest.mark.asyncio
async def test_symbolic_tool_unavailable_without_miasm_returns_clean_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the flag ON but miasm absent, the tool returns status
    'unavailable' as a clean dict -- never an uncaught exception."""
    async def _enabled() -> bool:
        return True

    def _no_miasm(*_a: Any, **_k: Any) -> Any:
        raise ImportError("miasm is not installed")

    monkeypatch.setattr(sym, "_resolve_enabled", _enabled)
    monkeypatch.setattr(sym, "_run_concolic", _no_miasm)

    result = await SymbolicExploreTool().forward(
        action="explore",
        module="vr",
        workspace_id="ws-1",
        symbol_name="parse_header",
        arch="x86_32",
        entry_address=0,
        code_bytes="9090c3",
    )
    assert result["status"] == "unavailable"
    assert result["function"] == "parse_header"
    assert result["error"] is None


@pytest.mark.asyncio
async def test_symbolic_tool_rejects_bad_input_without_raising() -> None:
    bad = await SymbolicExploreTool().forward(
        action="explore",
        module="vr",
        workspace_id="ws-1",
        symbol_name="f",
        arch="x86_32",
        entry_address=0,
        code_bytes="not-hex-zz",
    )
    assert bad["status"] == "error"
    assert "code_bytes" in bad["error"]

    missing_scope = await SymbolicExploreTool().forward(
        action="explore", symbol_name="f", arch="x86_32",
        entry_address=0, code_bytes="90",
    )
    assert missing_scope["status"] == "error"


@pytest.mark.asyncio
async def test_dynamic_tool_disabled_returns_clean_status() -> None:
    """Flag defaults off -> run_dynamic short-circuits to 'disabled' with
    no sandbox dispatch and no exception."""
    result = await DynamicRunTool().forward(
        action="run_dynamic",
        module="vr",
        workspace_id="ws-1",
        subject="probe:target:seed1",
        argv=["/work/target", "@@"],
    )
    assert result["status"] == "disabled"
    assert result["target"] == "probe:target:seed1"


@pytest.mark.asyncio
async def test_dynamic_tool_rejects_bad_argv() -> None:
    result = await DynamicRunTool().forward(
        action="run_dynamic", module="vr", workspace_id="ws-1",
        subject="probe", argv=[],
    )
    assert result["status"] == "error"
    assert "argv" in result["error"]


# ---------------------------------------------------------------------------
# Gap A -- producer: adapters project the exact colon-keyed observable.
# ---------------------------------------------------------------------------


def _ctx(server: str, tool: str, args: dict[str, Any]) -> AdapterContext:
    return AdapterContext(
        mcp_server_id=server, tool_name=tool,
        investigation_id="inv-148", branch_id="br-148",
        call_id="call-1", args=args,
    )


def test_symbolic_adapter_projects_reached_observable() -> None:
    raw = {
        "status": "success",
        "function": "parse_header",
        "subject": "vr:parse_header@0x0",
        "arch": "x86_32",
        "reached_count": 3,
        "reached_addresses": ["0x0", "0x1", "0x2"],
        "path_constraints": ["RAX == sym_input_0"],
        "steps_executed": 3,
        "observation_id": "obs-1",
        "error": None,
    }
    result = adapt_symbolic_explore(
        raw, _ctx("symbolic", "explore", {"symbol_name": "parse_header"}),
    )
    assert "symbolic:parse_header:reached" in result.observables_delta
    body = result.observables_delta["symbolic:parse_header:reached"]
    assert "reached 3 blocks" in body


def test_dynamic_adapter_projects_coverage_delta_and_crash_observables() -> None:
    raw = {
        "status": "crashed",
        "target": "probe:target:seed1",
        "reason": "timed out after 30.0s",
        "exit_code": None,
        "crashed": True,
        "coverage_edge_count": 10,
        "coverage_delta_edges": ["e1", "e2"],
        "coverage_delta_count": 2,
        "observations_emitted": ["dynamic.run", "dynamic.crash"],
    }
    result = adapt_dynamic_run(
        raw, _ctx("dynamic", "run_dynamic", {"subject": "probe:target:seed1"}),
    )
    assert "dynamic:probe:target:seed1:coverage_delta" in result.observables_delta
    assert "dynamic:probe:target:seed1:crash" in result.observables_delta
    cov = result.observables_delta["dynamic:probe:target:seed1:coverage_delta"]
    assert "2 new edge(s)" in cov


def test_dynamic_adapter_omits_crash_observable_when_clean() -> None:
    raw = {
        "status": "executed",
        "target": "probe:seed2",
        "reason": None,
        "exit_code": 0,
        "crashed": False,
        "coverage_edge_count": 4,
        "coverage_delta_edges": [],
        "coverage_delta_count": 0,
        "observations_emitted": ["dynamic.run"],
    }
    result = adapt_dynamic_run(
        raw, _ctx("dynamic", "run_dynamic", {"subject": "probe:seed2"}),
    )
    assert "dynamic:probe:seed2:coverage_delta" in result.observables_delta
    assert "dynamic:probe:seed2:crash" not in result.observables_delta
