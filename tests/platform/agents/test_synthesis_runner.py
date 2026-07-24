"""Characterization tests for the platform SynthesisRunner (RFC-03 Phase 5).

Exercises the synthesis pipeline for BOTH module configs (vr + malware)
so the pre-extraction behavior is preserved after the extraction. Every
LLM call is mocked at the ``idempotent_llm_call`` seam; the DB round-
trips are patched via ``_load_inv_and_canonical`` / ``_commit_synthesis``
so no migrations or infra are required.

Coverage:
  * Class-attribute bindings (task_type, branch_table, response_model,
    system prompt, investigation/outcome model) are per-module correct.
  * Panel-entry structure: vr's ``_build_panel_entry`` overrides adds
    ``affected_components`` + ``variant_hunt_orders`` derived from the
    canonical payload; malware inherits the 7-core-key default.
  * User-prompt rendering: vr surfaces persona blocks + agreement /
    disagreement instructions; malware injects tone + length + optional
    operator-focus + structured-schema instructions.
  * ``_should_force_resynthesize`` returns False for vr always, and for
    malware tracks ``options.force``.
  * ``_should_flip_investigation_status`` returns True for vr always,
    for malware skips only on ``force + already_completed``.
  * ``_update_payload_extras``: vr is a no-op; malware promotes every
    structured field (family_attribution / capabilities / iocs /
    detection_guidance / next_actions / panel_dissent / etc.) onto
    payload top-level with correct IOC-bucket merge semantics.
  * ``run()`` orchestration paths: happy path, skip paths
    (investigation_not_found, no_canonical_outcome,
    already_synthesized, no_panel_contributions, no_valid_contributions,
    structured_parse_failed, empty_llm_response, llm_kill_switch_active,
    llm_error:*), and malware's force-bypass of the pre-lock
    already_synthesized gate.
  * ``_commit_synthesis`` under-lock behavior: alive-status gate,
    already-synthesized-under-lock gate, force bypass, status-flip
    hook interaction.

The test parametrises on a small ``_Config`` struct so both modules run
through the identical assertion set -- any drift between the vr and
malware subclass classes would immediately break one variant.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from aila.modules.malware.agents.synthesis_agent import (
    CapabilityEntry,
    IOCBundle,
)
from aila.modules.malware.agents.synthesis_agent import (
    SynthesisAgent as MalwareSynthesisAgent,
)
from aila.modules.malware.agents.synthesis_agent import (
    SynthesisOptions as MalwareSynthesisOptions,
)
from aila.modules.malware.agents.synthesis_agent import (
    SynthesisResponse as MalwareSynthesisResponse,
)
from aila.modules.malware.db_models import (
    MalwareInvestigationOutcomeRecord,
    MalwareInvestigationRecord,
)
from aila.modules.vr.agents.synthesis_agent import (
    SynthesisAgent as VRSynthesisAgent,
)
from aila.modules.vr.agents.synthesis_agent import (
    SynthesisResponse as VRSynthesisResponse,
)
from aila.modules.vr.db_models import (
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
)
from aila.platform.agents.synthesis_runner import (
    SynthesisRunnerBase,
    synthesis_confidence,
)
from aila.platform.contracts.enums import (
    InvestigationStatus,
    OutcomeConfidence,
)
from aila.platform.llm.errors import BudgetExceededError

# --------------------------------------------------------------------- #
#  Per-module test config                                               #
# --------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Config:
    """One module's binding + canned SynthesisResponse for the happy path."""

    label: str
    agent_factory: Any  # callable returning a SynthesisRunnerBase instance
    agent_cls: type[SynthesisRunnerBase]
    response_cls: type[Any]
    task_type: str
    branch_table: str
    investigation_model: type[Any]
    outcome_model: type[Any]
    canned_response: Any  # SynthesisResponse instance
    expected_prompt_snippets: tuple[str, ...]


_VR_CANNED = VRSynthesisResponse(
    headline_verdict="Panel converged on a real TypeConfusion in InferMaps.",
    points_of_agreement=["Halvar + Maddie both cite src/foo.cc:120"],
    points_of_disagreement=["Renzo dissents on exploitability"],
    unresolved_questions=["Whether v8 shipped the alias fix upstream"],
    recommended_next_actions=["Spawn variant hunt on adjacent InferMaps call sites"],
)


_MW_CANNED = MalwareSynthesisResponse(
    family_attribution="AsyncRAT",
    attribution_rationale=(
        "Brand string AsyncRAT in .rsrc UTF-16LE config block; "
        "matches Renzo IOCs; matches Wei capability cluster."
    ),
    headline_verdict=(
        "AsyncRAT sample -- credential theft + persistent backdoor. "
        "Stage 1 fetch to evil.example.com. Quarantine + pivot."
    ),
    capabilities=[
        CapabilityEntry(
            technique_id="T1055.012",
            evidence="sub_474D50 calls VirtualAllocEx + WriteProcessMemory",
        ),
        CapabilityEntry(
            technique_id="T1547.001",
            evidence="registry Run key from persistence writer",
        ),
    ],
    inconclusive_capabilities=["T1027.002 -- capa hit without confirming code path"],
    iocs=IOCBundle(
        domains=["evil.example.com"],
        c2_stage_1_urls=["http://evil.example.com/gate"],
        c2_stage_2_endpoints=["ddns.example.com:443"],
        mutexes=["Global\\AsyncRAT_Mutex"],
        persistence=["HKCU\\...\\Run AsyncRAT=%APPDATA%\\a.exe"],
    ),
    detection_guidance=["YARA on the AsyncRAT config UTF-16LE block"],
    next_actions=["Unpack Stage 2 from .rsrc offset 0x4c0700"],
    panel_dissent=["Halvar says packer=UPX; Noor says custom XOR"],
    inconclusive_areas=["Whether the .rsrc 0x4c0608 block is a second config"],
)


VR_CONFIG = _Config(
    label="vr",
    agent_factory=lambda: VRSynthesisAgent(investigation_id="inv-x"),
    agent_cls=VRSynthesisAgent,
    response_cls=VRSynthesisResponse,
    task_type="vulnerability_research.synthesizer",
    branch_table="vr_investigation_branches",
    investigation_model=VRInvestigationRecord,
    outcome_model=VRInvestigationOutcomeRecord,
    canned_response=_VR_CANNED,
    expected_prompt_snippets=(
        "# Persona deliberation panel",
        "outcome_kind:",
        "affected_components:",
        "variant_hunt_orders:",
        "### answer",
        "Points of agreement",
        "Points of disagreement",
    ),
)

MALWARE_CONFIG = _Config(
    label="malware",
    agent_factory=lambda: MalwareSynthesisAgent(investigation_id="inv-y"),
    agent_cls=MalwareSynthesisAgent,
    response_cls=MalwareSynthesisResponse,
    task_type="malware_analysis.synthesizer",
    branch_table="malware_investigation_branches",
    investigation_model=MalwareInvestigationRecord,
    outcome_model=MalwareInvestigationOutcomeRecord,
    canned_response=_MW_CANNED,
    expected_prompt_snippets=(
        "# Persona deliberation panel",
        "outcome_kind:",
        "### submission",
        "# Operator controls",
        "# Synthesis instruction",
        "SynthesisResponse",
    ),
)

ALL_CONFIGS = [VR_CONFIG, MALWARE_CONFIG]


def _sample_contribution(persona: str = "halvar") -> dict[str, Any]:
    """One canonical panel_contributions entry, module-agnostic shape."""
    return {
        "branch_id": f"br-{persona}",
        "persona": persona,
        "at_turn": 25,
        "outcome_kind": "direct_finding",
        "confidence": "strong",
        "answer_brief": f"{persona} submission body here",
    }


def _canonical_payload(contribs_count: int = 3) -> dict[str, Any]:
    """A canonical outcome payload with N panel_contributions."""
    return {
        "panel_contributions": [
            _sample_contribution(f"persona{i}") for i in range(contribs_count)
        ],
        "affected_components": ["src/foo.cc:120", "src/bar.cc:99"],
        "variant_hunt_orders": [{"id": "vh-1"}],
    }


# --------------------------------------------------------------------- #
#  LLM idempotency wrapper -- bypassed for tests                         #
# --------------------------------------------------------------------- #


class _FakeLLMResponse:
    def __init__(self, content: str, disabled: bool = False) -> None:
        self.content = content
        self.disabled = disabled
        self.model = "test-model"
        self.usage: dict[str, int] = {}
        self.finish_reason = "stop"


@pytest.fixture
def bypass_llm(monkeypatch: pytest.MonkeyPatch):
    """Patch ``idempotent_llm_call`` in synthesis_runner with a controllable stub.

    Returns a helper (``configure``) so each test can set the LLM
    response independently. The stub records every invocation on
    ``.calls`` so tests can assert task_type + messages + model_class.
    """

    state: dict[str, Any] = {
        "response": _FakeLLMResponse(content=""),
        "raise_": None,
    }
    calls: list[dict[str, Any]] = []

    async def _bypass(llm_client, *, method, task_type, messages, **kwargs):
        del llm_client
        assert method == "chat_structured", (
            f"synthesis always uses chat_structured; got {method}"
        )
        calls.append({
            "task_type": task_type,
            "messages": list(messages),
            **kwargs,
        })
        if state["raise_"] is not None:
            raise state["raise_"]
        return state["response"], False

    monkeypatch.setattr(
        "aila.platform.agents.synthesis_runner.idempotent_llm_call",
        _bypass,
    )
    # ServiceFactory().llm_client is otherwise lazy-initialised through
    # ConfigRegistry + SecretStore which need infra. Since the bypass
    # ignores the first positional arg, patch ServiceFactory to a stub
    # whose ``llm_client`` property returns a sentinel object.
    class _StubFactory:
        @property
        def llm_client(self) -> Any:
            return "stub-llm-client"

    monkeypatch.setattr(
        "aila.platform.agents.synthesis_runner.ServiceFactory",
        _StubFactory,
    )

    def configure(response: Any = None, raise_: Exception | None = None) -> None:
        if response is not None:
            if isinstance(response, str):
                state["response"] = _FakeLLMResponse(content=response)
            elif isinstance(response, _FakeLLMResponse):
                state["response"] = response
            else:
                state["response"] = _FakeLLMResponse(
                    content=response.model_dump_json(),
                )
        state["raise_"] = raise_

    return configure, calls


# --------------------------------------------------------------------- #
#  Class binding                                                         #
# --------------------------------------------------------------------- #


@pytest.mark.parametrize("cfg", ALL_CONFIGS, ids=[c.label for c in ALL_CONFIGS])
class TestClassBinding:
    def test_subclass_of_platform_base(self, cfg: _Config) -> None:
        assert issubclass(cfg.agent_cls, SynthesisRunnerBase)

    def test_task_type(self, cfg: _Config) -> None:
        assert cfg.agent_cls._TASK_TYPE == cfg.task_type

    def test_branch_table(self, cfg: _Config) -> None:
        assert cfg.agent_cls._branch_table == cfg.branch_table

    def test_investigation_model(self, cfg: _Config) -> None:
        assert cfg.agent_cls._investigation_model is cfg.investigation_model

    def test_outcome_model(self, cfg: _Config) -> None:
        assert cfg.agent_cls._outcome_model is cfg.outcome_model

    def test_response_model(self, cfg: _Config) -> None:
        assert cfg.agent_cls._response_model is cfg.response_cls

    def test_system_prompt_is_module_specific(self, cfg: _Config) -> None:
        # vr's prompt mentions researcher/critic/implementer; malware's
        # names the six-persona triad by name.
        prompt = cfg.agent_cls._SYSTEM_PROMPT
        assert isinstance(prompt, str) and len(prompt) > 200
        if cfg.label == "vr":
            assert "vulnerability-research" in prompt
            assert "HALVAR" not in prompt
        else:
            assert "malware-analysis" in prompt
            assert "HALVAR" in prompt


# --------------------------------------------------------------------- #
#  Panel-entry hook                                                     #
# --------------------------------------------------------------------- #


class TestBuildPanelEntry:
    def test_vr_adds_affected_components_and_variant_hunt_orders(self) -> None:
        agent = VR_CONFIG.agent_factory()
        payload = _canonical_payload(contribs_count=1)
        entry = agent._build_panel_entry(payload["panel_contributions"][0], payload)
        assert entry["affected_components"] == ["src/foo.cc:120", "src/bar.cc:99"]
        assert entry["variant_hunt_orders"] == [{"id": "vh-1"}]

    def test_malware_omits_the_vr_extras(self) -> None:
        agent = MALWARE_CONFIG.agent_factory()
        payload = _canonical_payload(contribs_count=1)
        entry = agent._build_panel_entry(payload["panel_contributions"][0], payload)
        assert "affected_components" not in entry
        assert "variant_hunt_orders" not in entry

    @pytest.mark.parametrize(
        "cfg", ALL_CONFIGS, ids=[c.label for c in ALL_CONFIGS],
    )
    def test_core_keys_present_both_modules(self, cfg: _Config) -> None:
        agent = cfg.agent_factory()
        payload = _canonical_payload(contribs_count=1)
        entry = agent._build_panel_entry(payload["panel_contributions"][0], payload)
        assert set(entry) >= {
            "branch_id", "persona_voice", "turn_count",
            "outcome_kind", "confidence", "answer", "reasoning",
        }
        assert entry["persona_voice"] == "persona0"
        assert entry["outcome_kind"] == "direct_finding"
        assert entry["confidence"] == "strong"

    @pytest.mark.parametrize(
        "cfg", ALL_CONFIGS, ids=[c.label for c in ALL_CONFIGS],
    )
    def test_missing_fields_fall_back_to_defaults(self, cfg: _Config) -> None:
        agent = cfg.agent_factory()
        entry = agent._build_panel_entry({}, {})
        assert entry["persona_voice"] == "(none)"
        assert entry["outcome_kind"] == ""
        assert entry["confidence"] == "unknown"
        assert entry["answer"] == ""


# --------------------------------------------------------------------- #
#  User-prompt rendering                                                #
# --------------------------------------------------------------------- #


class TestRenderUserPrompt:
    def _panel(self, cfg: _Config) -> list[dict[str, Any]]:
        agent = cfg.agent_factory()
        payload = _canonical_payload(contribs_count=2)
        return [
            agent._build_panel_entry(c, payload)
            for c in payload["panel_contributions"]
        ]

    @pytest.mark.parametrize(
        "cfg", ALL_CONFIGS, ids=[c.label for c in ALL_CONFIGS],
    )
    def test_prompt_contains_expected_snippets(self, cfg: _Config) -> None:
        agent = cfg.agent_factory()
        panel = self._panel(cfg)
        prompt = agent._render_user_prompt(panel)
        for snippet in cfg.expected_prompt_snippets:
            assert snippet in prompt, (
                f"{cfg.label} prompt missing snippet {snippet!r}\n{prompt}"
            )

    def test_vr_renders_component_and_hunt_counts(self) -> None:
        agent = VR_CONFIG.agent_factory()
        panel = self._panel(VR_CONFIG)
        prompt = agent._render_user_prompt(panel)
        # canonical payload has 2 affected_components + 1 variant_hunt_order
        assert "affected_components: 2 entries" in prompt
        assert "variant_hunt_orders: 1 entries" in prompt

    def test_malware_injects_default_operator_controls(self) -> None:
        agent = MALWARE_CONFIG.agent_factory()
        panel = self._panel(MALWARE_CONFIG)
        prompt = agent._render_user_prompt(panel)
        # Default options=operator+standard: check both directives fire.
        assert "Terse, action-oriented voice" in prompt
        assert "Length: standard" in prompt
        # Neither optional block fires by default.
        assert "ENUMERATE-EVERY-SUSPICIOUS" not in prompt
        assert "## User focus" not in prompt

    def test_malware_options_switch_tone_and_length(self) -> None:
        agent = MalwareSynthesisAgent(
            investigation_id="inv-o",
            options=MalwareSynthesisOptions(
                tone="executive", length="brief",
                enumerate_every_suspicious=True,
                operator_focus="focus on Stage 2 unpack",
            ),
        )
        panel = self._panel(MALWARE_CONFIG)
        prompt = agent._render_user_prompt(panel)
        # Executive tone directive.
        assert "Non-technical executive voice" in prompt
        # Brief length directive.
        assert "Length: brief" in prompt
        # Optional blocks fire when their flags are set.
        assert "ENUMERATE-EVERY-SUSPICIOUS mode is ON" in prompt
        assert "## User focus" in prompt
        assert "focus on Stage 2 unpack" in prompt

    @pytest.mark.parametrize(
        "cfg", ALL_CONFIGS, ids=[c.label for c in ALL_CONFIGS],
    )
    def test_persona_name_uppercased(self, cfg: _Config) -> None:
        agent = cfg.agent_factory()
        panel = self._panel(cfg)
        prompt = agent._render_user_prompt(panel)
        assert "PERSONA0" in prompt
        assert "PERSONA1" in prompt


# --------------------------------------------------------------------- #
#  Force / status hooks                                                 #
# --------------------------------------------------------------------- #


class TestForceHooks:
    def test_vr_never_force_resynthesizes(self) -> None:
        assert VRSynthesisAgent(investigation_id="i")._should_force_resynthesize() is False

    def test_malware_default_options_no_force(self) -> None:
        agent = MalwareSynthesisAgent(investigation_id="i")
        assert agent._should_force_resynthesize() is False

    def test_malware_force_true_when_options_force(self) -> None:
        agent = MalwareSynthesisAgent(
            investigation_id="i",
            options=MalwareSynthesisOptions(force=True),
        )
        assert agent._should_force_resynthesize() is True

    def test_vr_always_flips_status(self) -> None:
        agent = VRSynthesisAgent(investigation_id="i")
        for status in (
            InvestigationStatus.CREATED.value,
            InvestigationStatus.RUNNING.value,
            InvestigationStatus.COMPLETED.value,
        ):
            inv = type("Row", (), {"status": status})()
            assert agent._should_flip_investigation_status(inv) is True, status

    def test_malware_default_flips_status_regardless(self) -> None:
        agent = MalwareSynthesisAgent(investigation_id="i")
        for status in (
            InvestigationStatus.CREATED.value,
            InvestigationStatus.RUNNING.value,
            InvestigationStatus.COMPLETED.value,
        ):
            inv = type("Row", (), {"status": status})()
            assert agent._should_flip_investigation_status(inv) is True, status

    def test_malware_force_skips_flip_only_on_completed_row(self) -> None:
        agent = MalwareSynthesisAgent(
            investigation_id="i",
            options=MalwareSynthesisOptions(force=True),
        )
        # Force + COMPLETED -> skip the flip.
        completed = type("Row", (), {"status": InvestigationStatus.COMPLETED.value})()
        assert agent._should_flip_investigation_status(completed) is False
        # Force + still-alive -> flip anyway (there is no already-completed
        # state to preserve).
        running = type("Row", (), {"status": InvestigationStatus.RUNNING.value})()
        assert agent._should_flip_investigation_status(running) is True


# --------------------------------------------------------------------- #
#  Payload extras -- vr no-op / malware promotes everything             #
# --------------------------------------------------------------------- #


class TestUpdatePayloadExtras:
    def test_vr_is_a_no_op(self) -> None:
        agent = VRSynthesisAgent(investigation_id="i")
        payload: dict[str, Any] = {"existing": "value"}
        agent._update_payload_extras(payload, _VR_CANNED)
        assert payload == {"existing": "value"}

    def test_malware_promotes_all_structured_fields(self) -> None:
        agent = MalwareSynthesisAgent(investigation_id="i")
        payload: dict[str, Any] = {}
        agent._update_payload_extras(payload, _MW_CANNED)
        assert payload["family_attribution"] == "AsyncRAT"
        assert payload["attribution_rationale"].startswith("Brand string")
        assert payload["capabilities"] == ["T1055.012", "T1547.001"]
        assert payload["capability_evidence"] == [
            {"technique_id": "T1055.012", "evidence": _MW_CANNED.capabilities[0].evidence},
            {"technique_id": "T1547.001", "evidence": _MW_CANNED.capabilities[1].evidence},
        ]
        assert payload["inconclusive_capabilities"] == [
            "T1027.002 -- capa hit without confirming code path",
        ]
        assert payload["detection_guidance"] == [
            "YARA on the AsyncRAT config UTF-16LE block",
        ]
        assert payload["next_actions"] == [
            "Unpack Stage 2 from .rsrc offset 0x4c0700",
        ]
        assert payload["panel_dissent"] == [
            "Halvar says packer=UPX; Noor says custom XOR",
        ]
        assert payload["inconclusive_areas"] == [
            "Whether the .rsrc 0x4c0608 block is a second config",
        ]
        assert payload["headline_verdict"].startswith("AsyncRAT sample")
        # summary mirrors the headline verdict as the fallback.
        assert payload["summary"] == payload["headline_verdict"]
        # IOC buckets promoted.
        iocs = payload["iocs"]
        assert iocs["domains"] == ["evil.example.com"]
        assert iocs["c2_stage_1_urls"] == ["http://evil.example.com/gate"]
        assert iocs["c2_stage_2_endpoints"] == ["ddns.example.com:443"]
        assert iocs["persistence"] == [
            "HKCU\\...\\Run AsyncRAT=%APPDATA%\\a.exe",
        ]

    def test_malware_null_family_does_not_write_the_key(self) -> None:
        agent = MalwareSynthesisAgent(investigation_id="i")
        parsed = _MW_CANNED.model_copy(update={"family_attribution": None})
        payload: dict[str, Any] = {}
        agent._update_payload_extras(payload, parsed)
        # attribution_rationale still lands; family_attribution is not
        # set to null (would overwrite an existing attribution when this
        # was a re-synthesize).
        assert "family_attribution" not in payload
        assert payload["attribution_rationale"] == parsed.attribution_rationale

    def test_malware_ioc_merge_preserves_existing_buckets(self) -> None:
        """Pre-existing IOC bucket entries survive; new entries append without duplicates."""
        agent = MalwareSynthesisAgent(investigation_id="i")
        payload: dict[str, Any] = {
            "iocs": {
                "domains": ["pre-existing.example.com", "evil.example.com"],
                "urls": ["http://another.example.com/x"],
            },
        }
        agent._update_payload_extras(payload, _MW_CANNED)
        merged = payload["iocs"]
        # Pre-existing bucket preserved and unioned with synth entry.
        assert merged["domains"] == [
            "pre-existing.example.com", "evil.example.com",
        ]
        # Pre-existing bucket that synth doesn't touch stays.
        assert merged["urls"] == ["http://another.example.com/x"]
        # New bucket from synth added.
        assert merged["c2_stage_1_urls"] == ["http://evil.example.com/gate"]


# --------------------------------------------------------------------- #
#  synthesis_confidence -- shared helper                                 #
# --------------------------------------------------------------------- #


class TestSynthesisConfidence:
    def test_unanimous_returns_median(self) -> None:
        panel = [
            {"confidence": "strong", "outcome_kind": "direct_finding"},
            {"confidence": "strong", "outcome_kind": "direct_finding"},
            {"confidence": "strong", "outcome_kind": "direct_finding"},
        ]
        assert synthesis_confidence(panel) == OutcomeConfidence.STRONG

    def test_exact_rank_round_trips(self) -> None:
        panel = [
            {"confidence": "exact", "outcome_kind": "direct_finding"},
            {"confidence": "exact", "outcome_kind": "direct_finding"},
            {"confidence": "exact", "outcome_kind": "direct_finding"},
        ]
        assert synthesis_confidence(panel) == OutcomeConfidence.EXACT

    def test_kind_disagreement_downgrades_one_notch(self) -> None:
        # median=strong (rank 1); 2 distinct kinds -> +1 notch -> medium.
        panel = [
            {"confidence": "strong", "outcome_kind": "direct_finding"},
            {"confidence": "strong", "outcome_kind": "patch_assessment_report"},
            {"confidence": "strong", "outcome_kind": "direct_finding"},
        ]
        assert synthesis_confidence(panel) == OutcomeConfidence.MEDIUM

    def test_three_way_disagreement_downgrades_two_notches(self) -> None:
        # median=strong (rank 1); 3 distinct kinds -> +2 notches -> caveated.
        panel = [
            {"confidence": "strong", "outcome_kind": "direct_finding"},
            {"confidence": "strong", "outcome_kind": "patch_assessment_report"},
            {"confidence": "strong", "outcome_kind": "audit_memo"},
        ]
        assert synthesis_confidence(panel) == OutcomeConfidence.CAVEATED

    def test_unknown_alias_falls_back(self) -> None:
        # 'weak' isn't a valid rank -> default to 4 (unknown).
        panel = [
            {"confidence": "weak", "outcome_kind": "direct_finding"},
            {"confidence": "weak", "outcome_kind": "direct_finding"},
            {"confidence": "weak", "outcome_kind": "direct_finding"},
        ]
        assert synthesis_confidence(panel) == OutcomeConfidence.UNKNOWN


# --------------------------------------------------------------------- #
#  run() orchestration -- DB seams patched with AsyncMock                #
# --------------------------------------------------------------------- #


def _fake_canonical_row(payload: dict[str, Any] | None = None, oid: str = "oc-1"):
    return type("Canonical", (), {
        "id": oid,
        "payload_json": json.dumps(payload) if payload else "{}",
    })()


def _fake_inv_row(status: str = InvestigationStatus.RUNNING.value):
    return type("Inv", (), {"id": "inv-x", "status": status})()


@pytest.mark.parametrize("cfg", ALL_CONFIGS, ids=[c.label for c in ALL_CONFIGS])
class TestRunOrchestration:
    @pytest.mark.asyncio
    async def test_investigation_not_found_skips(
        self, cfg: _Config,
    ) -> None:
        agent = cfg.agent_factory()
        agent._load_inv_and_canonical = AsyncMock(  # type: ignore[method-assign]
            return_value={"status": "skipped", "reason": "investigation_not_found"},
        )
        result = await agent.run()
        assert result == {"status": "skipped", "reason": "investigation_not_found"}

    @pytest.mark.asyncio
    async def test_no_canonical_outcome_skips(
        self, cfg: _Config,
    ) -> None:
        agent = cfg.agent_factory()
        agent._load_inv_and_canonical = AsyncMock(  # type: ignore[method-assign]
            return_value={"status": "skipped", "reason": "no_canonical_outcome"},
        )
        result = await agent.run()
        assert result["reason"] == "no_canonical_outcome"

    @pytest.mark.asyncio
    async def test_already_synthesized_skips(
        self, cfg: _Config,
    ) -> None:
        agent = cfg.agent_factory()
        canonical = _fake_canonical_row(payload={"panel_summary": {"narrative": "x"}})
        agent._load_inv_and_canonical = AsyncMock(  # type: ignore[method-assign]
            return_value=(_fake_inv_row(), canonical, {"panel_summary": {"narrative": "x"}}),
        )
        # _commit_synthesis must NOT be reached on this path.
        agent._commit_synthesis = AsyncMock(  # type: ignore[method-assign]
            side_effect=AssertionError("commit reached on skip path"),
        )
        result = await agent.run()
        assert result == {
            "status": "skipped",
            "reason": "already_synthesized",
            "canonical_outcome_id": "oc-1",
        }

    @pytest.mark.asyncio
    async def test_no_panel_contributions_skips(
        self, cfg: _Config,
    ) -> None:
        agent = cfg.agent_factory()
        canonical = _fake_canonical_row(payload={})
        agent._load_inv_and_canonical = AsyncMock(  # type: ignore[method-assign]
            return_value=(_fake_inv_row(), canonical, {}),
        )
        agent._commit_synthesis = AsyncMock(  # type: ignore[method-assign]
            side_effect=AssertionError("commit reached on skip path"),
        )
        result = await agent.run()
        assert result == {"status": "skipped", "reason": "no_panel_contributions"}

    @pytest.mark.asyncio
    async def test_no_valid_contributions_skips(
        self, cfg: _Config,
    ) -> None:
        agent = cfg.agent_factory()
        # panel_contributions contains only non-dict garbage.
        canonical_payload = {"panel_contributions": ["not-a-dict", 42, None]}
        canonical = _fake_canonical_row(payload=canonical_payload)
        agent._load_inv_and_canonical = AsyncMock(  # type: ignore[method-assign]
            return_value=(_fake_inv_row(), canonical, canonical_payload),
        )
        agent._commit_synthesis = AsyncMock(  # type: ignore[method-assign]
            side_effect=AssertionError("commit reached on skip path"),
        )
        result = await agent.run()
        assert result == {"status": "skipped", "reason": "no_valid_contributions"}


@pytest.mark.parametrize("cfg", ALL_CONFIGS, ids=[c.label for c in ALL_CONFIGS])
class TestRunHappyPath:
    @pytest.mark.asyncio
    async def test_llm_receives_module_task_type_and_prompt(
        self, cfg: _Config, bypass_llm,
    ) -> None:
        configure, calls = bypass_llm
        configure(response=cfg.canned_response)
        agent = cfg.agent_factory()
        canonical_payload = _canonical_payload(contribs_count=3)
        canonical = _fake_canonical_row(payload=canonical_payload)
        agent._load_inv_and_canonical = AsyncMock(  # type: ignore[method-assign]
            return_value=(_fake_inv_row(), canonical, canonical_payload),
        )
        agent._commit_synthesis = AsyncMock(  # type: ignore[method-assign]
            return_value={
                "status": "ok",
                "canonical_outcome_id": "oc-1",
                "panel_size": 3,
            },
        )
        result = await agent.run()
        assert result["status"] == "ok"
        assert result["panel_size"] == 3
        # LLM invoked once, with the module's task_type.
        assert len(calls) == 1
        assert calls[0]["task_type"] == cfg.task_type
        # System prompt is the module's _SYSTEM_PROMPT (schema-agnostic
        # check: just confirm the module-specific opening phrase leaked
        # through the messages list unchanged).
        messages = calls[0]["messages"]
        assert messages[0]["role"] == "system"
        assert messages[0]["content"] == cfg.agent_cls._SYSTEM_PROMPT
        assert messages[1]["role"] == "user"
        # model_class forwarded correctly (base uses ``model_class=``).
        assert calls[0].get("model_class") is cfg.response_cls

    @pytest.mark.asyncio
    async def test_commit_receives_parsed_and_synthesis_text(
        self, cfg: _Config, bypass_llm,
    ) -> None:
        configure, _calls = bypass_llm
        configure(response=cfg.canned_response)
        agent = cfg.agent_factory()
        canonical_payload = _canonical_payload(contribs_count=2)
        canonical = _fake_canonical_row(payload=canonical_payload)
        agent._load_inv_and_canonical = AsyncMock(  # type: ignore[method-assign]
            return_value=(_fake_inv_row(), canonical, canonical_payload),
        )
        commit_mock = AsyncMock(return_value={
            "status": "ok",
            "canonical_outcome_id": "oc-1",
            "panel_size": 2,
        })
        agent._commit_synthesis = commit_mock  # type: ignore[method-assign]
        await agent.run()
        assert commit_mock.await_count == 1
        args, kwargs = commit_mock.call_args
        # Positional: canonical_id, panel, parsed, synthesis_text.
        assert args[0] == "oc-1"
        assert isinstance(args[1], list) and len(args[1]) == 2
        assert isinstance(args[2], cfg.response_cls)
        # to_markdown returns non-empty text.
        assert isinstance(args[3], str) and args[3].strip()


# --------------------------------------------------------------------- #
#  Failure paths                                                        #
# --------------------------------------------------------------------- #


@pytest.mark.parametrize("cfg", ALL_CONFIGS, ids=[c.label for c in ALL_CONFIGS])
class TestRunFailurePaths:
    @pytest.mark.asyncio
    async def test_llm_kill_switch_disabled(
        self, cfg: _Config, bypass_llm,
    ) -> None:
        configure, _ = bypass_llm
        configure(response=_FakeLLMResponse(content="", disabled=True))
        agent = cfg.agent_factory()
        payload = _canonical_payload(contribs_count=1)
        canonical = _fake_canonical_row(payload=payload)
        agent._load_inv_and_canonical = AsyncMock(  # type: ignore[method-assign]
            return_value=(_fake_inv_row(), canonical, payload),
        )
        agent._commit_synthesis = AsyncMock(  # type: ignore[method-assign]
            side_effect=AssertionError("commit reached on disabled path"),
        )
        result = await agent.run()
        assert result == {"status": "skipped", "reason": "llm_kill_switch_active"}

    @pytest.mark.asyncio
    async def test_structured_parse_failure(
        self, cfg: _Config, bypass_llm,
    ) -> None:
        # The LLM returned JSON that doesn't validate the schema.
        configure, _ = bypass_llm
        configure(response=_FakeLLMResponse(content='{"garbage": true}'))
        agent = cfg.agent_factory()
        payload = _canonical_payload(contribs_count=1)
        canonical = _fake_canonical_row(payload=payload)
        agent._load_inv_and_canonical = AsyncMock(  # type: ignore[method-assign]
            return_value=(_fake_inv_row(), canonical, payload),
        )
        agent._commit_synthesis = AsyncMock(  # type: ignore[method-assign]
            side_effect=AssertionError("commit reached on parse-fail path"),
        )
        result = await agent.run()
        assert result == {"status": "failed", "reason": "structured_parse_failed"}

    @pytest.mark.asyncio
    async def test_llm_transport_error_returns_failed(
        self, cfg: _Config, bypass_llm,
    ) -> None:
        configure, _ = bypass_llm
        configure(raise_=httpx.HTTPError("boom"))
        agent = cfg.agent_factory()
        payload = _canonical_payload(contribs_count=1)
        canonical = _fake_canonical_row(payload=payload)
        agent._load_inv_and_canonical = AsyncMock(  # type: ignore[method-assign]
            return_value=(_fake_inv_row(), canonical, payload),
        )
        agent._commit_synthesis = AsyncMock(  # type: ignore[method-assign]
            side_effect=AssertionError("commit reached on transport-fail path"),
        )
        result = await agent.run()
        assert result["status"] == "failed"
        assert result["reason"].startswith("llm_error:")

    @pytest.mark.asyncio
    async def test_budget_exceeded_reraises(
        self, cfg: _Config, bypass_llm,
    ) -> None:
        configure, _ = bypass_llm
        configure(raise_=BudgetExceededError("bill hit"))
        agent = cfg.agent_factory()
        payload = _canonical_payload(contribs_count=1)
        canonical = _fake_canonical_row(payload=payload)
        agent._load_inv_and_canonical = AsyncMock(  # type: ignore[method-assign]
            return_value=(_fake_inv_row(), canonical, payload),
        )
        with pytest.raises(BudgetExceededError):
            await agent.run()


# --------------------------------------------------------------------- #
#  Malware force -- bypasses the pre-lock already_synthesized gate      #
# --------------------------------------------------------------------- #


class TestMalwareForceBypass:
    @pytest.mark.asyncio
    async def test_force_true_reaches_llm_despite_prior_panel_summary(
        self, bypass_llm,
    ) -> None:
        configure, calls = bypass_llm
        configure(response=_MW_CANNED)
        agent = MalwareSynthesisAgent(
            investigation_id="inv-force",
            options=MalwareSynthesisOptions(force=True),
        )
        # Canonical payload ALREADY carries a panel_summary -- default
        # behavior would skip. With force=True we should reach the LLM.
        payload = {
            "panel_summary": {"narrative": "old text"},
            **_canonical_payload(contribs_count=1),
        }
        canonical = _fake_canonical_row(payload=payload)
        agent._load_inv_and_canonical = AsyncMock(  # type: ignore[method-assign]
            return_value=(_fake_inv_row(), canonical, payload),
        )
        agent._commit_synthesis = AsyncMock(  # type: ignore[method-assign]
            return_value={
                "status": "ok",
                "canonical_outcome_id": "oc-1",
                "panel_size": 1,
            },
        )
        result = await agent.run()
        assert result["status"] == "ok"
        # LLM invoked -- pre-lock gate did NOT short-circuit us.
        assert len(calls) == 1

    @pytest.mark.asyncio
    async def test_force_false_skips_pre_lock(self, bypass_llm) -> None:
        configure, calls = bypass_llm
        configure(response=_MW_CANNED)
        agent = MalwareSynthesisAgent(
            investigation_id="inv-noforce",
            options=MalwareSynthesisOptions(force=False),
        )
        payload = {
            "panel_summary": {"narrative": "old text"},
            **_canonical_payload(contribs_count=1),
        }
        canonical = _fake_canonical_row(payload=payload)
        agent._load_inv_and_canonical = AsyncMock(  # type: ignore[method-assign]
            return_value=(_fake_inv_row(), canonical, payload),
        )
        result = await agent.run()
        assert result == {
            "status": "skipped",
            "reason": "already_synthesized",
            "canonical_outcome_id": "oc-1",
        }
        # LLM never called.
        assert calls == []
