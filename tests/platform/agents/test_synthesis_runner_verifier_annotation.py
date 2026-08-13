"""Acceptance test for issue #105 (P1) -- synthesis must annotate
each panel entry with the claim verifier's verdict and surface that
verdict in the rendered user prompt.

Before this wiring the shared synthesis runner assembled the panel
from ``payload['panel_contributions']`` and never read
``payload['verifier_report']`` -- the verdict the claim verifier
wrote post-synthesis simply never influenced the next synthesis pass.
After the wiring:

  * ``_build_panel_entry`` attaches ``verified_status`` derived from
    ``canonical_payload['verifier_report']['verdict']``: one of
    ``"confirmed"`` / ``"refuted"`` / ``"inconclusive"`` /
    ``"unverified"`` (fallback when no report has been written yet).
  * ``run`` appends a ``# Claim verifier annotations`` block after the
    subclass-rendered panel so the synthesis LLM sees each persona's
    verified_status and any verifier summary text. No panel entries
    are dropped: refuted claims stay in the panel and get annotated.

Tests exercise both module subclasses (vr + malware) so any drift
between the two rendering paths breaks the acceptance guard.
"""
from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock

import pytest

from aila.modules.malware.agents.synthesis_agent import (
    IOCBundle,
    SynthesisAgent as MalwareSynthesisAgent,
)
from aila.modules.malware.agents.synthesis_agent import (
    SynthesisResponse as MalwareSynthesisResponse,
)
from aila.modules.vr.agents.synthesis_agent import (
    SynthesisAgent as VRSynthesisAgent,
)
from aila.modules.vr.agents.synthesis_agent import (
    SynthesisResponse as VRSynthesisResponse,
)
from aila.platform.agents.synthesis_runner import (
    _render_verifier_annotation,
    _verified_status_from_payload,
)
from aila.platform.contracts.enums import InvestigationStatus


# --------------------------------------------------------------------- #
#  Panel-entry annotation (base helper)                                 #
# --------------------------------------------------------------------- #


class TestVerifiedStatusHelper:
    def test_missing_verifier_report_is_unverified(self) -> None:
        assert _verified_status_from_payload({}) == "unverified"

    def test_non_dict_verifier_report_is_unverified(self) -> None:
        assert _verified_status_from_payload(
            {"verifier_report": "malformed-string"},
        ) == "unverified"

    def test_missing_verdict_is_unverified(self) -> None:
        assert _verified_status_from_payload(
            {"verifier_report": {"summary": "x"}},
        ) == "unverified"

    def test_unknown_verdict_is_unverified(self) -> None:
        assert _verified_status_from_payload(
            {"verifier_report": {"verdict": "maybe"}},
        ) == "unverified"

    @pytest.mark.parametrize(
        "verdict", ["confirmed", "refuted", "inconclusive"],
    )
    def test_known_verdict_round_trips(self, verdict: str) -> None:
        assert _verified_status_from_payload(
            {"verifier_report": {"verdict": verdict}},
        ) == verdict


# --------------------------------------------------------------------- #
#  _build_panel_entry -- both subclasses inherit the annotation         #
# --------------------------------------------------------------------- #


def _contrib(persona: str) -> dict[str, Any]:
    return {
        "branch_id": f"br-{persona}",
        "persona": persona,
        "at_turn": 12,
        "outcome_kind": "direct_finding",
        "confidence": "strong",
        "answer_brief": f"{persona} claim body",
    }


class TestBuildPanelEntryCarriesVerifiedStatus:
    def _canonical_payload(
        self, verdict: str | None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "panel_contributions": [_contrib("halvar"), _contrib("renzo")],
            "affected_components": ["src/foo.cc:120"],
            "variant_hunt_orders": [],
        }
        if verdict is not None:
            payload["verifier_report"] = {
                "verdict": verdict,
                "confidence": 0.87,
                "summary": "Probe reproduced the type confusion via the "
                           "argv[1] length overflow on the parsing path.",
            }
        return payload

    @pytest.mark.parametrize(
        "verdict, expected",
        [
            (None, "unverified"),
            ("confirmed", "confirmed"),
            ("refuted", "refuted"),
            ("inconclusive", "inconclusive"),
        ],
    )
    def test_vr_entry_carries_verified_status(
        self, verdict: str | None, expected: str,
    ) -> None:
        agent = VRSynthesisAgent(investigation_id="inv-x")
        payload = self._canonical_payload(verdict)
        entry = agent._build_panel_entry(
            payload["panel_contributions"][0], payload,
        )
        assert entry["verified_status"] == expected
        # vr override still adds the two vr-specific keys on top.
        assert "affected_components" in entry
        assert "variant_hunt_orders" in entry

    @pytest.mark.parametrize(
        "verdict, expected",
        [
            (None, "unverified"),
            ("confirmed", "confirmed"),
            ("refuted", "refuted"),
            ("inconclusive", "inconclusive"),
        ],
    )
    def test_malware_entry_carries_verified_status(
        self, verdict: str | None, expected: str,
    ) -> None:
        agent = MalwareSynthesisAgent(investigation_id="inv-y")
        payload = self._canonical_payload(verdict)
        entry = agent._build_panel_entry(
            payload["panel_contributions"][0], payload,
        )
        assert entry["verified_status"] == expected


# --------------------------------------------------------------------- #
#  Prompt injection -- run() concatenates the verifier block            #
# --------------------------------------------------------------------- #


class _FakeLLMResponse:
    def __init__(self, content: str, disabled: bool = False) -> None:
        self.content = content
        self.disabled = disabled
        self.model = "test-model"
        self.usage: dict[str, int] = {}
        self.finish_reason = "stop"


def _fake_inv_row(status: str = InvestigationStatus.RUNNING.value):
    return type("Inv", (), {"id": "inv-x", "status": status})()


def _fake_canonical_row(payload: dict[str, Any], oid: str = "oc-1"):
    return type("Canonical", (), {
        "id": oid,
        "payload_json": json.dumps(payload),
    })()


@pytest.fixture
def bypass_llm(monkeypatch: pytest.MonkeyPatch):
    """Stub ``idempotent_llm_call`` and ``ServiceFactory``.

    Captures every LLM invocation on ``calls`` so tests can assert the
    user prompt includes the verifier annotation block.
    """
    state: dict[str, Any] = {"response": _FakeLLMResponse("")}
    calls: list[dict[str, Any]] = []

    async def _bypass(llm_client, *, method, task_type, messages, **kwargs):
        del llm_client, method, task_type
        calls.append({"messages": list(messages), **kwargs})
        return state["response"], False

    monkeypatch.setattr(
        "aila.platform.agents.synthesis_runner.idempotent_llm_call",
        _bypass,
    )

    class _StubFactory:
        @property
        def llm_client(self) -> Any:
            return "stub-llm"

    monkeypatch.setattr(
        "aila.platform.agents.synthesis_runner.ServiceFactory",
        _StubFactory,
    )

    def configure(response: Any) -> None:
        if isinstance(response, str):
            state["response"] = _FakeLLMResponse(content=response)
        elif isinstance(response, _FakeLLMResponse):
            state["response"] = response
        else:
            state["response"] = _FakeLLMResponse(
                content=response.model_dump_json(),
            )

    return configure, calls


@pytest.fixture(autouse=True)
def _no_reviews(monkeypatch: pytest.MonkeyPatch) -> None:
    """Skip the DB-backed sibling-review load so no infra is required."""
    async def _empty(self: Any, canonical_id: str) -> list[dict[str, Any]]:
        del self, canonical_id
        return []

    monkeypatch.setattr(
        "aila.platform.agents.synthesis_runner.SynthesisRunnerBase._load_reviews",
        _empty,
    )


_VR_CANNED = VRSynthesisResponse(
    scope="Panel scoped to the InferMaps type-confusion hypothesis.",
    headline_verdict="Panel converged on a real TypeConfusion in InferMaps.",
    points_of_agreement=["Halvar + Renzo cite src/foo.cc:120"],
    points_of_disagreement=[],
    unresolved_questions=[],
    recommended_next_actions=[],
)


class TestRunAppendsVerifierAnnotationToUserPrompt:
    @pytest.mark.asyncio
    async def test_refuted_verdict_is_surfaced_in_user_prompt(
        self, bypass_llm,
    ) -> None:
        configure, calls = bypass_llm
        configure(response=_VR_CANNED)

        agent = VRSynthesisAgent(investigation_id="inv-x")
        payload: dict[str, Any] = {
            "panel_contributions": [_contrib("halvar"), _contrib("renzo")],
            "affected_components": ["src/foo.cc:120"],
            "variant_hunt_orders": [],
            "verifier_report": {
                "verdict": "refuted",
                "confidence": 0.15,
                "summary": (
                    "Probe with malformed input did not reproduce; the "
                    "guard at src/foo.cc:118 short-circuits before the "
                    "cast."
                ),
            },
        }
        canonical = _fake_canonical_row(payload=payload)
        agent._load_inv_and_canonical = AsyncMock(  # type: ignore[method-assign]
            return_value=(_fake_inv_row(), canonical, payload),
        )
        agent._commit_synthesis = AsyncMock(  # type: ignore[method-assign]
            return_value={
                "status": "ok",
                "canonical_outcome_id": "oc-1",
                "panel_size": 2,
            },
        )

        result = await agent.run()
        assert result["status"] == "ok"

        # One LLM call reached the stub.
        assert len(calls) == 1
        user_message = calls[0]["messages"][1]
        assert user_message["role"] == "user"
        content = user_message["content"]

        # The verifier block is appended AFTER the vr panel body.
        assert "# Claim verifier annotations" in content
        # Every panel entry carries the ``refuted`` token.
        assert content.count("verified_status=refuted") == 2
        assert "HALVAR" in content  # subclass panel body still present
        # Each persona is individually named in the verifier roster.
        assert "HALVAR (branch=br-halvar): verified_status=refuted" in content or \
               "halvar (branch=br-halvar): verified_status=refuted" in content
        # Verifier summary text is surfaced for the model.
        assert "Verifier summary:" in content
        assert "short-circuits before" in content
        # No panel entry was dropped even though the verdict is refuted.
        assert "PERSONA" not in content  # sanity: our personas are halvar+renzo
        assert "RENZO" in content

    @pytest.mark.asyncio
    async def test_missing_verifier_report_annotates_unverified(
        self, bypass_llm,
    ) -> None:
        configure, calls = bypass_llm
        configure(response=_VR_CANNED)

        agent = VRSynthesisAgent(investigation_id="inv-x")
        payload: dict[str, Any] = {
            "panel_contributions": [_contrib("halvar"), _contrib("renzo")],
            "affected_components": [],
            "variant_hunt_orders": [],
            # No verifier_report -- initial synthesis pass.
        }
        canonical = _fake_canonical_row(payload=payload)
        agent._load_inv_and_canonical = AsyncMock(  # type: ignore[method-assign]
            return_value=(_fake_inv_row(), canonical, payload),
        )
        agent._commit_synthesis = AsyncMock(  # type: ignore[method-assign]
            return_value={
                "status": "ok",
                "canonical_outcome_id": "oc-1",
                "panel_size": 2,
            },
        )

        result = await agent.run()
        assert result["status"] == "ok"

        content = calls[0]["messages"][1]["content"]
        # Annotation block still appears (so the model always knows the
        # verifier surface exists) but every entry is marked unverified
        # and no summary line is emitted (nothing to summarise).
        assert "# Claim verifier annotations" in content
        assert content.count("verified_status=unverified") == 2
        assert "Verifier summary:" not in content

    @pytest.mark.asyncio
    async def test_malware_prompt_also_receives_the_annotation(
        self, bypass_llm,
    ) -> None:
        """The base's append happens regardless of which subclass
        renders the panel; malware's ``_render_user_prompt`` output is
        also followed by the verifier annotation block."""
        configure, calls = bypass_llm
        canned = MalwareSynthesisResponse(
            family_attribution=None,
            attribution_rationale="Panel could not pin a family.",
            scope="Reviewed the .rsrc block for the AsyncRAT config marker.",
            headline_verdict="Panel dissented on family attribution.",
            capabilities=[],
            inconclusive_capabilities=[],
            iocs=IOCBundle(),
            detection_guidance=[],
            next_actions=[],
            panel_dissent=[],
            inconclusive_areas=[],
        )
        configure(response=canned)

        agent = MalwareSynthesisAgent(investigation_id="inv-y")
        payload: dict[str, Any] = {
            "panel_contributions": [_contrib("halvar")],
            "verifier_report": {
                "verdict": "inconclusive",
                "summary": "Probe timed out on the imports table read.",
            },
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

        await agent.run()

        content = calls[0]["messages"][1]["content"]
        # Malware's own panel body is present (subclass renderer).
        assert "# Persona deliberation panel" in content
        # Verifier block appended by the base runner.
        assert "# Claim verifier annotations" in content
        assert "verified_status=inconclusive" in content
        assert "Probe timed out" in content


# --------------------------------------------------------------------- #
#  Direct helper test -- refuted claims are NOT dropped                 #
# --------------------------------------------------------------------- #


class TestRenderVerifierAnnotationDoesNotDropEntries:
    def test_all_personas_named_in_annotation_block(self) -> None:
        payload = {
            "verifier_report": {
                "verdict": "refuted",
                "summary": "Contradicting probe evidence.",
            },
        }
        panel = [
            {
                "branch_id": "br-a", "persona_voice": "halvar",
                "verified_status": "refuted",
            },
            {
                "branch_id": "br-b", "persona_voice": "renzo",
                "verified_status": "refuted",
            },
            {
                "branch_id": "br-c", "persona_voice": "maddie",
                "verified_status": "refuted",
            },
        ]
        block = _render_verifier_annotation(payload, panel)
        assert "halvar (branch=br-a): verified_status=refuted" in block
        assert "renzo (branch=br-b): verified_status=refuted" in block
        assert "maddie (branch=br-c): verified_status=refuted" in block
        assert "Verifier summary: Contradicting probe evidence." in block

    def test_empty_panel_returns_empty_string(self) -> None:
        assert _render_verifier_annotation({"verifier_report": {}}, []) == ""
