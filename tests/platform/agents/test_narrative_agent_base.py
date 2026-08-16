"""NarrativeAgentBase contract tests (RFC #208 P2, closes #112 + #137).

Covers the shared skeleton lifted out of the VR and malware
NarrativeAgent implementations:

    (a) :func:`render_narrative_prompt` folds the tone directive,
        length directive, operator focus, and every subclass-supplied
        chronology section into the user prompt.
    (b) A minimal concrete subclass whose seams are stubbed drives the
        full :meth:`NarrativeAgentBase.run` template end to end and
        persists a :class:`NarrativeResponse` payload under
        ``payload["investigation_narrative"]`` on the canonical
        outcome row.
    (c) :func:`build_narrative_payload` strips a ``<script>`` tag from
        the body via :func:`sanitize_output`, records the strip count
        under ``sanitizer_counts``, and emits the canonical wire keys
        (``tone_used`` / ``length_used`` / ``narrative_words``).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import pytest

from aila.platform.agents.narrative_agent import (
    LENGTH_DIRECTIVES,
    TONE_DIRECTIVES,
    NarrativeAgentBase,
    NarrativeOptions,
    NarrativePromptContext,
    NarrativeResponse,
    build_narrative_payload,
    render_narrative_prompt,
)
from aila.platform.prompts import PromptRegistry

# --------------------------------------------------------------------- #
#  (a) render_narrative_prompt                                          #
# --------------------------------------------------------------------- #


class TestRenderNarrativePrompt:
    def test_includes_tone_length_focus_and_chronology_sections(self) -> None:
        ctx = NarrativePromptContext(
            investigation_id="inv-42",
            options=NarrativeOptions(
                tone="thriller",
                length="long",
                operator_focus="lead with the Stage 2 unpack moment",
            ),
            inv_question="what does this sample actually do?",
            panel_summary={"narrative": "spine from synthesis"},
            panel_contributions=[
                {
                    "persona": "halvar",
                    "at_turn": 3,
                    "outcome_kind": "direct_finding",
                    "confidence": "high",
                    "answer_brief": "unbounded memcpy at http.c:412",
                },
            ],
            chronology_sections=[
                "## Observation chronology (1 rows; chronological order)\n"
                "- [2026-06-25T20:00:00Z] kind=crypto_algorithm "
                "polarity=positive branch=abc12345 "
                "-- ida_headless.detect_crypto_primitives: "
                "primitives_found=3\n",
            ],
        )
        out = render_narrative_prompt(ctx)

        assert TONE_DIRECTIVES["thriller"] in out
        assert LENGTH_DIRECTIVES["long"] in out
        assert "User focus" in out
        assert "Stage 2 unpack moment" in out
        assert "Initial question" in out
        assert "what does this sample actually do?" in out
        assert "Synthesized findings" in out
        assert "spine from synthesis" in out
        assert "Panel contributions (1)" in out
        assert "HALVAR" in out
        assert "unbounded memcpy at http.c:412" in out
        assert "Observation chronology" in out
        assert "primitives_found=3" in out
        assert "# Write the narrative" in out
        assert "``thriller``" in out  # tone echo in terminal instruction

    def test_skips_empty_optional_sections(self) -> None:
        ctx = NarrativePromptContext(
            investigation_id="inv-x",
            options=NarrativeOptions(),
        )
        out = render_narrative_prompt(ctx)

        assert "User focus" not in out
        assert "Investigation title" not in out
        assert "Initial question" not in out
        assert "Final verdict" not in out
        assert "Claim verifier report" not in out
        assert "Synthesized findings" not in out
        assert "Panel contributions" not in out


# --------------------------------------------------------------------- #
#  (c) sanitize-on-persist                                              #
# --------------------------------------------------------------------- #


class TestBuildNarrativePayload:
    def test_strips_script_tag_from_body(self) -> None:
        out = build_narrative_payload(
            title="Clean Title",
            body="Intro <script>alert(1)</script> tail.",
            chapter_outline=["chapter one"],
            tone="blog",
            length="standard",
        )
        assert "<script>" not in out["body"]
        assert out["sanitizer_counts"]["body"] >= 1
        assert out["title"] == "Clean Title"
        assert out["sanitizer_counts"]["title"] == 0
        # Canonical wire keys the frontend + the base both read.
        assert out["tone_used"] == "blog"
        assert out["length_used"] == "standard"
        assert out["narrative_words"] == len(out["body"].split())


# --------------------------------------------------------------------- #
#  (b) run() template end to end with a minimal concrete subclass      #
# --------------------------------------------------------------------- #


@dataclass
class _StubInv:
    id: str
    initial_question: str = "why does this thing crash on boot?"


@dataclass
class _StubCanonical:
    id: str
    payload_json: str = "{}"


@dataclass
class _StubSession:
    added: list[Any] = field(default_factory=list)
    commits: int = 0

    async def exec(self, _stmt: Any) -> Any:
        # The stub subclass below never routes DB reads through
        # session.exec -- it returns rows directly from its overrides.
        # So this is only reached if a subclass accidentally does; we
        # return a no-row scalar to keep the run graceful.
        return _ScalarNoRow()

    def add(self, obj: Any) -> None:
        self.added.append(obj)


class _ScalarNoRow:
    def first(self):
        return None

    def all(self):
        return []


@dataclass
class _StubUoW:
    session: _StubSession = field(default_factory=_StubSession)
    commits: int = 0

    async def __aenter__(self) -> _StubUoW:
        return self

    async def __aexit__(self, *args: Any) -> bool:
        return False

    async def commit(self) -> None:
        self.commits += 1


class _StubServiceFactory:
    @property
    def llm_client(self) -> Any:
        return "stub-llm-client"


class _StubLLMResponse:
    def __init__(self, content: str) -> None:
        self.content = content
        self.disabled = False


def _canned_narrative_json() -> str:
    return NarrativeResponse(
        title="A crisp headline for the writeup",
        body="## Prelude\n\n" + ("The panel opened the case. " * 300) + "\n",
        chapter_outline=["Prelude", "Audit", "Verdict"],
        tone_used="blog",
    ).model_dump_json()


class _StubPromptRegistry:
    """Minimal :class:`PromptRegistry`-compatible object -- we only
    exercise ``.load()`` here."""

    def load(self, _role: str) -> str:
        return "SYSTEM PROMPT: stub narrative body"


class _StubNarrativeAgent(NarrativeAgentBase[_StubInv, _StubCanonical]):
    """Concrete subclass wired to in-memory stubs -- the smallest
    subclass that satisfies the abstract seams."""

    _TASK_TYPE = "test.narrative"
    _LOG_LABEL = "test narrative"

    def __init__(
        self,
        investigation_id: str,
        *,
        options: NarrativeOptions | None = None,
        inv: _StubInv | None = None,
        canonical: _StubCanonical | None = None,
    ) -> None:
        super().__init__(investigation_id, options=options)
        self._inv = inv
        self._canonical = canonical
        # Records what the persist path locked and rewrote so the test
        # can inspect the payload without reaching into UoW internals.
        self.persisted: _StubCanonical | None = None

    @property
    def _prompt_registry(self) -> PromptRegistry:  # type: ignore[override]
        return _StubPromptRegistry()  # type: ignore[return-value]

    async def _load_investigation(self, uow: Any) -> _StubInv | None:
        del uow
        return self._inv

    async def _load_canonical_outcome(
        self, uow: Any, inv: _StubInv,
    ) -> _StubCanonical | None:
        del uow, inv
        return self._canonical

    async def _reload_canonical_locked(
        self, uow: Any, canonical_id: str,
    ) -> _StubCanonical | None:
        del uow
        assert self._canonical is not None
        assert self._canonical.id == canonical_id
        # The persist path mutates this row in place; hand back the same
        # object so the test can read the resulting payload_json.
        self.persisted = self._canonical
        return self._canonical

    async def _build_prompt_context(
        self,
        uow: Any,
        inv: _StubInv,
        canonical: _StubCanonical,
        canonical_payload: dict[str, Any],
    ) -> NarrativePromptContext:
        del uow, canonical, canonical_payload
        return NarrativePromptContext(
            investigation_id=self.investigation_id,
            options=self.options,
            inv_question=inv.initial_question,
            chronology_sections=[
                "## Stub chronology (0 rows)\n",
            ],
        )


@pytest.fixture
def patch_base_seams(monkeypatch: pytest.MonkeyPatch):
    """Patch UoW + ServiceFactory + idempotent_llm_call in the base
    module. Returns a dict recording the LLM invocation kwargs so the
    test can assert task_type / messages routing."""
    calls: dict[str, Any] = {}

    def _make_uow() -> _StubUoW:
        return _StubUoW()

    async def _stub_idempotent(
        _llm_client: Any, **kwargs: Any,
    ) -> tuple[_StubLLMResponse, bool]:
        calls["kwargs"] = kwargs
        return _StubLLMResponse(content=_canned_narrative_json()), False

    monkeypatch.setattr(
        "aila.platform.agents.narrative_agent.UnitOfWork", _make_uow,
    )
    monkeypatch.setattr(
        "aila.platform.agents.narrative_agent.ServiceFactory",
        _StubServiceFactory,
    )
    monkeypatch.setattr(
        "aila.platform.agents.narrative_agent.idempotent_llm_call",
        _stub_idempotent,
    )
    return calls


class TestRunTemplateEndToEnd:
    @pytest.mark.asyncio
    async def test_run_persists_narrative_payload(
        self, patch_base_seams: dict[str, Any],
    ) -> None:
        inv = _StubInv(id="inv-1")
        canonical = _StubCanonical(id="oc-1", payload_json=json.dumps({
            "panel_summary": {"narrative": "prior synth"},
        }))
        agent = _StubNarrativeAgent(
            investigation_id="inv-1",
            options=NarrativeOptions(tone="blog", length="standard"),
            inv=inv,
            canonical=canonical,
        )

        result = await agent.run()

        assert result["status"] == "ok"
        assert result["canonical_outcome_id"] == "oc-1"
        assert result["narrative_words"] > 0
        assert result["tone"] == "blog"
        assert result["length"] == "standard"

        # LLM was called with the subclass's _TASK_TYPE and the system
        # prompt resolved through the subclass's prompt registry.
        assert patch_base_seams["kwargs"]["task_type"] == "test.narrative"
        messages = patch_base_seams["kwargs"]["messages"]
        assert messages[0]["role"] == "system"
        assert messages[0]["content"] == "SYSTEM PROMPT: stub narrative body"
        assert messages[1]["role"] == "user"
        assert "# Investigation inv-1" in messages[1]["content"]
        assert "Stub chronology" in messages[1]["content"]

        # Persisted payload -- narrative COEXISTS with the prior
        # panel_summary; base emits the canonical wire keys.
        assert agent.persisted is not None
        written = json.loads(agent.persisted.payload_json)
        assert "investigation_narrative" in written
        assert written["panel_summary"] == {"narrative": "prior synth"}
        narrative = written["investigation_narrative"]
        assert narrative["title"] == "A crisp headline for the writeup"
        assert narrative["tone_used"] == "blog"
        assert narrative["length_used"] == "standard"
        assert narrative["narrative_words"] > 0
        assert narrative["chapter_outline"] == ["Prelude", "Audit", "Verdict"]

    @pytest.mark.asyncio
    async def test_run_skips_when_narrative_already_present(
        self, patch_base_seams: dict[str, Any],
    ) -> None:
        del patch_base_seams  # LLM is not called on the idempotent path.
        inv = _StubInv(id="inv-2")
        canonical = _StubCanonical(id="oc-2", payload_json=json.dumps({
            "investigation_narrative": {"title": "already there", "body": "x" * 4200},
        }))
        agent = _StubNarrativeAgent(
            investigation_id="inv-2",
            options=NarrativeOptions(),  # force=False
            inv=inv,
            canonical=canonical,
        )

        result = await agent.run()

        assert result["status"] == "skipped"
        assert result["reason"] == "narrative_already_present"
        assert result["canonical_outcome_id"] == "oc-2"

    @pytest.mark.asyncio
    async def test_run_skips_when_investigation_missing(
        self, patch_base_seams: dict[str, Any],
    ) -> None:
        del patch_base_seams
        agent = _StubNarrativeAgent(
            investigation_id="inv-missing", inv=None, canonical=None,
        )
        result = await agent.run()
        assert result == {
            "status": "skipped", "reason": "investigation_not_found",
        }
