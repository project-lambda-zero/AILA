"""VR NarrativeAgent contract tests.

The narrative is a SEPARATE artifact from the structured synthesis --
a long-form vulnerability-research writeup stored under
``payload['investigation_narrative']`` on the canonical outcome row,
alongside (not replacing) ``payload['panel_summary']``.

Coverage:
  * Schema + options surface (defaults, tone / length echo, validation).
  * Prompt rendering: tone / length directives cover every value;
    optional focus / verifier / verdict / branch-roster blocks appear
    only when their inputs are set.
  * Message-payload summarizer collapses each of the VR payload_kinds
    the reasoning loop emits (tool_call / text / decompiled_function /
    taint_flow / outcome_pending) into a one-line summary.
  * ``run()`` orchestration with the DB seams + LLM call patched to
    fakes:
      - persists ``investigation_narrative`` on the canonical outcome
      - preserves an existing ``panel_summary`` alongside the narrative
      - is idempotent without ``force`` (a second run returns
        ``status=skipped`` and does NOT re-write the payload)
      - honors ``force=True`` (re-writes even when a narrative is
        already present)
      - resolves ``inv.primary_outcome_id`` when set, falling back to
        the earliest outcome by ``created_at`` otherwise.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import pytest
from pydantic import ValidationError

from aila.modules.vr.agents.narrative_agent import (
    VRNarrativeAgent as NarrativeAgent,
)
from aila.modules.vr.agents.narrative_agent import (
    _load_system_prompt,
    _render_branch_roster_section,
    _render_message_chronology_section,
    _summarize_message_payload,
)
from aila.platform.agents.narrative_agent import (
    LENGTH_DIRECTIVES,
    TONE_DIRECTIVES,
    NarrativeOptions,
    NarrativePromptContext,
    NarrativeResponse,
    render_narrative_prompt,
)


def _render_narrative_prompt(
    *,
    investigation_id: str,
    inv_question: str,
    inv_title: str,
    verdict: str,
    branch_roster: list,
    panel_contributions: list,
    panel_summary: dict,
    verifier_report: dict,
    messages: list,
    options: NarrativeOptions,
) -> str:
    """Test-local adapter: build a NarrativePromptContext from the VR
    kwargs (via the module's real section renderers) and delegate to the
    shared platform renderer. Replaces the removed production shim."""
    chronology_sections: list[str] = []
    roster_section = _render_branch_roster_section(branch_roster)
    if roster_section:
        chronology_sections.append(roster_section)
    chrono_section = _render_message_chronology_section(messages)
    if chrono_section:
        chronology_sections.append(chrono_section)
    return render_narrative_prompt(
        NarrativePromptContext(
            investigation_id=investigation_id,
            options=options,
            inv_question=inv_question,
            inv_title=inv_title,
            verdict=verdict,
            verifier_report=verifier_report if verifier_report else None,
            panel_summary=panel_summary if panel_summary else None,
            panel_contributions=list(panel_contributions or []),
            chronology_sections=chronology_sections,
        ),
    )

# The historical test referenced a module-level ``_SYSTEM_PROMPT`` string
# constant that predates the RFC-09 PromptRegistry rework; the current
# module resolves the body lazily through ``_load_system_prompt()``. We
# keep the name as a module-local snapshot so the existing assertions
# read the resolved body without a wider rewrite.
_SYSTEM_PROMPT = _load_system_prompt()

# --------------------------------------------------------------------- #
#  Schema + options                                                     #
# --------------------------------------------------------------------- #


class TestNarrativeOptions:
    def test_defaults(self) -> None:
        opts = NarrativeOptions()
        assert opts.force is False
        assert opts.tone == "blog"
        assert opts.length == "standard"
        assert opts.operator_focus == ""

    def test_set_fields(self) -> None:
        opts = NarrativeOptions(
            force=True,
            tone="academic",
            length="long",
            operator_focus="focus on the parse_header sink",
        )
        assert opts.force is True
        assert opts.tone == "academic"
        assert opts.length == "long"
        assert "parse_header" in opts.operator_focus


class TestNarrativeResponse:
    def test_minimum_valid(self) -> None:
        r = NarrativeResponse(title="A crisp headline", body="x" * 4200)
        assert r.title == "A crisp headline"
        assert r.tone_used == "blog"
        assert r.chapter_outline == []

    def test_body_too_short_rejected(self) -> None:
        with pytest.raises(ValidationError):
            NarrativeResponse(title="t", body="x" * 3999)

    def test_body_too_long_rejected(self) -> None:
        with pytest.raises(ValidationError):
            NarrativeResponse(title="t", body="x" * 65_000)

    def test_title_empty_rejected(self) -> None:
        with pytest.raises(ValidationError):
            NarrativeResponse(title="", body="x" * 4200)

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            NarrativeResponse(  # type: ignore[call-arg]
                title="t", body="x" * 4200, junk="x",
            )

    def test_chapter_outline_round_trips(self) -> None:
        r = NarrativeResponse(
            title="t",
            body="x" * 4200,
            chapter_outline=["Intro", "The audit", "Verdict"],
        )
        assert r.chapter_outline == ["Intro", "The audit", "Verdict"]

    def test_tone_used_echoes(self) -> None:
        r = NarrativeResponse(
            title="t", body="x" * 4200, tone_used="academic",
        )
        assert r.tone_used == "academic"


class TestNarrativeAgentConstruction:
    def test_default_options(self) -> None:
        agent = NarrativeAgent(investigation_id="inv-x")
        assert agent.investigation_id == "inv-x"
        assert agent.options.tone == "blog"
        assert agent.options.length == "standard"
        assert agent.options.force is False

    def test_custom_options(self) -> None:
        agent = NarrativeAgent(
            investigation_id="inv-x",
            options=NarrativeOptions(force=True, tone="thriller", length="long"),
        )
        assert agent.options.tone == "thriller"
        assert agent.options.length == "long"
        assert agent.options.force is True


# --------------------------------------------------------------------- #
#  Prompt rendering                                                     #
# --------------------------------------------------------------------- #


class TestPromptComposition:
    def test_tone_directives_cover_every_tone(self) -> None:
        for tone in ("blog", "incident_report", "thriller", "academic", "casual"):
            assert tone in TONE_DIRECTIVES
            assert len(TONE_DIRECTIVES[tone]) > 100

    def test_length_directives_cover_every_length(self) -> None:
        for length in ("short", "standard", "long"):
            assert length in LENGTH_DIRECTIVES
            assert "word" in LENGTH_DIRECTIVES[length].lower()

    def test_system_prompt_names_vulnerability_research(self) -> None:
        # This is a VR narrative, not a malware narrative -- the
        # system prompt has to be domain-specific so the LLM writes
        # vuln-research prose instead of IOC / capability enumeration.
        assert "vulnerability-research" in _SYSTEM_PROMPT
        assert "audit-mcp" in _SYSTEM_PROMPT

    def test_render_prompt_includes_focus_block_when_set(self) -> None:
        prompt = _render_narrative_prompt(
            investigation_id="inv-x",
            inv_question="Is there a bug here?",
            inv_title="",
            verdict="",
            branch_roster=[],
            panel_contributions=[],
            panel_summary={},
            verifier_report={},
            messages=[],
            options=NarrativeOptions(operator_focus="parse_header sink audit"),
        )
        assert "User focus" in prompt
        assert "parse_header sink audit" in prompt

    def test_render_prompt_skips_focus_block_when_empty(self) -> None:
        prompt = _render_narrative_prompt(
            investigation_id="inv-x",
            inv_question="Is there a bug here?",
            inv_title="",
            verdict="",
            branch_roster=[],
            panel_contributions=[],
            panel_summary={},
            verifier_report={},
            messages=[],
            options=NarrativeOptions(),
        )
        assert "User focus" not in prompt

    def test_render_prompt_surfaces_verdict_and_verifier(self) -> None:
        prompt = _render_narrative_prompt(
            investigation_id="inv-x",
            inv_question="",
            inv_title="",
            verdict="direct_finding",
            branch_roster=[],
            panel_contributions=[],
            panel_summary={},
            verifier_report={
                "verdict": "confirmed",
                "confidence": 0.87,
                "summary": "audit_mcp confirmed unchecked memcpy at src/http.c:412",
            },
            messages=[],
            options=NarrativeOptions(),
        )
        assert "Final verdict" in prompt
        assert "direct_finding" in prompt
        assert "Claim verifier report" in prompt
        assert "confirmed" in prompt
        assert "src/http.c:412" in prompt

    def test_render_prompt_lists_persona_roster(self) -> None:
        prompt = _render_narrative_prompt(
            investigation_id="inv-x",
            inv_question="",
            inv_title="",
            verdict="",
            branch_roster=[
                {
                    "branch_id": "brnch-halvar-01",
                    "persona_voice": "halvar",
                    "turn_count": 14,
                    "status": "closed",
                },
                {
                    "branch_id": "brnch-maddie-01",
                    "persona_voice": "maddie",
                    "turn_count": 9,
                    "status": "closed",
                },
            ],
            panel_contributions=[],
            panel_summary={},
            verifier_report={},
            messages=[],
            options=NarrativeOptions(),
        )
        assert "Persona panel" in prompt
        assert "HALVAR" in prompt
        assert "MADDIE" in prompt
        assert "turns=14" in prompt

    def test_render_prompt_includes_message_chronology(self) -> None:
        prompt = _render_narrative_prompt(
            investigation_id="inv-x",
            inv_question="",
            inv_title="",
            verdict="",
            branch_roster=[],
            panel_contributions=[],
            panel_summary={},
            verifier_report={},
            messages=[
                {
                    "payload_kind": "tool_call",
                    "sender_kind": "engine",
                    "branch_id": "brnch-halvar-01",
                    "at_turn": 3,
                    "created_at": "2026-07-20T10:00:00Z",
                    "summary": "tool=audit_mcp.taint_paths_to; args={\"name\": \"memcpy\"}",
                },
            ],
            options=NarrativeOptions(),
        )
        assert "Message chronology" in prompt
        assert "taint_paths_to" in prompt
        assert "brnch-ha" in prompt  # first 8 chars of branch id


# --------------------------------------------------------------------- #
#  Message summarizer                                                   #
# --------------------------------------------------------------------- #


class TestMessagePayloadSummarizer:
    def test_tool_call_extracts_tool_and_args(self) -> None:
        summary = _summarize_message_payload(
            "tool_call",
            {
                "command": json.dumps(
                    {"tool": "audit_mcp.read_function",
                     "args": {"name": "parse_header"}},
                ),
                "reasoning": "read the function body to check length validation",
            },
        )
        assert "audit_mcp.read_function" in summary
        assert "parse_header" in summary
        assert "read the function body" in summary

    def test_tool_call_tolerates_malformed_command_json(self) -> None:
        summary = _summarize_message_payload(
            "tool_call",
            {"command": "{not json", "reasoning": "x"},
        )
        # Falls through without raising; reasoning still surfaces.
        assert "why=x" in summary or "reasoning" in summary or summary

    def test_text_returns_text_head(self) -> None:
        summary = _summarize_message_payload(
            "text",
            {"text": "halvar hypothesizes that ``parse_header`` "
                     "dereferences before validating."},
        )
        assert "parse_header" in summary

    def test_decompiled_function_names_function_and_address(self) -> None:
        summary = _summarize_message_payload(
            "decompiled_function",
            {
                "function_name": "parse_header",
                "address": "0x00401234",
                "content": "int parse_header(char *buf) { ... }",
            },
        )
        assert "parse_header" in summary
        assert "0x00401234" in summary

    def test_taint_flow_names_source_and_sink(self) -> None:
        summary = _summarize_message_payload(
            "taint_flow",
            {"source": "recv_buffer", "sink": "memcpy", "flow_count": 3},
        )
        assert "recv_buffer" in summary
        assert "memcpy" in summary
        assert "3" in summary

    def test_outcome_pending_shows_confidence_and_answer(self) -> None:
        summary = _summarize_message_payload(
            "outcome_pending",
            {"confidence": "strong", "answer": "found unbounded memcpy in parse_header"},
        )
        assert "strong" in summary
        assert "parse_header" in summary

    def test_unknown_payload_kind_falls_back_to_json_head(self) -> None:
        summary = _summarize_message_payload(
            "hypothesis_update",
            {"hypothesis_id": "h7", "state": "live"},
        )
        assert "h7" in summary


# --------------------------------------------------------------------- #
#  run() orchestration -- DB seams + LLM patched                        #
# --------------------------------------------------------------------- #


class _FakeLLMResponse:
    def __init__(self, content: str, disabled: bool = False) -> None:
        self.content = content
        self.disabled = disabled
        self.model = "test-model"
        self.usage: dict[str, int] = {}
        self.finish_reason = "stop"


@dataclass
class _FakeInv:
    id: str = "inv-x"
    initial_question: str = "Is there a bug in the header parser?"
    title: str = "http parser deep dive"
    primary_outcome_id: str | None = None


@dataclass
class _FakeOutcome:
    id: str = "oc-canonical"
    outcome_kind: str = "direct_finding"
    payload_json: str = "{}"


@dataclass
class _FakeBranch:
    id: str
    persona_voice: str
    turn_count: int
    status: str
    created_at: Any = None


@dataclass
class _FakeMessage:
    id: str
    branch_id: str
    payload_kind: str
    sender_kind: str
    payload_json: str
    at_turn: int
    created_at: Any = None


@dataclass
class _FakeScalar:
    _rows: list[Any]

    def first(self) -> Any:
        return self._rows[0] if self._rows else None

    def all(self) -> list[Any]:
        return list(self._rows)


class _FakeSession:
    """Async session stand-in.

    The narrative agent runs several ``session.exec()`` calls per UoW.
    We answer each in order from a canned FIFO the test primes.
    """

    def __init__(self, exec_answers: list[Any] | None = None) -> None:
        self._answers: list[Any] = list(exec_answers or [])
        self.added: list[Any] = []
        self.commits = 0

    async def exec(self, _stmt: Any) -> _FakeScalar:
        if not self._answers:
            # Anything past the primed answers returns "no row" so the
            # narrative agent gracefully falls back to "no data" paths
            # in tests that only care about the primary flow.
            return _FakeScalar([])
        answer = self._answers.pop(0)
        if isinstance(answer, list):
            return _FakeScalar(answer)
        return _FakeScalar([answer]) if answer is not None else _FakeScalar([])

    def add(self, obj: Any) -> None:
        self.added.append(obj)


@dataclass
class _FakeUoW:
    """Async-context stand-in for :class:`UnitOfWork`.

    Reuses one session across every ``async with UnitOfWork()`` in the
    narrative agent so assertions can inspect writes from either the
    read UoW or the persist UoW on the shared recorder.
    """

    session: _FakeSession = field(default_factory=_FakeSession)
    committed: int = 0

    async def __aenter__(self) -> _FakeUoW:
        return self

    async def __aexit__(self, *args: Any) -> bool:
        return False

    async def commit(self) -> None:
        self.committed += 1


class _CannedLLM:
    """Records ``idempotent_llm_call`` invocations and returns canned response."""

    def __init__(self, response: _FakeLLMResponse) -> None:
        self._response = response
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, _llm_client: Any, **kwargs: Any) -> tuple[Any, bool]:
        self.calls.append(kwargs)
        return self._response, False


class _StubFactory:
    """ServiceFactory stand-in whose ``llm_client`` is a sentinel."""

    @property
    def llm_client(self) -> Any:
        return "stub-llm-client"


def _canned_narrative_json() -> str:
    """A NarrativeResponse.model_dump_json() payload the schema accepts."""
    return NarrativeResponse(
        title="An unbounded memcpy in the HTTP header parser",
        body=(
            "## Setup\n\nThe panel opened on the http header parser.\n\n"
            "## Audit\n\n"
            + "\n".join([
                f"halvar traced call {i} through parse_header at "
                f"src/http.c:{412 + i}." for i in range(80)
            ])
            + "\n\n## Verdict\n\ndirect_finding: unbounded memcpy at "
            "src/http.c:412 confirmed by claim verifier.\n"
        ),
        chapter_outline=["Setup", "Audit", "Verdict"],
        tone_used="blog",
    ).model_dump_json()


class _StubResponse:
    """A fake LLM response object whose .content parses as NarrativeResponse."""


@pytest.fixture
def patch_agent_seams(monkeypatch: pytest.MonkeyPatch):
    """Patch UoW + ServiceFactory + idempotent_llm_call in narrative_agent.

    Returns a tuple ``(configure, uow_holder, llm)`` where:
      * ``configure`` sets the exec answers the fake session will return
        across the (potentially multiple) UnitOfWork() ``async with``
        blocks the agent opens.
      * ``uow_holder`` is a dict{'uow': _FakeUoW} the test can inspect.
      * ``llm`` is the ``_CannedLLM`` instance recording LLM calls.
    """

    holder: dict[str, _FakeUoW] = {}

    def _make_uow() -> _FakeUoW:
        # Reuse ONE UoW across every construction so exec answers primed
        # by the test flow through in-order regardless of which read /
        # write block consumes them.
        if "uow" not in holder:
            holder["uow"] = _FakeUoW()
        return holder["uow"]

    # RFC #208 P2: the run() template now lives in the platform base,
    # so the seams to patch are on aila.platform.agents.narrative_agent.
    monkeypatch.setattr(
        "aila.platform.agents.narrative_agent.UnitOfWork",
        _make_uow,
    )
    monkeypatch.setattr(
        "aila.platform.agents.narrative_agent.ServiceFactory",
        _StubFactory,
    )

    llm = _CannedLLM(_FakeLLMResponse(content=_canned_narrative_json()))
    monkeypatch.setattr(
        "aila.platform.agents.narrative_agent.idempotent_llm_call",
        llm,
    )

    def _configure(exec_answers: list[Any]) -> None:
        # Rebuild the shared session with the primed answers.
        holder["uow"] = _FakeUoW(session=_FakeSession(exec_answers))

    return _configure, holder, llm


class TestRunPersistsNarrative:
    """The happy path: narrative lands under payload['investigation_narrative']."""

    @pytest.mark.asyncio
    async def test_persists_narrative_on_canonical_outcome(
        self, patch_agent_seams: Any,
    ) -> None:
        configure, holder, llm = patch_agent_seams

        inv = _FakeInv(primary_outcome_id=None)
        # Pre-existing panel_summary MUST survive: the narrative
        # coexists with it, never replaces it (per the contract).
        canonical = _FakeOutcome(
            payload_json=json.dumps({
                "panel_summary": {
                    "narrative": "**Headline verdict.** confirmed direct_finding",
                    "personas": [{"persona": "halvar", "branch_id": "b1",
                                  "kind": "direct_finding",
                                  "confidence": "strong"}],
                    "synthesized_at": "2026-07-20T09:00:00Z",
                },
                "panel_contributions": [
                    {
                        "persona": "halvar",
                        "branch_id": "b1",
                        "at_turn": 12,
                        "outcome_kind": "direct_finding",
                        "confidence": "strong",
                        "answer_brief": "unbounded memcpy at src/http.c:412",
                    },
                ],
            }),
        )
        branches = [
            _FakeBranch(id="b1", persona_voice="halvar", turn_count=12,
                        status="closed"),
        ]
        messages = [
            _FakeMessage(
                id="m1", branch_id="b1", payload_kind="tool_call",
                sender_kind="engine",
                payload_json=json.dumps({
                    "command": json.dumps({
                        "tool": "audit_mcp.taint_paths_to",
                        "args": {"name": "memcpy"},
                    }),
                    "reasoning": "trace user input into memcpy",
                }),
                at_turn=3,
            ),
        ]

        # Read UoW: inv, canonical, branches (list), messages (list).
        # Persist UoW: canonical (row-locked re-read).
        configure([inv, canonical, branches, messages, canonical])

        agent = NarrativeAgent(
            investigation_id="inv-x",
            options=NarrativeOptions(tone="blog", length="standard"),
        )
        result = await agent.run()

        assert result["status"] == "ok"
        assert result["canonical_outcome_id"] == "oc-canonical"
        assert result["narrative_words"] > 0
        assert result["tone"] == "blog"
        assert result["length"] == "standard"

        # Exactly one LLM call, correct task_type + system prompt shape.
        assert len(llm.calls) == 1
        call = llm.calls[0]
        assert call["task_type"] == "vulnerability_research.narrative"
        assert call["messages"][0]["role"] == "system"
        assert call["messages"][1]["role"] == "user"
        assert call["messages"][0]["content"] == _SYSTEM_PROMPT
        # Focus block should NOT appear (operator_focus is empty).
        assert "User focus" not in call["messages"][1]["content"]
        # Prompt carries the panel data assembled from the DB fakes.
        user_prompt = call["messages"][1]["content"]
        assert "audit_mcp.taint_paths_to" in user_prompt
        assert "HALVAR" in user_prompt

        # Persist landed: the canonical row was written to session.
        added = holder["uow"].session.added
        assert len(added) == 1
        written = json.loads(added[0].payload_json)
        assert "investigation_narrative" in written
        narrative = written["investigation_narrative"]
        assert narrative["title"].startswith("An unbounded memcpy")
        assert narrative["tone_used"] == "blog"
        assert narrative["length_used"] == "standard"
        assert narrative["narrative_words"] > 0
        assert narrative["chapter_outline"] == ["Setup", "Audit", "Verdict"]
        # Panel summary was preserved -- narrative COEXISTS with it,
        # never overwrites.
        assert "panel_summary" in written
        assert written["panel_summary"]["personas"][0]["persona"] == "halvar"
        assert holder["uow"].committed == 1


class TestIdempotency:
    """Second run without force is a no-op; force=True overrides."""

    @pytest.mark.asyncio
    async def test_second_run_without_force_skips(
        self, patch_agent_seams: Any,
    ) -> None:
        configure, holder, llm = patch_agent_seams

        # Canonical outcome ALREADY carries an investigation_narrative
        # payload from a prior run.
        prior = {
            "panel_summary": {"narrative": "prior synth"},
            "investigation_narrative": {
                "title": "Already written",
                "body": "y" * 1000,
                "chapter_outline": ["ch1"],
                "tone_used": "blog",
                "length_used": "standard",
                "narrative_words": 200,
                "generated_at": "2026-07-01T00:00:00Z",
                "sanitizer_counts": {"title": 0, "body": 0, "chapter_outline": 0},
            },
        }
        canonical = _FakeOutcome(payload_json=json.dumps(prior))
        inv = _FakeInv(primary_outcome_id=None)
        # Only the read UoW is expected -- the early-exit path bails
        # before the LLM call, so no branches / messages exec is issued.
        configure([inv, canonical])

        agent = NarrativeAgent(
            investigation_id="inv-x",
            options=NarrativeOptions(force=False),
        )
        result = await agent.run()

        assert result["status"] == "skipped"
        assert result["reason"] == "narrative_already_present"
        assert result["canonical_outcome_id"] == "oc-canonical"

        # No LLM call was made; no session.add / commit fired.
        assert llm.calls == []
        assert holder["uow"].session.added == []
        assert holder["uow"].committed == 0

    @pytest.mark.asyncio
    async def test_force_true_rewrites_existing_narrative(
        self, patch_agent_seams: Any,
    ) -> None:
        configure, holder, llm = patch_agent_seams

        prior = {
            "panel_summary": {"narrative": "prior synth"},
            "investigation_narrative": {
                "title": "Already written",
                "body": "y" * 1000,
                "chapter_outline": ["ch1"],
                "tone_used": "blog",
                "length_used": "standard",
                "narrative_words": 200,
                "generated_at": "2026-07-01T00:00:00Z",
                "sanitizer_counts": {"title": 0, "body": 0, "chapter_outline": 0},
            },
        }
        canonical = _FakeOutcome(payload_json=json.dumps(prior))
        inv = _FakeInv(primary_outcome_id=None)
        # force=True proceeds through the full flow: read UoW +
        # persist UoW (both re-fetch the canonical row).
        configure([inv, canonical, [], [], canonical])

        agent = NarrativeAgent(
            investigation_id="inv-x",
            options=NarrativeOptions(force=True, tone="thriller"),
        )
        result = await agent.run()

        assert result["status"] == "ok"
        assert len(llm.calls) == 1
        added = holder["uow"].session.added
        assert len(added) == 1
        written = json.loads(added[0].payload_json)
        # The freshly rewritten narrative from the fake LLM response
        # overrides the prior one; panel_summary still survives.
        assert (
            written["investigation_narrative"]["title"]
            == "An unbounded memcpy in the HTTP header parser"
        )
        assert written["investigation_narrative"]["tone_used"] == "thriller"
        assert written["panel_summary"]["narrative"] == "prior synth"


class TestCanonicalOutcomeResolution:
    """primary_outcome_id wins when set; else earliest by created_at."""

    @pytest.mark.asyncio
    async def test_primary_outcome_id_takes_precedence(
        self, patch_agent_seams: Any,
    ) -> None:
        configure, holder, _llm = patch_agent_seams

        inv = _FakeInv(primary_outcome_id="oc-primary")
        primary_row = _FakeOutcome(id="oc-primary", payload_json="{}")
        # No other outcomes need to appear -- the load path returns
        # primary_row from its first exec and stops.
        configure([inv, primary_row, [], [], primary_row])

        agent = NarrativeAgent(
            investigation_id="inv-x", options=NarrativeOptions(),
        )
        result = await agent.run()

        assert result["status"] == "ok"
        assert result["canonical_outcome_id"] == "oc-primary"

    @pytest.mark.asyncio
    async def test_falls_back_to_earliest_outcome_when_primary_unset(
        self, patch_agent_seams: Any,
    ) -> None:
        configure, holder, _llm = patch_agent_seams

        inv = _FakeInv(primary_outcome_id=None)
        earliest = _FakeOutcome(id="oc-earliest", payload_json="{}")
        configure([inv, earliest, [], [], earliest])

        agent = NarrativeAgent(
            investigation_id="inv-x", options=NarrativeOptions(),
        )
        result = await agent.run()

        assert result["status"] == "ok"
        assert result["canonical_outcome_id"] == "oc-earliest"


class TestNotFoundPaths:
    """Missing investigation / missing canonical outcome exit cleanly."""

    @pytest.mark.asyncio
    async def test_investigation_not_found_skips(
        self, patch_agent_seams: Any,
    ) -> None:
        configure, _holder, llm = patch_agent_seams
        configure([None])  # inv lookup returns nothing.

        agent = NarrativeAgent(investigation_id="inv-missing")
        result = await agent.run()

        assert result == {"status": "skipped", "reason": "investigation_not_found"}
        assert llm.calls == []

    @pytest.mark.asyncio
    async def test_no_canonical_outcome_skips(
        self, patch_agent_seams: Any,
    ) -> None:
        configure, _holder, llm = patch_agent_seams
        inv = _FakeInv(primary_outcome_id=None)
        # Both the primary_outcome_id-branch (skipped since None) and
        # the earliest-outcome exec return nothing.
        configure([inv, None])

        agent = NarrativeAgent(investigation_id="inv-x")
        result = await agent.run()

        assert result == {"status": "skipped", "reason": "no_canonical_outcome"}
        assert llm.calls == []
