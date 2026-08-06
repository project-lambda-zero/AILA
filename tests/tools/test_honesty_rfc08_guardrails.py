"""RFC-08 self-improvement honesty guardrails.

Covers the two RFC-08 gates locked in by ``honesty_audit``:

* **Rule 55 (ungated_self_improvement_write)** -- extended so a pattern
  store bound as ``self._store`` (the shape the sanctioned DRAFT
  proposers use) is recognised. The DRAFT proposer files
  ``platform/agents/pattern_extractor.py`` and
  ``modules/<mod>/services/pattern_proposer.py`` are exempted because
  they stamp ``trust_tier=UNREVIEWED`` on every row they write -- the
  retrieval path down-weights those rows to zero standalone influence
  until an operator / reviewer promotes them via
  :class:`ExperienceWriter`. Rule 55 continues to guard against a
  FOURTH unsanctioned write path (a service, an agent turn, a
  workflow state) that would bypass the review-gate closure.

* **Rule 73 (structural_self_modification)** -- the shape-level sibling
  of rules 55-57. The RFC-08 self-improvement layer moves parameters
  (thresholds / persona-selection / patterns / routing weights) within
  the operator-authored workflow graph; a structural graph edit from
  that layer (constructing ``PhaseSpec`` / ``WorkflowDefinition``,
  calling ``make_dispatch_router`` / ``build_dispatch_workflow``, a
  subscript / delete / mutator-method mutation of a ``.states`` /
  ``.nodes`` / ``.edges`` mapping, or a persona-roster mutation) mints
  a graph shape the operator did not sign off on. Scope is scoped to
  ``platform/eval/`` and the specific proposer files in
  ``platform/agents/`` so the workflow / engine layer is never
  flagged.

Each rule gets both positive tests (the offending shape fires) and
negative tests (a legitimate shape does not fire). The full-audit
gate lives in ``test_honesty_guardrails_rfc.py`` and does not need
duplicating here.
"""
from __future__ import annotations

from pathlib import Path

from aila.tools.honesty_audit import HonestyAuditor

# ---------------------------------------------------------------------------
# Helpers (kept local so this file can move without touching siblings).
# ---------------------------------------------------------------------------


def _write(base: Path, rel: str, source: str) -> Path:
    """Write *source* to *base/rel*, creating parent directories."""
    path = base / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


def _audit(path: Path) -> list[str]:
    """Return the rule names of findings emitted for *path*."""
    return [f.rule for f in HonestyAuditor().audit_file(path)]


# ---------------------------------------------------------------------------
# Rule 55 -- ungated_self_improvement_write (broadened receiver tokens)
# ---------------------------------------------------------------------------


class TestUngatedSelfImprovementWriteBroadened:
    """Rule 55: ``self._store.create(...)`` outside the sanctioned files.

    The broadening adds ``_store`` to the receiver tokens because
    ExperienceWriter, pattern_extractor, and pattern_proposer all bind
    the pattern store to ``self._store``. Rule 55 has to see through
    the shortened name so a fourth writer file cannot slip in under a
    bare ``self._store`` binding. ``store`` alone is matched only as a
    dotted attribute (``self.store``, ``obj.store``); a bare local
    ``store = PatternStore(...); store.create(...)`` is a common
    api_router / factory idiom and is intentionally NOT flagged.
    """

    # ---- POSITIVE ----------------------------------------------------

    def test_self_dot_underscore_store_create_flagged(
        self, tmp_path: Path,
    ) -> None:
        """A non-exempt file calling ``self._store.create(...)`` fires."""
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/rogue_writer.py",
            "class Rogue:\n"
            "    async def go(self, body, team_id):\n"
            "        return await self._store.create(body, team_id=team_id)\n",
        )
        assert "ungated_self_improvement_write" in _audit(src)

    def test_bare_underscore_store_create_flagged(
        self, tmp_path: Path,
    ) -> None:
        """A local ``_store = ...; _store.create(...)`` still fires."""
        src = _write(
            tmp_path,
            "aila/modules/malware/services/rogue_writer.py",
            "async def go(_store, body, team_id):\n"
            "    return await _store.create(body, team_id=team_id)\n",
        )
        assert "ungated_self_improvement_write" in _audit(src)

    def test_self_dot_store_create_flagged(self, tmp_path: Path) -> None:
        """``self.store.create(...)`` (attr-only ``store`` token) fires."""
        src = _write(
            tmp_path,
            "aila/modules/vr/services/rogue_writer.py",
            "class Rogue:\n"
            "    async def go(self, body, team_id):\n"
            "        return await self.store.create(body, team_id=team_id)\n",
        )
        assert "ungated_self_improvement_write" in _audit(src)

    def test_original_pattern_store_still_flagged(
        self, tmp_path: Path,
    ) -> None:
        """Regression: the pre-broadening ``self.pattern_store.create(...)``
        shape still fires (the broadening extends, does not replace)."""
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/rogue_writer.py",
            "class Rogue:\n"
            "    async def go(self, body, team_id):\n"
            "        return await self.pattern_store.create(\n"
            "            body, team_id=team_id,\n"
            "        )\n",
        )
        assert "ungated_self_improvement_write" in _audit(src)

    # ---- NEGATIVE (sanctioned exemptions) ----------------------------

    def test_pattern_extractor_exempt(self, tmp_path: Path) -> None:
        """``platform/agents/pattern_extractor.py`` is a sanctioned DRAFT
        proposer (writes ``trust_tier=UNREVIEWED``) and is exempt."""
        src = _write(
            tmp_path,
            "aila/platform/agents/pattern_extractor.py",
            "class Extractor:\n"
            "    async def go(self, body, team_id):\n"
            "        return await self._store.create(body, team_id=team_id)\n",
        )
        assert "ungated_self_improvement_write" not in _audit(src)

    def test_module_pattern_extractor_exempt(self, tmp_path: Path) -> None:
        """A module's ``agents/pattern_extractor.py`` matches the suffix
        exemption too (vr / malware / forensics / _template all use it)."""
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/pattern_extractor.py",
            "class Extractor:\n"
            "    async def go(self, body, team_id):\n"
            "        return await self._store.create(body, team_id=team_id)\n",
        )
        assert "ungated_self_improvement_write" not in _audit(src)

    def test_pattern_proposer_exempt(self, tmp_path: Path) -> None:
        """``modules/*/services/pattern_proposer.py`` is a sanctioned
        DRAFT proposer service and is exempt."""
        src = _write(
            tmp_path,
            "aila/modules/malware/services/pattern_proposer.py",
            "async def go(store, body, team_id):\n"
            "    return await store.create(body=body, team_id=team_id)\n",
        )
        assert "ungated_self_improvement_write" not in _audit(src)

    def test_experience_writer_exempt(self, tmp_path: Path) -> None:
        """The canonical review-gated writer stays exempt after the
        broadening (regression against the pre-existing exemption)."""
        src = _write(
            tmp_path,
            "aila/platform/eval/experience_writer.py",
            "class ExperienceWriter:\n"
            "    async def record(self, body, team_id):\n"
            "        return await self._store.create(body, team_id=team_id)\n",
        )
        assert "ungated_self_improvement_write" not in _audit(src)

    def test_pattern_store_file_exempt(self, tmp_path: Path) -> None:
        """The store implementation itself is exempt (its ``.create``
        cannot recurse through itself)."""
        src = _write(
            tmp_path,
            "aila/platform/services/pattern_store.py",
            "class PatternStore:\n"
            "    async def create(self, body, team_id):\n"
            "        return await self._store.create(body, team_id=team_id)\n",
        )
        assert "ungated_self_improvement_write" not in _audit(src)

    # ---- NEGATIVE (attr-only ``store`` guard) ------------------------

    def test_bare_local_store_not_flagged(self, tmp_path: Path) -> None:
        """A bare local ``store = PatternStore(...); store.create(...)`` in
        an api_router-style helper is NOT flagged.

        This is the common operator-manual entry idiom; treating a
        plain Name ``store`` as the receiver would fire on every
        legitimate operator-manual write path.
        """
        src = _write(
            tmp_path,
            "aila/modules/vr/api_router.py",
            "async def create_pattern(body, team_id):\n"
            "    store = PatternStore()\n"
            "    return await store.create(body, team_id=team_id)\n",
        )
        assert "ungated_self_improvement_write" not in _audit(src)

    def test_unrelated_kb_create_not_flagged(self, tmp_path: Path) -> None:
        """A bare ``.create(...)`` on an unrelated receiver stays silent."""
        src = _write(
            tmp_path,
            "aila/modules/vr/services/knowledge_helper.py",
            "async def go(kb, entry):\n"
            "    return await kb.create(entry)\n",
        )
        assert "ungated_self_improvement_write" not in _audit(src)


# ---------------------------------------------------------------------------
# Rule 73 -- structural_self_modification
# ---------------------------------------------------------------------------


class TestStructuralSelfModificationConstructors:
    """Rule 73 shape 1: a structural constructor / factory call from
    inside the self-improvement layer fires."""

    def test_phasespec_in_eval_flagged(self, tmp_path: Path) -> None:
        """``PhaseSpec(...)`` inside ``platform/eval/`` fires."""
        src = _write(
            tmp_path,
            "aila/platform/eval/rogue.py",
            "def build():\n"
            "    return PhaseSpec(name='p', strategy_family='x')\n",
        )
        assert "structural_self_modification" in _audit(src)

    def test_workflow_definition_in_eval_flagged(
        self, tmp_path: Path,
    ) -> None:
        """``WorkflowDefinition(...)`` inside ``platform/eval/`` fires."""
        src = _write(
            tmp_path,
            "aila/platform/eval/rogue.py",
            "def build():\n"
            "    return WorkflowDefinition(definition_id='x', states={})\n",
        )
        assert "structural_self_modification" in _audit(src)

    def test_make_dispatch_router_in_eval_flagged(
        self, tmp_path: Path,
    ) -> None:
        src = _write(
            tmp_path,
            "aila/platform/eval/rogue.py",
            "def build():\n"
            "    return make_dispatch_router(phases=())\n",
        )
        assert "structural_self_modification" in _audit(src)

    def test_build_dispatch_workflow_in_agent_proposer_flagged(
        self, tmp_path: Path,
    ) -> None:
        """A proposer file in ``platform/agents/calibrator.py`` also
        fires -- the agent-side scope covers the sanctioned proposer
        files by suffix."""
        src = _write(
            tmp_path,
            "aila/platform/agents/calibrator.py",
            "def build():\n"
            "    return build_dispatch_workflow('x', ())\n",
        )
        assert "structural_self_modification" in _audit(src)

    def test_dotted_phasespec_in_eval_flagged(self, tmp_path: Path) -> None:
        """A dotted ``phase_graph.PhaseSpec(...)`` also matches
        (terminal attribute name is checked, not the module prefix)."""
        src = _write(
            tmp_path,
            "aila/platform/eval/rogue.py",
            "def build():\n"
            "    return phase_graph.PhaseSpec(name='p')\n",
        )
        assert "structural_self_modification" in _audit(src)

    # ---- NEGATIVE ----------------------------------------------------

    def test_phasespec_in_workflows_not_flagged(self, tmp_path: Path) -> None:
        """The workflow / engine layer legitimately builds the graph;
        precision-over-recall keeps it out of scope."""
        src = _write(
            tmp_path,
            "aila/platform/workflows/phase_graph.py",
            "def build():\n"
            "    return PhaseSpec(name='p', strategy_family='x')\n",
        )
        assert "structural_self_modification" not in _audit(src)

    def test_phasespec_in_module_not_flagged(self, tmp_path: Path) -> None:
        """A random module file is out of scope."""
        src = _write(
            tmp_path,
            "aila/modules/vr/workflow/foo.py",
            "def build():\n"
            "    return PhaseSpec(name='p')\n",
        )
        assert "structural_self_modification" not in _audit(src)

    def test_non_scope_agent_file_not_flagged(self, tmp_path: Path) -> None:
        """A non-proposer file under ``platform/agents/`` (e.g.
        ``turn_runner.py``) is out of scope -- only the specific
        proposer files (pattern_extractor, persona_router, calibrator)
        match the agent side of the scope."""
        src = _write(
            tmp_path,
            "aila/platform/agents/turn_runner.py",
            "def build():\n"
            "    return PhaseSpec(name='p')\n",
        )
        assert "structural_self_modification" not in _audit(src)

    def test_phasespec_annotation_not_flagged(self, tmp_path: Path) -> None:
        """An annotation ``-> PhaseSpec`` is a Name, not a Call, and
        does not fire."""
        src = _write(
            tmp_path,
            "aila/platform/eval/rogue.py",
            "def build() -> PhaseSpec:\n"
            "    return None  # type: ignore[return-value]\n",
        )
        assert "structural_self_modification" not in _audit(src)


class TestStructuralSelfModificationMapMutations:
    """Rule 73 shapes 2 + 3: mutations of a ``.states`` / ``.nodes`` /
    ``.edges`` map from inside the self-improvement layer fire."""

    def test_states_subscript_write_in_eval_flagged(
        self, tmp_path: Path,
    ) -> None:
        src = _write(
            tmp_path,
            "aila/platform/eval/rogue.py",
            "def add(wf, key, node):\n"
            "    wf.states[key] = node\n",
        )
        assert "structural_self_modification" in _audit(src)

    def test_nodes_subscript_write_in_eval_flagged(
        self, tmp_path: Path,
    ) -> None:
        src = _write(
            tmp_path,
            "aila/platform/eval/rogue.py",
            "def add(wf, key, node):\n"
            "    wf.nodes[key] = node\n",
        )
        assert "structural_self_modification" in _audit(src)

    def test_edges_delete_in_agent_proposer_flagged(
        self, tmp_path: Path,
    ) -> None:
        src = _write(
            tmp_path,
            "aila/platform/agents/persona_router.py",
            "def drop(wf, key):\n"
            "    del wf.edges[key]\n",
        )
        assert "structural_self_modification" in _audit(src)

    def test_states_update_mutator_in_eval_flagged(
        self, tmp_path: Path,
    ) -> None:
        src = _write(
            tmp_path,
            "aila/platform/eval/rogue.py",
            "def widen(wf, extra):\n"
            "    wf.states.update(extra)\n",
        )
        assert "structural_self_modification" in _audit(src)

    def test_nodes_pop_mutator_in_eval_flagged(
        self, tmp_path: Path,
    ) -> None:
        src = _write(
            tmp_path,
            "aila/platform/eval/rogue.py",
            "def drop(wf, key):\n"
            "    wf.nodes.pop(key)\n",
        )
        assert "structural_self_modification" in _audit(src)

    # ---- NEGATIVE ----------------------------------------------------

    def test_states_read_in_eval_not_flagged(self, tmp_path: Path) -> None:
        """A pure read ``wf.states[key]`` (Load context) is not a write."""
        src = _write(
            tmp_path,
            "aila/platform/eval/rogue.py",
            "def lookup(wf, key):\n"
            "    return wf.states[key]\n",
        )
        assert "structural_self_modification" not in _audit(src)

    def test_states_get_in_eval_not_flagged(self, tmp_path: Path) -> None:
        """A read via ``.get`` is not a mutator method."""
        src = _write(
            tmp_path,
            "aila/platform/eval/rogue.py",
            "def lookup(wf, key):\n"
            "    return wf.states.get(key)\n",
        )
        assert "structural_self_modification" not in _audit(src)

    def test_states_mutation_in_workflows_not_flagged(
        self, tmp_path: Path,
    ) -> None:
        """The workflow layer's own ``.states`` mutations are out of
        scope for rule 73 (they may still fire rule 50 -- which is
        this rule's universal sibling -- but that is a separate
        rule tested elsewhere)."""
        src = _write(
            tmp_path,
            "aila/platform/workflows/phase_graph.py",
            "def add(wf, key, node):\n"
            "    wf.states[key] = node\n",
        )
        assert "structural_self_modification" not in _audit(src)


class TestStructuralSelfModificationRoster:
    """Rule 73 shape 4: persona-roster mutations from inside the self-
    improvement layer fire."""

    def test_persona_role_map_subscript_write_in_eval_flagged(
        self, tmp_path: Path,
    ) -> None:
        src = _write(
            tmp_path,
            "aila/platform/eval/rogue.py",
            "def rewire(voice, role):\n"
            "    PERSONA_ROLE_MAP[voice] = role\n",
        )
        assert "structural_self_modification" in _audit(src)

    def test_persona_task_type_update_in_persona_router_flagged(
        self, tmp_path: Path,
    ) -> None:
        """A live ``persona_task_type.update({...})`` inside the
        persona-router proposer file fires."""
        src = _write(
            tmp_path,
            "aila/platform/agents/persona_router.py",
            "def widen(extra):\n"
            "    persona_task_type.update(extra)\n",
        )
        assert "structural_self_modification" in _audit(src)

    def test_role_task_type_append_in_eval_flagged(
        self, tmp_path: Path,
    ) -> None:
        """Sequence-mutator ``.append(...)`` on a persona-roster
        binding fires (defensive against a future tuple/list roster)."""
        src = _write(
            tmp_path,
            "aila/platform/eval/rogue.py",
            "def append(entry):\n"
            "    role_task_type.append(entry)\n",
        )
        assert "structural_self_modification" in _audit(src)

    # ---- NEGATIVE ----------------------------------------------------

    def test_persona_role_map_read_not_flagged(self, tmp_path: Path) -> None:
        """A pure ``PERSONA_ROLE_MAP.get(voice)`` read is not a write."""
        src = _write(
            tmp_path,
            "aila/platform/agents/persona_router.py",
            "def lookup(voice):\n"
            "    return PERSONA_ROLE_MAP.get(voice)\n",
        )
        assert "structural_self_modification" not in _audit(src)

    def test_persona_task_type_class_body_bind_not_flagged(
        self, tmp_path: Path,
    ) -> None:
        """A subclass BODY that binds ``persona_task_type = {...}`` with
        a bare Name target is a legitimate ClassVar override; it is
        an :class:`ast.Assign` / :class:`ast.AnnAssign` with a plain
        Name target, NOT a Subscript, so rule 73 does not fire."""
        src = _write(
            tmp_path,
            "aila/platform/agents/persona_router.py",
            "class MyRouter:\n"
            "    persona_task_type = {'a': 'x'}\n"
            "    role_task_type = {}\n",
        )
        assert "structural_self_modification" not in _audit(src)

    def test_persona_role_map_module_binding_not_flagged(
        self, tmp_path: Path,
    ) -> None:
        """The canonical ``PERSONA_ROLE_MAP: dict[...] = {...}`` module
        binding in ``persona_router.py`` is a plain Name AnnAssign
        (not a Subscript write) and is legitimate."""
        src = _write(
            tmp_path,
            "aila/platform/agents/persona_router.py",
            "PERSONA_ROLE_MAP: dict[str, str] = {'a': 'x'}\n",
        )
        assert "structural_self_modification" not in _audit(src)

    def test_persona_task_type_read_in_eval_not_flagged(
        self, tmp_path: Path,
    ) -> None:
        """A pure ``cls.persona_task_type`` attribute read is not a
        mutation."""
        src = _write(
            tmp_path,
            "aila/platform/eval/rogue.py",
            "def lookup(cls):\n"
            "    return cls.persona_task_type\n",
        )
        assert "structural_self_modification" not in _audit(src)

    def test_persona_roster_mutation_in_module_not_flagged(
        self, tmp_path: Path,
    ) -> None:
        """A persona-roster mutation from a module file (out of scope)
        is not flagged by rule 73."""
        src = _write(
            tmp_path,
            "aila/modules/vr/services/rogue.py",
            "def rewire(voice, role):\n"
            "    PERSONA_ROLE_MAP[voice] = role\n",
        )
        assert "structural_self_modification" not in _audit(src)
