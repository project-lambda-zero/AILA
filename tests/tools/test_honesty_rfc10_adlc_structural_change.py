"""RFC-10 rule 75 (adlc_structural_change) honesty guardrail.

Rule 75 is the RFC-10 fourth ADLC guardrail (design doc
``.run/designs/DESIGN_reasoning_platform.md`` sec 3.7 -- a bundle body
whose diff adds a new tool call, a new node kind, or a new graph edge
is a finding). The RFC-10 Agent Development Lifecycle control plane
under ``platform/lifecycle/**`` promotes versioned agent bundles
behind the eval + quorum gate: it flips an alias, writes a
:class:`LifecycleTransitionRecord`, and stamps a
:class:`LifecycleCanaryAssignment` state. It must NOT mint new graph
structure (a phase, node kind, edge, or persona-roster entry) and
must NOT register a new tool; those go through the code lifecycle
(a PR, a review, a deploy), not through the ADLC bundle promotion
path.

The rule reuses rule 73's four structural AST shapes
(:data:`_STRUCTURAL_GRAPH_CALLABLES` / :data:`_STRUCTURAL_MAP_ATTRS` /
:data:`_STRUCTURAL_MUTATOR_METHODS` / :data:`_STRUCTURAL_ROSTER_TOKENS`)
but rescopes them to ``platform/lifecycle/**``. Additionally, it flags
tool registration entering via the lifecycle path:
``.register_tool(...)`` on any receiver, ``.register(...)`` on a
tool-registry-shaped receiver (``tool_registry`` / ``tool_scope``),
and constructing a ``Tool`` subclass (callee terminal ending in
``Tool``).

Sibling of rule 73 (structural_self_modification) which locks the
RFC-08 self-improvement layer; rule 75 locks the RFC-10 ADLC control
plane. Precision over recall: the live lifecycle controller
legitimately flips aliases, writes assignment rows, and journals
transition records -- none of those hit the rule's four shapes, so
rule 75 fires zero on the current tree.
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


_RULE = "adlc_structural_change"


# ---------------------------------------------------------------------------
# POSITIVE (rule fires)
# ---------------------------------------------------------------------------


class TestAdlcStructuralChangeFires:
    """A structural graph edit or tool registration inside
    ``platform/lifecycle/**`` fires."""

    def test_phase_spec_construction_fires(self, tmp_path: Path) -> None:
        """A ``PhaseSpec(...)`` call inside the ADLC control plane fires
        (shape 1: structural graph constructor / factory)."""
        src = _write(
            tmp_path,
            "aila/platform/lifecycle/rogue_phase.py",
            "def install_new_phase():\n"
            "    return PhaseSpec(name='canary_hold', on_enter=None)\n",
        )
        assert _RULE in _audit(src)

    def test_states_subscript_write_fires(self, tmp_path: Path) -> None:
        """A ``workflow.states[<key>] = ...`` subscript write inside the
        ADLC control plane fires (shape 2: structural map subscript)."""
        src = _write(
            tmp_path,
            "aila/platform/lifecycle/rogue_states.py",
            "def bolt_on_state(workflow):\n"
            "    workflow.states['canary_hold'] = None\n",
        )
        assert _RULE in _audit(src)

    def test_nodes_mutator_call_fires(self, tmp_path: Path) -> None:
        """A ``.nodes.update({...})`` mutator call inside the ADLC
        control plane fires (shape 3: mutator on a structural map)."""
        src = _write(
            tmp_path,
            "aila/platform/lifecycle/rogue_nodes.py",
            "def rewrite_nodes(definition):\n"
            "    definition.nodes.update({'ghost': object()})\n",
        )
        assert _RULE in _audit(src)

    def test_persona_roster_subscript_write_fires(
        self, tmp_path: Path,
    ) -> None:
        """A ``PERSONA_ROLE_MAP[x] = y`` subscript write inside the ADLC
        control plane fires (shape 4: persona-roster binding write)."""
        src = _write(
            tmp_path,
            "aila/platform/lifecycle/rogue_roster.py",
            "PERSONA_ROLE_MAP = {}\n"
            "\n"
            "def install_persona():\n"
            "    PERSONA_ROLE_MAP['bundle_reviewer'] = None\n",
        )
        assert _RULE in _audit(src)

    def test_register_tool_call_fires(self, tmp_path: Path) -> None:
        """A ``.register_tool(...)`` call inside the ADLC control plane
        fires (tool registration -- new tools go through the code
        lifecycle, not through a bundle promotion)."""
        src = _write(
            tmp_path,
            "aila/platform/lifecycle/rogue_tool.py",
            "def install_tool(registry, tool):\n"
            "    return registry.register_tool('new.key', tool)\n",
        )
        assert _RULE in _audit(src)

    def test_tool_registry_register_call_fires(
        self, tmp_path: Path,
    ) -> None:
        """A ``tool_registry.register(...)`` call inside the ADLC control
        plane fires. The receiver's terminal name contains the token
        ``tool_registry`` so the platform's canonical registration
        entry point is caught even though the method name is the bare
        ``register``."""
        src = _write(
            tmp_path,
            "aila/platform/lifecycle/rogue_registry.py",
            "def bolt_on_tool(tool_registry, key, tool):\n"
            "    tool_registry.register(key, tool)\n",
        )
        assert _RULE in _audit(src)

    def test_tool_subclass_construction_fires(
        self, tmp_path: Path,
    ) -> None:
        """A ``PermanentMemoryTool(...)`` (or any ``XxxTool(...)``)
        construction inside the ADLC control plane fires. Callee
        terminals ending in ``Tool`` are the platform's naming
        convention for Tool subclasses."""
        src = _write(
            tmp_path,
            "aila/platform/lifecycle/rogue_ctor.py",
            "def install_tool(settings):\n"
            "    return PermanentMemoryTool(settings)\n",
        )
        assert _RULE in _audit(src)


# ---------------------------------------------------------------------------
# NEGATIVE (rule does NOT fire)
# ---------------------------------------------------------------------------


class TestAdlcStructuralChangeExempt:
    """Sanctioned lifecycle-controller shapes and out-of-scope files
    must NOT fire. Precision over recall: the live lifecycle
    controller does exactly these things (alias flip, journal write,
    assignment read) and must stay silent."""

    def test_alias_flip_and_journal_write_do_not_fire(
        self, tmp_path: Path,
    ) -> None:
        """The canonical ADLC promotion path: flip a production alias
        via the store, journal a :class:`LifecycleTransitionRecord`,
        and stamp an assignment row. None of these are structural
        graph edits or tool registrations, so rule 75 must stay
        silent."""
        src = _write(
            tmp_path,
            "aila/platform/lifecycle/controller_like.py",
            "def promote(key, version, actor):\n"
            "    store.set_alias(key, 'production', version, actor=actor)\n"
            "    record = LifecycleTransitionRecord(\n"
            "        key=key, from_stage=None, to_stage=LifecycleStage.PRODUCTION,\n"
            "        actor=actor, reason='eval+quorum',\n"
            "    )\n"
            "    session.add(record)\n"
            "    return record\n",
        )
        assert _RULE not in _audit(src)

    def test_reading_assignment_rows_does_not_fire(
        self, tmp_path: Path,
    ) -> None:
        """Reading :class:`LifecycleCanaryAssignment` rows via the ORM\n        is a plain query, not a structural edit. It must not fire."""
        src = _write(
            tmp_path,
            "aila/platform/lifecycle/reader_like.py",
            "def load_active_canary(session, key):\n"
            "    stmt = select(LifecycleCanaryAssignment).where(\n"
            "        LifecycleCanaryAssignment.key == key,\n"
            "        LifecycleCanaryAssignment.state == AssignmentState.ACTIVE,\n"
            "    )\n"
            "    return session.exec(stmt).first()\n",
        )
        assert _RULE not in _audit(src)

    def test_workflows_engine_building_graph_out_of_scope(
        self, tmp_path: Path,
    ) -> None:
        """A ``platform/workflows/**`` engine file legitimately builds
        the graph (constructs :class:`PhaseSpec` / :class:`WorkflowDefinition`,
        subscripts ``.states[x]``). It is OUT of rule 75's scope
        (``platform/lifecycle/**``) and must not fire."""
        src = _write(
            tmp_path,
            "aila/platform/workflows/engine.py",
            "def build_workflow():\n"
            "    workflow = WorkflowDefinition(name='vr')\n"
            "    workflow.states['triage'] = PhaseSpec(name='triage')\n"
            "    return workflow\n",
        )
        assert _RULE not in _audit(src)

    def test_platform_eval_out_of_scope(self, tmp_path: Path) -> None:
        """A ``platform/eval/**`` file is rule 73's scope, not 75. Rule
        75 must not fire on it (rule 73 will handle it separately)."""
        src = _write(
            tmp_path,
            "aila/platform/eval/proposer.py",
            "def propose_phase():\n"
            "    return PhaseSpec(name='shadow')\n",
        )
        assert _RULE not in _audit(src)

    def test_lifecycle_data_snapshot_dict_write_does_not_fire(
        self, tmp_path: Path,
    ) -> None:
        """A local ``snapshot[key] = value`` write on a plain dict is\n        NOT a structural map / roster subscript (the receiver's\n        terminal is ``snapshot``, which is not in the roster token set,\n        and it is a Name -- not an Attribute with .states / .nodes /\n        .edges). This mirrors the live controller pattern in\n        ``platform/lifecycle/controller.py`` (record_canary_signal\n        writes ``snapshot['signal_count'] = new_count`` on every\n        drift/cost breach) and MUST NOT fire."""
        src = _write(
            tmp_path,
            "aila/platform/lifecycle/snapshot_writer_like.py",
            "def build_snapshot(signal, count):\n"
            "    snapshot = signal.as_snapshot()\n"
            "    snapshot['signal_count'] = count\n"
            "    return snapshot\n",
        )
        assert _RULE not in _audit(src)
