"""RFC-driven honesty-audit guardrails.

Tests for the guardrails that lock in RFC-03's platform-agent-runtime
closures. Two rules:

- Rule 42 (agent_primitive_reimplementation), extended in RFC-03 Phase 7
  from the two Phase-1 primitives (``classify_intent``,
  ``maybe_post_auto_steering``) to also cover the turn-runner lift:
  ``run_turn``, ``decode_case_state``, ``encode_case_state``,
  ``auto_resolve_live_on_terminal``, ``to_outcome_confidence``. The check
  now walks class-body method defs too so a subclass that overrides
  ``run_turn`` on an ``AgentTurnRunnerBase`` subclass fires.

- Rule 49 (agent_env_read), the config-drift closure guard. Modules under
  ``aila/modules/*/agents/**`` must resolve config through
  ``ConfigRegistry`` and never touch ``os.environ`` / ``os.getenv``
  directly.

Each rule has positive tests (a synthetic violation fires) and negative
tests (thin subclasses, out-of-scope files, and import re-exports stay
clean). A final gate test runs the full audit on ``src/aila`` and
asserts exit 0 with zero findings, matching the CI contract.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from aila.tools.honesty_audit import HonestyAuditor, load_whitelist

# ---------------------------------------------------------------------------
# Helpers (kept local so this file can move without touching siblings).
# ---------------------------------------------------------------------------


def _write(base: Path, rel: str, source: str) -> Path:
    """Write *source* to *base/rel*, creating parent directories as needed."""
    path = base / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


def _audit(path: Path) -> list[str]:
    """Return the rule names of findings emitted for *path*."""
    return [f.rule for f in HonestyAuditor().audit_file(path)]


# ---------------------------------------------------------------------------
# Rule 42 -- agent_primitive_reimplementation (RFC-03 Phase 7 extension)
# ---------------------------------------------------------------------------


class TestAgentPrimitiveReimplementationTurnRunner:
    """Rule 42 extension: turn-runner + turn-helpers lifts fire the same rule.

    Phase 1 already covered ``classify_intent`` and
    ``maybe_post_auto_steering``; Phase 7 adds ``run_turn`` and the four
    ``turn_helpers`` primitives, and the check now walks class-body method
    defs so a subclass override on ``AgentTurnRunnerBase`` is caught too.
    """

    def test_top_level_run_turn_flagged(self, tmp_path: Path) -> None:
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/vuln_researcher.py",
            "async def run_turn(investigation_id, branch_id):\n"
            "    return None\n",
        )
        assert "agent_primitive_reimplementation" in _audit(src)

    def test_class_body_run_turn_flagged(self, tmp_path: Path) -> None:
        """A subclass override of the platform ``run_turn`` fires the rule."""
        src = _write(
            tmp_path,
            "aila/modules/malware/agents/malware_researcher.py",
            "class MalwareRunner(AgentTurnRunnerBase):\n"
            "    async def run_turn(self, investigation_id, branch_id):\n"
            "        return 42\n",
        )
        assert "agent_primitive_reimplementation" in _audit(src)

    def test_top_level_decode_case_state_flagged(self, tmp_path: Path) -> None:
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/turn_helpers.py",
            "def decode_case_state(raw):\n"
            "    return {}\n",
        )
        assert "agent_primitive_reimplementation" in _audit(src)

    def test_class_body_encode_case_state_flagged(self, tmp_path: Path) -> None:
        src = _write(
            tmp_path,
            "aila/modules/malware/agents/codec.py",
            "class Codec:\n"
            "    def encode_case_state(self, state):\n"
            "        return '{}'\n",
        )
        assert "agent_primitive_reimplementation" in _audit(src)

    def test_top_level_auto_resolve_flagged(self, tmp_path: Path) -> None:
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/terminal_resolver.py",
            "def auto_resolve_live_on_terminal(state, turn, outcome_kind):\n"
            "    del state, turn, outcome_kind\n"
            "    return None\n",
        )
        assert "agent_primitive_reimplementation" in _audit(src)

    def test_top_level_to_outcome_confidence_flagged(
        self, tmp_path: Path,
    ) -> None:
        src = _write(
            tmp_path,
            "aila/modules/malware/agents/confidence.py",
            "def to_outcome_confidence(raw):\n"
            "    return raw\n",
        )
        assert "agent_primitive_reimplementation" in _audit(src)

    def test_thin_subclass_not_flagged(self, tmp_path: Path) -> None:
        """A subclass that inherits without overriding stays clean.

        The whole point of Phase 7 wiring is a module writes
        ``class VrRunner(AgentTurnRunnerBase): pass`` and the platform
        method flows through. Nothing to redefine, nothing to flag.
        """
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/wiring.py",
            "class VrRunner(AgentTurnRunnerBase):\n"
            "    pass\n",
        )
        assert "agent_primitive_reimplementation" not in _audit(src)

    def test_import_reexport_not_flagged(self, tmp_path: Path) -> None:
        """Import re-exports of the lifted names stay silent."""
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/__init__.py",
            "from aila.platform.agents.turn_helpers import (\n"
            "    decode_case_state,\n"
            "    encode_case_state,\n"
            "    auto_resolve_live_on_terminal,\n"
            "    to_outcome_confidence,\n"
            ")\n"
            "__all__ = [\n"
            "    'decode_case_state',\n"
            "    'encode_case_state',\n"
            "    'auto_resolve_live_on_terminal',\n"
            "    'to_outcome_confidence',\n"
            "]\n",
        )
        assert "agent_primitive_reimplementation" not in _audit(src)

    def test_platform_definition_not_flagged(self, tmp_path: Path) -> None:
        """The platform's own definition of the lifted primitives is fine."""
        src = _write(
            tmp_path,
            "aila/platform/agents/turn_helpers.py",
            "def decode_case_state(raw):\n"
            "    return {}\n"
            "def encode_case_state(state):\n"
            "    return '{}'\n",
        )
        assert "agent_primitive_reimplementation" not in _audit(src)

    def test_underscore_run_turn_not_flagged(self, tmp_path: Path) -> None:
        """``_run_turn`` is a legitimate module-private helper name.

        The rule matches exact names; ``NdayResearcher._run_turn`` and
        ``HonestInvestigator._run_turn`` are private helpers, not the
        platform-owned ``run_turn`` method.
        """
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/nday_researcher.py",
            "class NdayResearcher:\n"
            "    async def _run_turn(self, turn, prior):\n"
            "        del turn, prior\n"
            "        return {}\n",
        )
        assert "agent_primitive_reimplementation" not in _audit(src)


# ---------------------------------------------------------------------------
# Rule 49 -- agent_env_read (RFC-03 config-drift closure)
# ---------------------------------------------------------------------------


class TestAgentEnvRead:
    """Rule 49: a module agents/ file must not read ``os.environ`` /
    ``os.getenv`` directly (RFC-03 config-drift closure)."""

    def test_os_environ_subscript_flagged(self, tmp_path: Path) -> None:
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/branch_manager.py",
            "import os\n"
            "def _cap():\n"
            "    return int(os.environ['VR_MAX_BRANCHES'])\n",
        )
        assert "agent_env_read" in _audit(src)

    def test_os_environ_get_flagged(self, tmp_path: Path) -> None:
        src = _write(
            tmp_path,
            "aila/modules/malware/agents/claim_verifier.py",
            "import os\n"
            "def _floor():\n"
            "    return os.environ.get('MW_AUTO_PROMOTE_FLOOR', '0.9')\n",
        )
        assert "agent_env_read" in _audit(src)

    def test_os_getenv_call_flagged(self, tmp_path: Path) -> None:
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/tool_executor.py",
            "import os\n"
            "def _limit():\n"
            "    return os.getenv('VR_HARD_BLOCK_LIMIT', '3')\n",
        )
        assert "agent_env_read" in _audit(src)

    def test_from_os_import_environ_flagged(self, tmp_path: Path) -> None:
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/persona_router.py",
            "from os import environ\n"
            "def _role():\n"
            "    return environ.get('VR_ROLE')\n",
        )
        assert "agent_env_read" in _audit(src)

    def test_from_os_import_getenv_flagged(self, tmp_path: Path) -> None:
        src = _write(
            tmp_path,
            "aila/modules/malware/agents/pattern_extractor.py",
            "from os import getenv\n"
            "def _limit():\n"
            "    return getenv('MW_PATTERN_LIMIT', '10')\n",
        )
        assert "agent_env_read" in _audit(src)

    def test_out_of_scope_module_file_not_flagged(
        self, tmp_path: Path,
    ) -> None:
        """A module file outside ``agents/`` is not scoped by rule 49.

        Rule 49 targets the RFC-03 agent-runtime lift specifically; other
        module paths (services, workflow, tasks) are governed by their
        own rules (e.g. ConfigRegistry adoption is a separate concern).
        """
        src = _write(
            tmp_path,
            "aila/modules/vr/services/config.py",
            "import os\n"
            "def f():\n"
            "    return os.environ.get('X')\n",
        )
        assert "agent_env_read" not in _audit(src)

    def test_platform_agent_file_not_flagged(self, tmp_path: Path) -> None:
        """A platform agents file is not a module agents file."""
        src = _write(
            tmp_path,
            "aila/platform/agents/branch_pool.py",
            "import os\n"
            "def _cap(module_id):\n"
            "    del module_id\n"
            "    return int(os.environ.get('BRANCH_CAP', '5'))\n",
        )
        assert "agent_env_read" not in _audit(src)

    def test_config_registry_call_not_flagged(self, tmp_path: Path) -> None:
        """The correct path -- ``ConfigRegistry(module_id, key)`` -- is silent."""
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/branch_manager.py",
            "async def _cap(registry):\n"
            "    return await registry.get('vr', 'max_branches')\n",
        )
        assert "agent_env_read" not in _audit(src)

    def test_string_literal_os_environ_not_flagged(
        self, tmp_path: Path,
    ) -> None:
        """``'os.environ'`` inside a docstring or blocklist tuple is a\n\n        string constant, not an ``os.environ`` attribute access. The rule\n        matches ``ast.Attribute`` nodes only, so a code-scanning module\n        that carries such names in a literal blocklist stays clean.\n        """
        src = _write(
            tmp_path,
            "aila/modules/vr/agents/investigator.py",
            "BLOCKLIST = ('os.environ', 'os.getenv', 'shutil.rmtree(')\n",
        )
        assert "agent_env_read" not in _audit(src)


# ---------------------------------------------------------------------------
# Gate -- full audit on the live tree must remain green.
# ---------------------------------------------------------------------------


def test_full_audit_exit_zero_and_clean() -> None:
    """The full CLI audit on ``src/aila`` must exit 0 with no findings.

    This mirrors the CI gate exactly: any new rule added here MUST leave
    the current tree unchanged (zero new findings), otherwise it would
    break every commit. The test walks up from this file to the project
    root, then invokes the auditor as a subprocess for full parity with
    the CI invocation.
    """
    repo_root = _find_repo_root(Path(__file__).resolve())
    target = repo_root / "src" / "aila"
    whitelist = repo_root / "honesty_whitelist.py"
    assert target.is_dir(), f"src/aila missing at {target}"
    assert whitelist.is_file(), f"honesty_whitelist.py missing at {whitelist}"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "aila.tools.honesty_audit",
            str(target),
            "--whitelist",
            str(whitelist),
        ],
        capture_output=True,
        text=True,
        cwd=str(repo_root),
        check=False,
    )
    # Exit 0 == clean; exit 1 == findings. The subprocess prints findings
    # to stdout; include them in the assertion so a regression names the
    # exact rules that fired.
    assert completed.returncode == 0, (
        f"honesty_audit exited {completed.returncode}\n"
        f"stdout:\n{completed.stdout}\n"
        f"stderr:\n{completed.stderr}"
    )


def _find_repo_root(start: Path) -> Path:
    """Walk up from *start* until a directory containing ``pyproject.toml``."""
    for candidate in (start, *start.parents):
        if (candidate / "pyproject.toml").is_file():
            return candidate
    raise RuntimeError(f"pyproject.toml not found above {start}")


# ---------------------------------------------------------------------------
# Whitelist-load smoke -- ensures the tests do not silently skip the gate.
# ---------------------------------------------------------------------------


def test_whitelist_loads() -> None:
    """A trivial safety check that ``honesty_whitelist.py`` parses.

    If the whitelist file were unparseable, the full-audit gate above
    would fail with a confusing message; this test catches that up front.
    """
    repo_root = _find_repo_root(Path(__file__).resolve())
    whitelist_path = repo_root / "honesty_whitelist.py"
    entries = load_whitelist(whitelist_path)
    # ``entries`` is a set of triples; presence of at least one is not
    # required (an empty whitelist is legal), but the load must succeed.
    assert isinstance(entries, set)
