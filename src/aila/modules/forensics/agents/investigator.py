"""Honest free-flow forensic investigator.

Replaces the prior strategy-catalogue driven agent. There are no hardcoded
playbooks, keyword routers, or pre-written profile bodies that pretend to
be a neutral framework. The LLM is the strategist end-to-end and the
module enforces an explicit closed-loop protocol per step:

    parse contract -> build case model -> propose hypotheses ->
    pick one action by information gain -> execute -> normalise observables ->
    rescore hypotheses -> answer gate -> commit with provenance.

Every intermediate artefact (contract, hypotheses, observables, rejected
alternatives) is persisted in ``AgentStepRecord`` so the frontend and
the write-up generator can trace every commit.

Delegation policy:
- DB persistence goes through ``UnitOfWork`` -- the platform's primitive.
  The investigator only writes records that are its responsibility
  (``AgentStepRecord``, ``AnswerCandidateRecord``, and the final summary
  fields on ``InvestigationRunRecord``). Investigation status transitions
  (pending -> running -> completed/failed) are owned by the workflow
  engine (``_state_response_emit``) and the state handler's error path.
- Script execution goes through ``ScriptExecutorTool`` -- no hand-rolled
  write/exec/cleanup loop, no hand-rolled exit-code wrappers.
- Shell commands go through ``SSHService.run_command`` directly -- no
  private ``__AILA_EXIT__`` marker dance.
- LLM calls go through ``AilaLLMClient`` -- no per-module clients.
- Artefact queries go through the existing ``UnitOfWork`` pattern used by
  every other forensics service.
"""
from __future__ import annotations

import ast
import hashlib
import json
import logging
import time
from typing import Any

from aila.config import Settings
from aila.modules.forensics.config_schema import ForensicsConfigSchema
from aila.platform.agents.turn_helpers import auto_resolve_live_on_terminal
from aila.platform.config_base import ModuleConfigReader
from aila.platform.contracts.reasoning import (
    Hypothesis,
    ReasoningCaseState,
    ReasoningContract,
    ReasoningOperatorSteering,
    ReasoningPromptContext,
    RejectedHypothesis,
    ResolvedHypothesis,
)
from aila.platform.exceptions import AILAError
from aila.platform.llm.correlation import (
    correlation_scope,
    current_join_keys,
    current_prompt_version,
)
from aila.platform.prompts import LoadedPrompt, PromptNotFoundError, PromptRegistry
from aila.platform.prompts.pinning import resolve_pinned_prompt
from aila.platform.prompts.seeds import (
    FORENSICS_BASE_TEXT,
    FORENSICS_NETWORK_COMMENTARY_TEXT,
    FORENSICS_OS_HINT_LINUX_TEXT,
    FORENSICS_OS_HINT_WINDOWS_TEXT,
    FORENSICS_WRITEUP_TEXT,
)
from aila.platform.prompts.version_store import PromptVersionStore
from aila.platform.services.reasoning import CyberReasoningEngine
from aila.platform.services.reasoning_graphs import ReasoningGraphService
from aila.storage.registry import ConfigRegistry

__all__ = ["HonestInvestigator"]

_log = logging.getLogger(__name__)
_cfg = ModuleConfigReader("forensics")


async def _read_float_config(key: str) -> float:
    """Resolve a forensics float-typed config value via ConfigRegistry.

    Falls back to the ForensicsConfigSchema field default on registry
    read failure or non-numeric value so a transient DB blip never
    replaces a bounded timeout with 0 (which would fire instantly).
    """
    default = float(ForensicsConfigSchema.model_fields[key].default)
    try:
        raw = await ConfigRegistry().get("forensics", key)
    except (OSError, RuntimeError, AILAError) as exc:
        _log.warning("forensics.%s registry read failed (%s); using default %.2f", key, exc, default)
        return default
    if raw is None:
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        _log.warning("forensics.%s config value %r not coercible to float; using default %.2f", key, raw, default)
        return default


# ---------------------------------------------------------------------------
# System prompts -- OS-dispatched, but strategy-neutral. No CTF playbooks.
# ---------------------------------------------------------------------------

_PROMPT_REGISTRY = PromptRegistry(module="forensics", version_store=PromptVersionStore())
_PROMPT_VERSION_STORE = PromptVersionStore()


def _freeflow_analyzer_os(analyzer_os: str) -> str:
    """Normalize the analyzer OS the way :func:`_load_freeflow_prompt` does.

    ``"windows"`` selects the Windows hint; every other value (including
    ``"darwin"`` and empty string) falls back to Linux. Keeping this in one
    place ensures the version-store key and the baseline body agree on
    the effective OS variant so pin identity does not diverge from body.
    """
    return "windows" if analyzer_os == "windows" else "linux"


def _freeflow_prompt_key(analyzer_os: str) -> str:
    """Version-store key for the assembled forensics free-flow system prompt.

    Distinct per effective analyzer OS since the assembled body differs
    (base + Windows hint vs. base + Linux hint). Aligned
    with the vr / malware key convention: ``{module}/{role}/{variant}``.
    """
    return f"forensics/freeflow/{_freeflow_analyzer_os(analyzer_os)}"


def _load_freeflow_prompt(analyzer_os: str) -> str:
    """Return the base system prompt + the OS-specific hint concatenated.

    Preserves the pre-RFC-09 assembly behavior exactly: ``base + windows``
    for a Windows analyzer, ``base + linux`` otherwise.
    """
    base = FORENSICS_BASE_TEXT
    hint_leaf = _freeflow_analyzer_os(analyzer_os)
    hint = FORENSICS_OS_HINT_WINDOWS_TEXT if hint_leaf == "windows" else FORENSICS_OS_HINT_LINUX_TEXT
    return base + hint


async def _resolve_freeflow_prompt(
    analyzer_os: str, *, investigation_id: str | None,
) -> LoadedPrompt:
    """Resolve the assembled free-flow system prompt through the version store.

    Routes through :func:`resolve_pinned_prompt` so the first turn on an
    investigation pins the current production-alias version onto
    ``forensics_investigations.prompt_pins_json`` and every later turn
    on the SAME investigation resolves that exact version. That is the
    RFC-09 criterion 4 safety: a live production-alias flip never
    rewrites the prompt of an in-flight investigation.

    Falls back to :func:`_load_freeflow_prompt` (byte-identical file
    assembly) when the store has no body -- no production alias yet, a
    pin pointing at a missing version, or a store fault. The returned
    :class:`LoadedPrompt` carries ``version=None`` in the fallback path
    so the caller can distinguish a versioned resolve from a file one
    and stamp the correlation scope accordingly (RFC-09 criterion 2).
    """
    # Lazy import: db_models pulls SQLModel table registration -- keeping
    # it lazy avoids a circular import between the agents module and the
    # forensics db_models package on cold interpreter startup. PLC0415 is
    # already covered file-wide via ``pyproject.toml`` per-file-ignores.
    from aila.modules.forensics.db_models import InvestigationRunRecord

    key = _freeflow_prompt_key(analyzer_os)
    body, version = await resolve_pinned_prompt(
        investigation_id=investigation_id,
        key=key,
        investigation_model=InvestigationRunRecord,
        store=_PROMPT_VERSION_STORE,
    )
    if body is not None:
        return LoadedPrompt(body=body, version=version)
    return LoadedPrompt(
        body=_load_freeflow_prompt(analyzer_os), version=None,
    )


_SEED_ANALYZER_OS: tuple[str, ...] = ("linux", "windows")


async def seed_prompt_versions() -> int:
    """Register the assembled forensics free-flow prompts (RFC-09 seed).

    For each effective analyzer OS variant, assemble the same file body
    the live turn path would produce (base + OS hint) and register it
    under the corresponding version-store key. Points ``production`` at
    the resulting version ONLY when the key has no production alias yet
    so an operator-promoted or canary-routed version is never overwritten
    on restart. Idempotent: :meth:`PromptVersionStore.register`
    deduplicates by content hash so an unchanged file writes no new row,
    and a later file edit registers a new version but does not flip
    ``production`` -- promotion stays an explicit RFC-10 lifecycle action.

    Called from :meth:`ForensicsModule.seed_prompts`, itself invoked by
    :func:`aila.platform.prompts.bootstrap.seed_module_prompts` at app
    startup. A per-key fault is logged by the store but never blocks
    startup: the fallback path in :func:`_resolve_freeflow_prompt` keeps
    working from the file baseline.

    Returns the count of keys whose ``production`` alias was newly set.
    """
    seeded = 0
    for analyzer_os in _SEED_ANALYZER_OS:
        try:
            body = _load_freeflow_prompt(analyzer_os)
        except (FileNotFoundError, PromptNotFoundError, OSError) as exc:
            _log.warning(
                "forensics seed_prompt_versions skipped os=%s (%s)",
                analyzer_os, exc,
            )
            continue
        key = _freeflow_prompt_key(analyzer_os)
        version = await _PROMPT_VERSION_STORE.register(
            key, body, author="bootstrap",
            notes="file baseline (RFC-09 activation seed)",
        )
        if await _PROMPT_VERSION_STORE.resolve(key, alias="production") is not None:
            continue
        await _PROMPT_VERSION_STORE.set_alias(
            key, "production", version,
            actor="bootstrap", reason="initial file baseline",
        )
        seeded += 1

    extra_entries: tuple[tuple[str, str], ...] = (
        (
            "forensics/base/network_commentary/default",
            FORENSICS_NETWORK_COMMENTARY_TEXT,
        ),
        ("prompts/base/writeup/default", FORENSICS_WRITEUP_TEXT),
    )
    for key, body in extra_entries:
        version = await _PROMPT_VERSION_STORE.register(
            key, body, author="bootstrap",
            notes="RFC-09 rule-58 migration seed",
        )
        if await _PROMPT_VERSION_STORE.resolve(key, alias="production") is not None:
            continue
        await _PROMPT_VERSION_STORE.set_alias(
            key, "production", version,
            actor="bootstrap", reason="initial file baseline",
        )
        seeded += 1
    return seeded


# ---------------------------------------------------------------------------
# Safety: AST-level guard for LLM-generated scripts.
#
# Substring matching (the earlier approach) is trivially bypassable via
# aliasing (``im = __import__``), string concatenation
# (``__import__('so'+'cket')``), ``importlib.import_module('socket')``, or
# unicode-escaped identifiers. We parse the script and walk it structurally
# so every one of those bypasses fails. The set of banned capabilities is
# unchanged: network egress modules, dynamic code execution, FFI escape,
# and specific destructive filesystem calls.
# ---------------------------------------------------------------------------

# Top-level module names (matched on the first dotted segment) whose import
# is denied. ``importlib`` is included so ``importlib.import_module('socket')``
# fails at the import line rather than requiring per-call string analysis.
_BANNED_MODULE_ROOTS: frozenset[str] = frozenset({
    "socket", "http", "urllib", "requests",
    "ftplib", "smtplib", "paramiko", "fabric",
    "ctypes", "importlib",
})

# Bare-name callables that give dynamic code execution or import.
# Also flagged as Name references (Load context) so ``im = __import__`` +
# later ``im('os')`` still trips the guard.
_BANNED_CALL_NAMES: frozenset[str] = frozenset({
    "exec", "eval", "compile", "__import__",
})

# Attribute names whose access is a classic sandbox-escape primitive
# (walking ``()__class__.__mro__[1].__subclasses__()`` and friends).
_BANNED_DUNDER_ATTRS: frozenset[str] = frozenset({
    "__class__", "__subclasses__", "__mro__", "__bases__", "__base__",
    "__globals__", "__builtins__", "__dict__", "__code__",
    "__init_subclass__", "__import__", "__loader__", "__spec__",
})

# Attribute-call names that destroy analyzer filesystem state. ``os`` and
# ``shutil`` themselves are allowed (needed for benign path/listdir work);
# the specific destructive verbs are blocked.
_BANNED_ATTR_CALLS: frozenset[str] = frozenset({
    "rmtree", "rmdir",
})


def _module_is_banned(dotted: str) -> bool:
    """Return True if the dotted module path's root segment is banned."""
    if not dotted:
        return False
    return dotted.split(".", 1)[0] in _BANNED_MODULE_ROOTS


class _ScriptGuard(ast.NodeVisitor):
    """AST walker that records the first banned construct it observes.

    Once ``reason`` is set the walker short-circuits: no further nodes are
    inspected, so the caller gets a stable "first offending construct"
    message rather than an accumulated list.
    """

    def __init__(self) -> None:
        self.reason: str | None = None

    def _reject(self, msg: str) -> None:
        if self.reason is None:
            self.reason = msg

    def generic_visit(self, node: ast.AST) -> None:
        if self.reason is not None:
            return
        super().generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if _module_is_banned(alias.name):
                self._reject(f"banned import: {alias.name}")
                return
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        # Relative imports (``from . import x``) have node.module == None and
        # can never resolve to a banned top-level. Absolute forms are checked.
        if node.module and _module_is_banned(node.module):
            self._reject(f"banned import: from {node.module}")
            return
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        # Catches aliasing bypasses: ``im = __import__`` on its own is a Load
        # reference to ``__import__`` and gets rejected here.
        if isinstance(node.ctx, ast.Load) and node.id in _BANNED_CALL_NAMES:
            self._reject(f"banned reference: {node.id}")
            return
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in _BANNED_DUNDER_ATTRS:
            self._reject(f"banned attribute access: .{node.attr}")
            return
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _BANNED_ATTR_CALLS:
            self._reject(f"banned call: .{func.attr}(...)")
            return
        # getattr(obj, "__dunder__"[, default]) -- classic escape primitive.
        if (
            isinstance(func, ast.Name)
            and func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
            and node.args[1].value.startswith("_")
        ):
            self._reject(f"banned call: getattr(..., {node.args[1].value!r})")
            return
        self.generic_visit(node)


def _script_rejection(script: str) -> str | None:
    """Reject scripts that use banned imports, calls, or escape attributes.

    Uses AST-level analysis so trivial obfuscations that defeat a substring
    check -- ``__import__('o'+'s')``, ``importlib.import_module('socket')``,
    ``im = __import__; im('socket')``, ``getattr(x, '__class__')`` -- all
    still fail. Fails closed: unparseable scripts are rejected here so the
    operator sees a security reason rather than a downstream SyntaxError.
    """
    try:
        tree = ast.parse(script)
    except SyntaxError as exc:
        return f"blocked: script does not parse (line {exc.lineno}): {exc.msg}"
    guard = _ScriptGuard()
    guard.visit(tree)
    if guard.reason is not None:
        return f"blocked: {guard.reason}"
    return None

# Shell-command blocklist for the ``tool_run`` path. Dynamic analysis is
# strictly prohibited: we never detonate the sample, never fetch remote
# resources named in the evidence, and never contact an IOC we derived
# from the investigation. Static analysis only.
_COMMAND_BLOCKLIST: tuple[str, ...] = (
    # network fetchers
    "curl ", "wget ", "aria2c", "fetch ", "lynx ", "links ", "w3m ",
    "iwr ", "invoke-webrequest", "invoke-restmethod",
    "bitsadmin", "certutil -urlcache", "certutil /urlcache",
    "powershell -c \"iex", "powershell -c 'iex", "iex(new-object",
    # direct transports
    "ncat ", "ncat.exe", "nc ", "nc.exe ", "socat ",
    "telnet ", "ssh ", "scp ", "sftp ", "rsync ",
    "ftp ", "tftp ",
    # packet / scan
    "nmap ", "masscan ", "zmap ", "hping3 ", "arp-scan",
    "ping -c", "ping -n", "ping6 ", "tracert ", "traceroute ",
    "nslookup ", "dig ", "host ", "whois ",
    # sample detonation
    "./a.out", "./sample", "./main.exe", "./server",
    "wine ", "mono ",
    "start malware", "start sample", "rundll32 ", "regsvr32 ",
    "msiexec ", "mshta ", "cscript ", "wscript ",
    # container / VM escape surfaces
    "docker run", "podman run", "lxc-start", "virsh start",
)


def _command_rejection(command: str) -> str | None:
    low = command.lower()
    for needle in _COMMAND_BLOCKLIST:
        if needle in low:
            return (
                f"blocked: dynamic-analysis prohibited -- command contains "
                f"'{needle.strip()}'. Static analysis only: do NOT execute "
                f"the sample, do NOT contact remote hosts, do NOT probe "
                f"IOCs."
            )
    return None

# Per-investigation turn cap (hard limit on top of config-supplied max_attempts).
_HARD_TURN_CAP = 50

# Max bytes of stdout to keep per turn in the persisted record. Sized
# to fit complete forensic windows (multi-entry security logs, full
# commits.diff blobs, Action-log zip listings) without truncation.
# The persisted record is ~512 KB; modern Postgres TEXT handles this
# easily and the LLM context window (~200K tokens for opus-4-6) has
# room to spare.
_STDOUT_KEEP_BYTES = 512_000

# Max bytes of stdout to render per *historical* turn into the next
# turn's prompt. The most recent turn is always rendered uncut so the
# agent can see the full output of the script it just ran.
_HISTORY_STDOUT_PER_TURN = 80_000

# How many recent turns to render into the next turn's prompt history.
_HISTORY_WINDOW_TURNS = 10


def _sanitize_for_postgres_text(s: str | None) -> str | None:
    """Strip bytes that PostgreSQL TEXT columns refuse to store.

    PostgreSQL rejects ``\\x00`` (NUL) bytes in TEXT/VARCHAR columns
    with ``CharacterNotInRepertoireError``. They appear in our pipeline
    when the agent runs ``strings`` or raw byte-carving against packed
    binaries. If they reach the agent_steps INSERT they kill the whole
    investigation: the worker catches the exception, the dispatcher
    records "no response", and the row is left frozen in ``running``
    forever.

    Replace NULs with the unicode replacement character so the bytes
    are still visible to the LLM on the next turn (it can see "binary
    block, replaced ``\ufffd`` chars") without poisoning the DB write.
    ``None`` is preserved as ``None`` so nullable columns stay null.
    """
    if s is None:
        return None
    if "\x00" not in s:
        return s
    return s.replace("\x00", "\ufffd")


class HonestInvestigator:
    """Bounded, closed-loop forensic investigator.

    Owned state during an investigation:
    - ``contract``: parsed once, locked after the first turn that emits it.
    - ``hypotheses``: live set; losers migrate to ``rejected``.
    - ``rejected``: kept for the whole investigation so the LLM cannot
      silently re-propose a dead hypothesis.
    - ``observables``: accumulated normalised facts.
    """

    def __init__(
        self,
        settings: Settings,
        reasoning_engine: CyberReasoningEngine,
        reasoning_graphs: ReasoningGraphService,
        run_id: str,
        integration: dict[str, Any],
        project_id: str,
        investigation_id: str,
        analyzer_os: str = "linux",
        parent_investigation_id: str | None = None,
    ) -> None:
        self.settings = settings
        self.reasoning_engine = reasoning_engine
        self.reasoning_graphs = reasoning_graphs
        self.run_id = run_id
        self.integration = integration
        self.project_id = project_id
        self.investigation_id = investigation_id
        self.analyzer_os = analyzer_os
        # Set when the API-layer rerun endpoint started this run from a
        # prior attempt. Triggers a single hydrate-from-parent pass at
        # the top of investigate() before turn 1.
        self.parent_investigation_id = parent_investigation_id

        self.contract: dict[str, Any] = {}
        self.hypotheses: list[dict[str, Any]] = []
        self.rejected: list[dict[str, Any]] = []
        # Hypotheses auto-bucketed at terminal submit when the agent
        # neither explicitly rejected nor folded them into the answer
        # (issue #175: parity with vr/malware via
        # ``platform.agents.turn_helpers.auto_resolve_live_on_terminal``).
        # Stays empty until the terminal turn; the frontend renders
        # this list with a neutral badge so operators know to consult
        # the canonical outcome for the true classification.
        self.resolved: list[dict[str, Any]] = []
        self.observables: dict[str, Any] = {}
        # Consecutive rejections by the unresolved-hypothesis submit
        # gate on THIS investigation (issue #175). Counted per run,
        # not persisted -- a re-enqueue starts fresh (matches the
        # per-branch counter behaviour in
        # ``HonestVulnResearcher._maybe_reject_submit_with_unresolved_hypotheses``).
        self._unresolved_hyp_gate_rejects: int = 0
        # Live cap for the gate above. Loaded lazily on first turn
        # via ConfigRegistry so an operator can widen or disable
        # (value=0) without a redeploy.
        self._unresolved_hyp_reject_cap: int | None = None
        # One-shot prompt block describing the parent attempt's outcome,
        # rendered into turn 1's history slot. Cleared after consumption.
        self._parent_summary: str | None = None
        # Denormalised copy of the parent project's ``team_id`` (#59).
        # Populated by :meth:`_load_project_context` on the first turn
        # so every persisted ``AgentStepRecord`` / ``AnswerCandidateRecord``
        # / summary flip carries the same tenant marker as the parent
        # ``InvestigationRunRecord`` -- the team-scope listener then
        # auto-filters reads on those rows without a project-join.
        # Stays ``None`` when the parent project is admin-owned.
        self.team_id: str | None = None

    # ------------------------------------------------------------------ run

    async def investigate(
        self,
        question: str,
        max_attempts: int = 10,
        emitter: Any = None,
    ) -> dict[str, Any]:
        """Drive the investigation to either a submitted answer or exhaustion.

        Persists each turn as an ``AgentStepRecord`` and the final answer
        (if any) as an ``AnswerCandidateRecord``. Does NOT transition the
        investigation status -- that is owned by the workflow engine's
        terminal state and the freeflow state handler's error path.
        """
        from sqlmodel import select

        from aila.modules.forensics.db_models import (
            AgentStepRecord,
            AnswerCandidateRecord,
            InvestigationRunRecord,
        )
        from aila.platform.uow import UnitOfWork

        max_turns = min(max(max_attempts, 1), _HARD_TURN_CAP)
        _log.info(
            "HonestInvestigator.investigate START inv_id=%s project_id=%s os=%s max_turns=%d q=%r",
            self.investigation_id, self.project_id, self.analyzer_os,
            max_turns, (question or "")[:120],
        )

        evidence_listing, evidence_dir, project_kind, project_team_id = await self._load_project_context()
        # Cache the parent project's team_id on the agent so downstream
        # per-turn persistence stamps it onto every child row (#59).
        self.team_id = project_team_id

        # Flip investigation to "running" so the reconciler can tell the
        # difference between "never started" and "in flight". Uses its own
        # short-lived UoW so a later turn failure cannot roll back this flip.
        await self._set_status("running")

        # Enrichment from prior attempt (rerun path). Hydrates
        # self.observables and prepares a one-shot prompt block that
        # turn 1 will see in its `previous` slot.
        if self.parent_investigation_id:
            try:
                self._parent_summary = await self._load_parent_findings()
                if emitter and self._parent_summary:
                    await emitter.emit(
                        "freeflow",
                        f"Enriched from parent attempt {self.parent_investigation_id[:8]} "
                        f"({len(self.observables)} observable(s) carried forward)",
                        {
                            "stage": "parent_enrichment",
                            "parent_investigation_id": self.parent_investigation_id,
                            "n_observables": len(self.observables),
                        },
                    )
            except (OSError, RuntimeError, AILAError) as exc:
                _log.warning(
                    "parent enrichment failed for inv %s (parent=%s): %s",
                    self.investigation_id, self.parent_investigation_id, exc,
                )

        steps: list[dict[str, Any]] = []
        answer: str | None = None
        confidence = "caveated"

        for turn in range(1, max_turns + 1):
            # Analyst-initiated stop: cheap indexed PK lookup at the top
            # of each iteration. We don't poll inside _run_turn -- that
            # would race with ssh commands already in flight. Between
            # turns is the safe boundary.
            if await self._is_cancelled():
                _log.info(
                    "HonestInvestigator inv_id=%s cancelled by analyst at turn %d",
                    self.investigation_id, turn,
                )
                if emitter:
                    await emitter.emit(
                        "freeflow",
                        "Investigation cancelled by analyst.",
                        {"stage": "cancelled", "attempt": turn},
                    )
                return {
                    "answer": "Cancelled by analyst.",
                    "confidence": "unknown",
                    "attempts_used": turn - 1,
                    "steps": steps,
                    "cancelled": True,
                }

            if emitter:
                await emitter.emit(
                    "freeflow",
                    f"Turn {turn}/{max_turns} -- planning next action...",
                    {
                        "stage": "turn_start",
                        "attempt": turn,
                        "max_attempts": max_turns,
                        "contract": self.contract,
                        "n_hypotheses": len(self.hypotheses),
                        "n_rejected": len(self.rejected),
                        "n_observables": len(self.observables),
                    },
                )

            # Each turn owns its own UoW. A crash in one turn must NOT
            # roll back earlier turns' persisted steps/answers.
            try:
                artifacts_snapshot = await self._snapshot_artifacts()
                turn_result = await self._run_turn(
                    question=question,
                    turn=turn,
                    max_turns=max_turns,
                    evidence_dir=evidence_dir,
                    evidence_listing=evidence_listing,
                    project_kind=project_kind,
                    artifacts_snapshot=artifacts_snapshot,
                    previous=steps,
                    emitter=emitter,
                )
            except (OSError, TimeoutError, RuntimeError, ValueError, KeyError,
                    IndexError, TypeError, AttributeError, AILAError) as exc:
                _log.exception(
                    "HonestInvestigator turn %d raised -- persisting as failure step",
                    turn,
                )
                turn_result = {
                    "step_number": turn,
                    "action": "reasoning",
                    "reasoning": f"[turn_exception] {type(exc).__name__}: {str(exc)[:500]}",
                    "expected_observation": "",
                    "contract": dict(self.contract),
                    "hypotheses": list(self.hypotheses),
                    "rejected": list(self.rejected),
                    "observables": dict(self.observables),
                    "answer": None,
                    "confidence": None,
                    "submitted": False,
                    "provenance": {},
                    "stderr": f"{type(exc).__name__}: {exc}",
                    "exit_code": 1,
                }
                if emitter:
                    await emitter.emit(
                        "freeflow",
                        f"Turn {turn} EXCEPTION -- {type(exc).__name__}: {str(exc)[:160]}",
                        {"stage": "turn_exception", "attempt": turn,
                         "error_type": type(exc).__name__, "error": str(exc)[:500]},
                    )

            steps.append(turn_result)

            # Persist step in its own UoW.
            try:
                async with UnitOfWork() as step_uow:
                    step_uow.session.add(AgentStepRecord(
                        investigation_id=self.investigation_id,
                        # Denormalised parent team_id (#59) so the
                        # team-scope listener auto-filters step reads.
                        team_id=self.team_id,
                        step_number=turn,
                        action=turn_result.get("action", "reasoning"),
                        script_content=_sanitize_for_postgres_text(turn_result.get("script_content")),
                        command=_sanitize_for_postgres_text(turn_result.get("command")),
                        stdout=_sanitize_for_postgres_text(turn_result.get("stdout")),
                        stderr=_sanitize_for_postgres_text(turn_result.get("stderr")),
                        exit_code=turn_result.get("exit_code"),
                        reasoning=_sanitize_for_postgres_text(self._compose_reasoning(turn_result)),
                    ))
                    # Bump attempts_used incrementally so the frontend
                    # sees progress without waiting for the final commit.
                    inv_row = (await step_uow.session.exec(
                        select(InvestigationRunRecord).where(
                            InvestigationRunRecord.id == self.investigation_id
                        )
                    )).first()
                    if inv_row is not None:
                        inv_row.attempts_used = len(steps)
                        step_uow.session.add(inv_row)
                    await step_uow.commit()
            except (OSError, RuntimeError, AILAError):
                _log.exception("Failed to persist agent step %d (continuing)", turn)

            # Persist any new structured findings the agent has
            # accumulated so far as ArtifactRecord rows. The service
            # de-dups on (artifact_type, sha256(data_json)) so calling
            # this every turn is safe -- only genuinely new findings
            # produce new rows. We skip the always-on summary row
            # here; that's reserved for the submission path below.
            try:
                from aila.modules.forensics.services.investigation_artifacts import (
                    persist_investigation_artifacts,
                )
                await persist_investigation_artifacts(
                    project_id=self.project_id,
                    investigation_id=self.investigation_id,
                    question=question,
                    answer="",
                    confidence="",
                    observables=dict(self.observables),
                    provenance=turn_result.get("provenance") or {},
                    contract=dict(self.contract),
                    include_summary=False,
                )
            except (OSError, RuntimeError, AILAError) as exc:
                _log.warning(
                    "per-step investigation-artifact persistence skipped (turn %d): %s",
                    turn, exc,
                )
            try:
                graph_payload = turn_result.get("evidence_graph") or {}
                await self.reasoning_graphs.save_snapshot(
                    run_id=self.run_id,
                    module_id="forensics",
                    subject_kind="investigation",
                    subject_id=self.investigation_id,
                    step_number=turn,
                    strategy_family=str(turn_result.get("strategy_family") or "generic"),
                    graph=graph_payload if isinstance(graph_payload, dict) else {},
                )
            except (OSError, RuntimeError, AILAError) as exc:
                _log.warning(
                    "reasoning graph snapshot persistence skipped (turn %d): %s",
                    turn,
                    exc,
                )

            if emitter:
                await emitter.emit(
                    "freeflow",
                    f"Turn {turn} persisted -- action={turn_result.get('action')}"
                    + (" (answer submitted)" if turn_result.get("submitted") else ""),
                    {
                        "stage": "turn_persisted",
                        "attempt": turn,
                        "action": turn_result.get("action"),
                        "exit_code": turn_result.get("exit_code"),
                        "submitted": bool(turn_result.get("submitted")),
                        "answer_preview": (turn_result.get("answer") or "")[:200] if turn_result.get("answer") else "",
                    },
                )

            if turn_result.get("submitted"):
                answer = turn_result["answer"]
                confidence = turn_result.get("confidence") or "medium"
                provenance = turn_result.get("provenance") or {}
                corroboration = provenance.get("corroboration") or []
                if not isinstance(corroboration, list):
                    corroboration = [str(corroboration)]
                try:
                    async with UnitOfWork() as ans_uow:
                        ans_uow.session.add(AnswerCandidateRecord(
                            project_id=self.project_id,
                            # Denormalised parent team_id (#59) so the
                            # team-scope listener auto-filters answer reads.
                            team_id=self.team_id,
                            investigation_id=self.investigation_id,
                            question_text=question,
                            answer_text=str(answer),
                            confidence=confidence,
                            primary_artifact_id=str(provenance.get("primary_artifact") or "")[:255] or None,
                            corroboration_json=json.dumps([str(x) for x in corroboration])[:4000],
                            format_hint=self.contract.get("answer_format", "")[:255],
                        ))
                        await ans_uow.commit()
                except (OSError, RuntimeError, AILAError):
                    _log.exception("Failed to persist AnswerCandidateRecord (continuing)")

                # Persist the agent's structured findings (observables +
                # provenance) as proper ArtifactRecord rows so the
                # Artifacts tab can show what the investigation
                # discovered. The helper swallows its own failures and
                # logs at WARNING -- it must never destabilise the
                # submission path.
                try:
                    from aila.modules.forensics.services.investigation_artifacts import (
                        persist_investigation_artifacts,
                    )
                    await persist_investigation_artifacts(
                        project_id=self.project_id,
                        investigation_id=self.investigation_id,
                        question=question,
                        answer=str(answer),
                        confidence=confidence,
                        observables=dict(self.observables),
                        provenance=provenance,
                        contract=dict(self.contract),
                    )
                except (OSError, RuntimeError, AILAError) as exc:
                    _log.warning("investigation-artifact persistence skipped: %s", exc)
                break

        # Final summary commit. Note: investigation status is owned by the
        # workflow engine's response_emit terminal state on the happy path,
        # and by state_freeflow's error path otherwise. We only write
        # summary scalars here.
        try:
            async with UnitOfWork() as summary_uow:
                inv = (await summary_uow.session.exec(
                    select(InvestigationRunRecord).where(
                        InvestigationRunRecord.id == self.investigation_id
                    )
                )).first()
                if inv is not None:
                    inv.attempts_used = len(steps)
                    inv.final_answer = answer
                    inv.confidence = confidence if answer else None
                    summary_uow.session.add(inv)
                    await summary_uow.commit()
        except (OSError, RuntimeError, AILAError):
            _log.exception("Failed to write summary fields (continuing)")

        _log.info(
            "HonestInvestigator.investigate END inv_id=%s steps=%d answer=%s",
            self.investigation_id, len(steps), bool(answer),
        )
        return {
            "answer": answer,
            "confidence": confidence,
            "attempts_used": len(steps),
            "steps": steps,
            "contract": self.contract,
            "observables": self.observables,
            "hypotheses": self.hypotheses,
            "rejected": self.rejected,
            # Auto-resolved-at-terminal hypotheses (issue #175 parity).
            "resolved": self.resolved,
        }

    async def _set_status(self, status_value: str) -> None:
        """Flip the investigation row's status in its own UoW."""
        from sqlmodel import select as _select

        from aila.modules.forensics.db_models import InvestigationRunRecord
        from aila.platform.uow import UnitOfWork

        try:
            async with UnitOfWork() as uow:
                row = (await uow.session.exec(
                    _select(InvestigationRunRecord).where(
                        InvestigationRunRecord.id == self.investigation_id
                    )
                )).first()
                if row is not None and row.status != status_value:
                    row.status = status_value
                    uow.session.add(row)
                    await uow.commit()
        except (OSError, RuntimeError, AILAError):
            _log.exception("Failed to set investigation status=%s", status_value)

    async def _is_cancelled(self) -> bool:
        """One indexed PK lookup against the investigation row.

        Returns True when the analyst has hit the Stop button on the UI
        (``POST .../cancel`` flipped ``status`` to ``cancelled``). The
        investigate loop calls this at the top of each iteration so it
        can exit cleanly between turns instead of mid-shell-command.
        """
        from sqlmodel import select as _select

        from aila.modules.forensics.db_models import InvestigationRunRecord
        from aila.platform.uow import UnitOfWork

        try:
            async with UnitOfWork() as uow:
                row = (await uow.session.exec(
                    _select(InvestigationRunRecord).where(
                        InvestigationRunRecord.id == self.investigation_id
                    )
                )).first()
            return bool(row is not None and row.status == "cancelled")
        except (OSError, RuntimeError, AILAError):
            _log.exception("Failed to poll investigation cancel flag")
            return False

    # ---------------------------------------------------------------- turn

    async def _run_turn(
        self,
        question: str,
        turn: int,
        max_turns: int,
        evidence_dir: str,
        evidence_listing: str,
        project_kind: str,
        artifacts_snapshot: str,
        previous: list[dict[str, Any]],
        emitter: Any,
    ) -> dict[str, Any]:
        case_state = self._case_state()
        case_model = self.reasoning_engine.render_case_model(case_state)
        prev_text = self._render_previous(previous[-_HISTORY_WINDOW_TURNS:])
        # On turn 1 of an enriched rerun, prepend the parent-attempt
        # summary into the `previous` slot so the LLM sees what the
        # earlier run found before it picks its first action. The block
        # is consumed once and cleared so subsequent turns rely on
        # actual step history.
        if turn == 1 and self._parent_summary:
            prev_text = (
                self._parent_summary
                + ("\n\n" if prev_text else "")
                + prev_text
            )
            self._parent_summary = None
        steering = await self._load_operator_steering()
        domain_profile = self.reasoning_engine.resolve_domain_profile("forensics")
        strategy_family = self.reasoning_engine.select_strategy_family(
            question=question,
            case_state=case_state,
            evidence_listing=evidence_listing,
            project_kind=project_kind,
            steering=steering,
        )

        prompt = self.reasoning_engine.build_user_prompt(
            ReasoningPromptContext(
                turn=turn,
                max_turns=max_turns,
                question=question,
                evidence_dir=evidence_dir,
                evidence_listing=evidence_listing,
                project_kind=project_kind,
                case_model=case_model,
                artifacts=artifacts_snapshot,
                previous=prev_text,
                domain_profile=domain_profile.domain_id,
                operator_steering=steering,
                strategy_family=strategy_family,
            )
        )

        if emitter:
            await emitter.emit(
                "freeflow",
                f"Turn {turn}: querying LLM ({len(prompt)} chars context)",
                {"stage": "llm_query_start", "step": turn, "prompt_chars": len(prompt)},
            )

        # RFC-09 criteria 2 + 4: route the free-flow prompt through the
        # version store so the first turn on this investigation pins the
        # production-alias version onto ``prompt_pins_json`` and every
        # later turn on the same investigation resolves that exact
        # version. Falls back to the file assembly when the store has no
        # body (no production alias yet, missing pin target, or store
        # fault). The resolved version is what stamps the correlation
        # scope so LLMCostRecord + AuditSealRecord carry non-null
        # ``prompt_version`` for every turn that landed a store body --
        # closing the (cost, prompt) join criterion 2 requires.
        loaded = await _resolve_freeflow_prompt(
            self.analyzer_os, investigation_id=self.investigation_id,
        )
        system_prompt = loaded.body
        # RFC-09 criterion 2: hash the FINAL assembled system prompt (base +
        # OS hint) so a Linux-analyzer turn and a Windows-analyzer turn land
        # distinct content hashes on their LLMCostRecord + AuditSealRecord.
        # Preserve any outer join keys so the investigation attribution
        # already established by the caller is not clobbered.
        prompt_hash = hashlib.sha256(system_prompt.encode("utf-8")).hexdigest()
        _inv, _br, _turn = current_join_keys()
        # loaded.version is the resolved version-store id when the store
        # returned a body; None on the file-fallback path. current_prompt_version()
        # is consulted as an outer fallback so an already-established version
        # (set by an enclosing scope) is preserved when the loader itself did
        # not resolve one.
        resolved_version = loaded.version or current_prompt_version()
        t0 = time.monotonic()
        with correlation_scope(
            investigation_id=_inv, branch_id=_br, turn_number=_turn,
            prompt_content_hash=prompt_hash,
            prompt_version=resolved_version,
        ):
            decision = await self.reasoning_engine.decide_next_turn(
                task_type=domain_profile.task_type,
                system_prompt=system_prompt,
                user_prompt=prompt,
                run_id=self.investigation_id,
            )
        elapsed = time.monotonic() - t0
        # Pass ``turn_number`` so absorb stamps ``opened_at_turn`` on
        # newly-live hypotheses and advances the case-model turn counter.
        # The per-turn staleness nag ("[alive N turns]") was removed: an
        # unresolved hypothesis is now pressured only at the submit gate
        # (_maybe_reject_submit_with_unresolved_hypotheses), not by age.
        case_state = self.reasoning_engine.absorb(
            case_state, decision, turn_number=turn,
        )
        self._apply_case_state(case_state)

        action = decision.action
        reasoning = decision.reasoning.strip()
        expected = decision.expected_observation.strip()

        if emitter:
            await emitter.emit(
                "freeflow",
                f"Turn {turn}: LLM returned in {elapsed:.1f}s -- action={action}",
                {
                    "stage": "llm_query_done",
                    "step": turn,
                    "elapsed_s": round(elapsed, 1),
                    "action": action,
                    "reasoning": reasoning,
                    "expected_observation": expected,
                    "contract": self.contract,
                    "hypotheses": self.hypotheses,
                    "rejected": self.rejected,
                    "observables": self.observables,
                },
            )

        evidence_graph = self.reasoning_engine.build_evidence_graph(
            case_state=case_state,
            decision=decision,
        )

        result: dict[str, Any] = {
            "step_number": turn,
            "action": action,
            "reasoning": reasoning,
            "expected_observation": expected,
            "strategy_family": strategy_family,
            "contract": dict(self.contract),
            "hypotheses": list(self.hypotheses),
            "rejected": list(self.rejected),
            "resolved": list(self.resolved),
            "observables": dict(self.observables),
            "evidence_graph": evidence_graph.model_dump(mode="json"),
            "answer": None,
            "confidence": None,
            "submitted": False,
            "provenance": decision.provenance.model_dump(mode="json"),
        }

        if action == "script_execute":
            script = decision.script_content or ""
            if not script.strip():
                result["stderr"] = "LLM emitted script_execute with empty script_content"
                result["exit_code"] = 1
                return result
            result["script_content"] = script
            if emitter:
                await emitter.emit(
                    "freeflow",
                    f"Turn {turn}: executing script on analyzer ({len(script)} chars)",
                    {"stage": "ssh_exec_script", "step": turn, "script": script},
                )
            exec_res = await self._execute_script(script)
            result.update(exec_res)
            if emitter:
                await emitter.emit(
                    "freeflow",
                    f"Turn {turn}: script exit={exec_res.get('exit_code')} stdout={len(exec_res.get('stdout') or ''):,}B",
                    {
                        "stage": "ssh_exec_done",
                        "step": turn,
                        "exit_code": exec_res.get("exit_code"),
                        "stdout": exec_res.get("stdout"),
                        "stderr": exec_res.get("stderr"),
                    },
                )
            return result

        if action == "tool_run":
            cmd = decision.command or ""
            if not cmd.strip():
                result["stderr"] = "LLM emitted tool_run with empty command"
                result["exit_code"] = 1
                return result
            result["command"] = cmd
            if emitter:
                await emitter.emit(
                    "freeflow",
                    f"Turn {turn}: running command -- {cmd[:160]}",
                    {"stage": "ssh_exec_command", "step": turn, "command": cmd},
                )
            exec_res = await self._execute_command(cmd)
            result.update(exec_res)
            if emitter:
                await emitter.emit(
                    "freeflow",
                    f"Turn {turn}: command exit={exec_res.get('exit_code')} stdout={len(exec_res.get('stdout') or ''):,}B",
                    {
                        "stage": "ssh_exec_done",
                        "step": turn,
                        "exit_code": exec_res.get("exit_code"),
                        "stdout": exec_res.get("stdout"),
                        "stderr": exec_res.get("stderr"),
                    },
                )
            return result

        if action == 'artifact_query':
            # Let the agent search/filter project artifacts by family, type, or text.
            search_text = (decision.command or '').strip()  # reuse command field for search query
            family_filter = self.observables.get('_artifact_family', '')
            type_filter = self.observables.get('_artifact_type', '')
            from aila.modules.forensics.tools.artifact_query import ArtifactQueryTool
            tool = ArtifactQueryTool(self.settings)
            try:
                query_result = await tool.forward(
                    action='search' if search_text else 'list',
                    project_id=self.project_id,
                    artifact_family=family_filter or None,
                    artifact_type=type_filter or None,
                    search_text=search_text or None,
                    limit=20,
                )
                import json as _json
                result['stdout'] = _json.dumps(query_result, default=str)[:_STDOUT_KEEP_BYTES]
                result['exit_code'] = 0
                result['command'] = f'artifact_query search={search_text!r} family={family_filter!r} type={type_filter!r}'
            except (ValueError, RuntimeError, OSError, KeyError) as exc:
                result['stderr'] = f'artifact_query failed: {exc}'
                result['exit_code'] = 1
            if emitter:
                await emitter.emit(
                    'freeflow',
                    f'Turn {turn}: artifact query -- {search_text or "list all"} ({result.get("exit_code")})',
                    {'stage': 'artifact_query', 'step': turn},
                )
            return result

        if action == "submit":
            ans = decision.answer
            prov = decision.provenance.model_dump(mode="json")
            primary = str(prov.get("primary_artifact") or "").strip()
            gate_error = self.reasoning_engine.validate_submission(
                answer=ans,
                primary_artifact=primary,
                previous_turns=previous,
                observables=case_state.observables,
                required_artifacts=steering.required_artifacts,
                corroboration=decision.provenance.corroboration,
            )
            if gate_error is not None:
                result["action"] = "reasoning"
                result["reasoning"] = f"[answer_gate_rejected] {gate_error} | original_reasoning: {reasoning}"
                return result

            # Issue #175 closure-pressure gate. A submit whose live
            # hypotheses aren't either rejected this turn or folded
            # into the answer leaves the operator unable to tell which
            # claims the finding actually settles. Mirrors
            # ``HonestVulnResearcher._maybe_reject_submit_with_unresolved_hypotheses``
            # in shape: reject up to ``unresolved_hyp_reject_cap`` times
            # with a steering directive; on the (cap+1)th attempt force
            # through with an advisory marker on the provenance.
            gate_reject = await self._maybe_reject_submit_with_unresolved_hypotheses(
                decision=decision,
                case_state=case_state,
                answer=ans,
                turn=turn,
            )
            if gate_reject is not None:
                result["action"] = "reasoning"
                result["reasoning"] = (
                    f"[unresolved_hyp_gate_rejected] {gate_reject} | "
                    f"original_reasoning: {reasoning}"
                )
                # Persist the directive the gate stamped onto observables
                # so the next turn's prompt renders it.
                self._apply_case_state(case_state)
                result["observables"] = dict(self.observables)
                return result

            # Accepted terminal submit: auto-resolve every still-live
            # hypothesis before the case_state is persisted so the
            # frontend / write-up sees an accurate closure picture instead
            # of live claims sitting under a completed investigation.
            # Uses the platform helper vr and malware share; the resolved
            # note points readers at the terminal outcome for the actual
            # confirmed / rejected classification.
            outcome_kind_for_resolve = (
                str(self.contract.get("answer_type") or "answer")
            )
            auto_resolve_live_on_terminal(
                case_state,
                turn=turn,
                outcome_kind=outcome_kind_for_resolve,
            )
            self._apply_case_state(case_state)

            # If the gate was rejected earlier on this run and this
            # submit is a force-through, stamp the advisory on the
            # provenance so downstream audit rows retain the trail.
            if self._unresolved_hyp_gate_rejects > int(
                self._unresolved_hyp_reject_cap or 0,
            ) > 0:
                prov = dict(prov)
                prov["unresolved_hypotheses_at_submit_advisory"] = {
                    "gate_rejects_before_force_through": (
                        self._unresolved_hyp_gate_rejects - 1
                    ),
                    "reject_cap": int(self._unresolved_hyp_reject_cap or 0),
                }

            result["answer"] = str(ans)
            result["confidence"] = (decision.confidence or "medium").strip().lower() or "medium"
            result["submitted"] = True
            result["provenance"] = prov
            result["resolved"] = list(self.resolved)
            result["hypotheses"] = list(self.hypotheses)
            return result

        # default: reasoning-only turn, nothing else to do.
        return result


    # ------------------------------------------------------- reasoning state

    def _case_state(self) -> ReasoningCaseState:
        """Return the current investigator state as platform reasoning models."""
        contract = (
            ReasoningContract.model_validate(self.contract)
            if self.contract
            else ReasoningContract()
        )
        hypotheses = [Hypothesis.model_validate(item) for item in self.hypotheses]
        rejected = [RejectedHypothesis.model_validate(item) for item in self.rejected]
        resolved = [ResolvedHypothesis.model_validate(item) for item in self.resolved]
        return ReasoningCaseState(
            contract=contract,
            hypotheses=hypotheses,
            rejected=rejected,
            resolved=resolved,
            observables=dict(self.observables),
        )

    def _apply_case_state(self, case_state: ReasoningCaseState) -> None:
        """Persist platform reasoning state back onto the investigator."""
        contract_payload = case_state.contract.model_dump(mode="json")
        self.contract = {
            key: value
            for key, value in contract_payload.items()
            if value not in ("", [], None)
        }
        self.hypotheses = [item.model_dump(mode="json") for item in case_state.hypotheses]
        self.rejected = [item.model_dump(mode="json") for item in case_state.rejected]
        self.resolved = [item.model_dump(mode="json") for item in case_state.resolved]
        self.observables = dict(case_state.observables)

    async def _maybe_reject_submit_with_unresolved_hypotheses(
        self,
        *,
        decision: Any,
        case_state: ReasoningCaseState,
        answer: object,
        turn: int,
    ) -> str | None:
        """Closure-pressure submit gate for the free-flow forensics loop.

        Parity with :meth:`aila.modules.vr.agents.vuln_researcher.HonestVulnResearcher._maybe_reject_submit_with_unresolved_hypotheses`
        (issue #175). A hypothesis is considered "resolved" this turn when
        it appears in ``decision.rejected[]`` OR when its id is cited
        verbatim in the answer text. Anything in
        ``case_state.hypotheses`` still live after those two escape hatches
        is an unresolved claim the operator can't tell the finding
        addresses -- the gate rejects, mutates ``case_state.observables``
        to inject a steering directive the next turn's prompt renders,
        and returns a short rejection reason so the caller can attach it
        to the persisted step. Returns ``None`` when the submit passes.

        After ``self._unresolved_hyp_reject_cap`` rejections on the same
        run the submit is force-through; the caller stamps
        ``unresolved_hypotheses_at_submit_advisory`` on the provenance
        so operators can audit. A cap of 0 disables the gate entirely
        (returns ``None`` immediately).

        Async because ``ConfigRegistry.get`` is async; the actual check
        is pure.
        """
        if self._unresolved_hyp_reject_cap is None:
            self._unresolved_hyp_reject_cap = await _cfg.get_int(
                "unresolved_hyp_reject_cap",
            )
        cap = int(self._unresolved_hyp_reject_cap or 0)
        if cap <= 0:
            return None

        live_ids = [h.id for h in case_state.hypotheses if h.id]
        if not live_ids:
            # Nothing live -- clear any stale directive.
            case_state.observables.pop(
                "_directive.unresolved_hyp_submit_rejected", None,
            )
            return None

        answer_text = str(answer or "")
        newly_rejected_ids = {r.id for r in decision.rejected if r.id}
        unresolved = [
            hid for hid in live_ids
            if hid not in newly_rejected_ids and hid not in answer_text
        ]

        if not unresolved:
            case_state.observables.pop(
                "_directive.unresolved_hyp_submit_rejected", None,
            )
            return None

        self._unresolved_hyp_gate_rejects += 1
        rejects_so_far = self._unresolved_hyp_gate_rejects

        # Compact rendering of the offending ids for the directive.
        hyp_by_id = {h.id: h for h in case_state.hypotheses if h.id}
        listing_lines: list[str] = []
        for hid in unresolved[:10]:
            h = hyp_by_id.get(hid)
            claim = (h.claim if h else "")[:140]
            listing_lines.append(f"  - {hid}: {claim}")
        if len(unresolved) > 10:
            listing_lines.append(f"  ... and {len(unresolved) - 10} more")
        listing_block = "\n".join(listing_lines)

        if rejects_so_far > cap:
            # Force-through path -- log and let the caller stamp the
            # advisory on the provenance. Clear the directive so the
            # next turn's prompt doesn't scold about a closure that
            # just landed.
            _log.warning(
                "forensics unresolved_hyp submit FORCED THROUGH after %d "
                "rejections inv=%s turn=%d -- %d unresolved: %s",
                rejects_so_far - 1, self.investigation_id, turn,
                len(unresolved), ",".join(unresolved[:20]),
            )
            case_state.observables.pop(
                "_directive.unresolved_hyp_submit_rejected", None,
            )
            return None

        _log.info(
            "forensics unresolved_hyp submit REJECTED inv=%s turn=%d "
            "rejects=%d/%d -- %d live hypotheses unresolved",
            self.investigation_id, turn,
            rejects_so_far, cap, len(unresolved),
        )
        case_state.observables["_directive.unresolved_hyp_submit_rejected"] = (
            "*** SUBMIT REJECTED - UNRESOLVED LIVE HYPOTHESES ***\n"
            f"Rejection {rejects_so_far}/{cap} on this investigation.\n"
            "\n"
            f"You attempted action: submit while {len(unresolved)} live "
            "hypotheses are unresolved. Submitting now leaves the operator "
            "unable to tell which hypotheses your answer actually settles.\n"
            "\n"
            "UNRESOLVED LIVE HYPOTHESES:\n"
            f"{listing_block}\n"
            "\n"
            "REQUIRED for your next decision: for EACH unresolved id above,\n"
            "EITHER\n"
            "  (a) add it to `rejected[]` with a `reason` that cites the\n"
            "      concrete evidence (artefact id, file:offset, tool-run\n"
            "      stdout you produced) that disproves the claim.\n"
            "  (b) name the id verbatim in your `answer` text so the reader\n"
            "      can see the finding confirms it. Include a supporting\n"
            "      artefact under `provenance.corroboration`.\n"
            "\n"
            "Then re-emit action=submit with the cleaned state. ALL live\n"
            "hypotheses must be reachable from (a) OR (b) on the same turn\n"
            "as the submit.\n"
            "\n"
            f"After {cap} rejections on this investigation the submit is\n"
            "FORCED THROUGH with an\n"
            "``unresolved_hypotheses_at_submit_advisory`` marker on the\n"
            "provenance so the operator can audit. Don't burn through the\n"
            "safety budget when the fix is mechanical."
        )
        return (
            f"{len(unresolved)} live hypothesis(es) unresolved at submit: "
            f"{','.join(unresolved[:5])}"
            + ("..." if len(unresolved) > 5 else "")
        )

    def _render_previous(self, prev: list[dict[str, Any]]) -> str:
        if not prev:
            return ""

        def _trunc(label: str, value: str | None, limit: int | None) -> str | None:
            if not value:
                return None
            s = str(value)
            if limit is None or len(s) <= limit:
                return f"  {label}: {s}"
            kept = s[:limit]
            dropped = len(s) - limit
            return (
                f"  {label}: {kept}\n"
                f"  ...[truncated {dropped:,} more bytes -- re-run with grep/head/tail "
                f"to view more]"
            )

        out: list[str] = []
        last_idx = len(prev) - 1
        for i, s in enumerate(prev):
            is_last = (i == last_idx)
            # The most recent turn is rendered uncut so the agent can
            # act on the freshest evidence. Older turns get a generous
            # per-turn budget (_HISTORY_STDOUT_PER_TURN) instead of the
            # old 600-char cap that was hiding multi-entry log dumps.
            stdout_limit = None if is_last else _HISTORY_STDOUT_PER_TURN
            stderr_limit = None if is_last else 4_000
            reasoning_limit = None if is_last else 2_000

            out.append(
                f"[turn {s.get('step_number', '?')}] "
                f"action={s.get('action', '?')}"
                + ("  (most recent)" if is_last else "")
            )
            line = _trunc("reasoning", s.get("reasoning"), reasoning_limit)
            if line:
                out.append(line)
            line = _trunc("command  ", s.get("command"), 1_000)
            if line:
                out.append(line)
            line = _trunc("script   ", s.get("script_content"), 4_000)
            if line:
                out.append(line)
            if s.get("exit_code") is not None:
                out.append(f"  exit     : {s['exit_code']}")
            line = _trunc("stdout   ", s.get("stdout"), stdout_limit)
            if line:
                out.append(line)
            line = _trunc("stderr   ", s.get("stderr"), stderr_limit)
            if line:
                out.append(line)
        return "\n".join(out)

    def _compose_reasoning(self, turn: dict[str, Any]) -> str:
        """Build the persisted reasoning blob used by the UI and write-up."""
        blob = {
            "reasoning": turn.get("reasoning", ""),
            "expected_observation": turn.get("expected_observation", ""),
            "strategy_family": turn.get("strategy_family", "generic"),
            "contract": turn.get("contract", {}),
            "hypotheses": turn.get("hypotheses", []),
            "rejected": turn.get("rejected", []),
            # Auto-bucketed hypotheses at terminal submit (issue #175).
            # Empty on non-terminal turns; consumers must not treat
            # ``resolved`` as an alternative to ``rejected``.
            "resolved": turn.get("resolved", []),
            "observables": turn.get("observables", {}),
            "evidence_graph": turn.get("evidence_graph", {}),
            "provenance": turn.get("provenance", {}),
            "submitted": bool(turn.get("submitted")),
        }
        try:
            return json.dumps(blob, ensure_ascii=False)[:6000]
        except (TypeError, ValueError):
            return (turn.get("reasoning") or "")[:6000]

    # --------------------------------------------------- execution helpers

    async def _execute_script(self, script_content: str) -> dict[str, Any]:
        """Execute a Python script on the analyzer via ``ScriptExecutorTool``.

        Safety blocklist is applied here; all SSH, temp-file handling, and
        OS dispatch are owned by the tool.
        """
        rejection = _script_rejection(script_content)
        if rejection is not None:
            _log.warning("script blocked for investigation %s: %s", self.investigation_id, rejection)
            return {"stdout": "", "stderr": rejection, "exit_code": 1}

        # Pre-flight syntax check -- catch IndentationError/SyntaxError before
        # wasting an SSH round-trip and a turn on broken Python.
        try:
            compile(script_content, '<investigator_script>', 'exec')
        except SyntaxError as syn_err:
            msg = f'SyntaxError before execution (line {syn_err.lineno}): {syn_err.msg}'
            _log.warning('script syntax error for investigation %s: %s', self.investigation_id, msg)
            return {'stdout': '', 'stderr': msg, 'exit_code': 1}

        # Pre-flight dissect API lint -- catch the top mistakes before SSH.
        _dissect_mistakes = [
            ('Target(', 'Target.open(', 'Use Target.open(path), not Target(path)'),
            ('.rglob(', '.walk(', 'RootFilesystem has no rglob(). Use t.fs.walk() or t.fs.path().iterdir()'),
            ('.get_value(', '.value(', 'RegfKey has no get_value(). Use key.value(name)'),
            ('.iter_values(', '.values()', 'RegfKey has no iter_values(). Use key.values()'),
            ('.get_subkey(', '.subkeys()', 'RegfKey has no get_subkey(). Use key.subkeys()'),
            ('hive.get_key(', 't.registry.key(', 'Do not open raw regf hives. Use t.registry.key(path)'),
            ('RegistryHive(', 't.registry.key(', 'Do not open raw regf hives. Use t.registry.key(path)'),
        ]
        for bad, good, explanation in _dissect_mistakes:
            if bad in script_content and 'Target.open(' not in script_content.split(bad, maxsplit=1)[0][-20:] if bad == 'Target(' else True:
                msg = f'API mistake: found `{bad}` -- {explanation}. Use `{good}` instead.'
                _log.warning('script API lint for investigation %s: %s', self.investigation_id, msg)
                return {'stdout': '', 'stderr': msg, 'exit_code': 1}

        from aila.modules.forensics.tools.script_tool import ScriptExecutorTool

        tool = ScriptExecutorTool(self.settings)
        result = await tool.forward(
            script_content=script_content,
            integration=self.integration,
            analyzer_os=self.analyzer_os,
            timeout_seconds=await _read_float_config("script_execution_timeout_seconds"),
        )
        stdout = _sanitize_for_postgres_text(
            (result.get("stdout") or "")[:_STDOUT_KEEP_BYTES]
        )
        return {
            "stdout": stdout,
            "stderr": _sanitize_for_postgres_text(result.get("stderr") or ""),
            "exit_code": result.get("exit_code", 0),
        }

    async def _execute_command(self, command: str) -> dict[str, Any]:
        """Run a shell command on the analyzer via the platform SSH service.

        The ``_command_rejection`` guard enforces static-analysis-only
        policy: network fetchers (curl, wget, invoke-webrequest),
        transports (ncat, ssh, ftp), scanners (nmap, ping), sample
        detonators (rundll32, mshta, wine) and container launchers are
        refused before they reach SSH.
        """
        rejection = _command_rejection(command)
        if rejection is not None:
            _log.warning("command blocked for investigation %s: %s", self.investigation_id, rejection)
            return {"stdout": "", "stderr": rejection, "exit_code": 1}

        from aila.modules.forensics.tools._ssh_helper import get_ssh_service

        ssh = await get_ssh_service(self.settings)
        try:
            stdout = await ssh.run_command(
                self.integration, command,
                timeout_seconds=await _read_float_config("ssh_command_timeout_seconds"),
            )
            return {
                "stdout": _sanitize_for_postgres_text((stdout or "")[:_STDOUT_KEEP_BYTES]),
                "stderr": "",
                "exit_code": 0,
            }
        except (OSError, TimeoutError, RuntimeError, AILAError) as exc:
            return {
                "stdout": "",
                "stderr": _sanitize_for_postgres_text(str(exc)[:2000]),
                "exit_code": 1,
            }

    # ------------------------------------------------------ context loaders

    async def _load_project_context(self) -> tuple[str, str, str, str | None]:
        """Return ``(evidence_listing, evidence_dir, project_kind, team_id)``."""
        from sqlmodel import select

        from aila.modules.forensics.db_models import (
            ForensicsProjectRecord,
            ProjectEvidenceRecord,
        )
        from aila.platform.uow import UnitOfWork

        async with UnitOfWork() as uow:
            project = (await uow.session.exec(
                select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == self.project_id)
            )).first()
            evidence_rows = (await uow.session.exec(
                select(ProjectEvidenceRecord).where(
                    ProjectEvidenceRecord.project_id == self.project_id
                )
            )).all()

        evidence_dir = project.evidence_directory if project else "/evidence"
        project_kind = project.project_kind if project else "disk_evidence"
        team_id = project.team_id if project else None
        if not evidence_rows:
            return "", evidence_dir, project_kind, team_id
        lines = [
            f"- {r.file_path} ({r.evidence_type}, {r.size_bytes or '?'} bytes)"
            for r in evidence_rows
        ]
        return "\n".join(lines[:80]), evidence_dir, project_kind, team_id

    async def _load_parent_findings(self) -> str | None:
        """Hydrate observables from the parent attempt and render a summary.

        The parent attempt's per-step persistence (see
        ``services.investigation_artifacts``) recorded its findings as
        ``ArtifactRecord`` rows tagged with
        ``source_investigation_id == parent``. Here we:

        1. Read those rows + the parent's ``InvestigationRunRecord``.
        2. Lift each row's ``data`` payload into ``self.observables``
           (skipping the descriptive ``investigation_summary`` row).
        3. Return a compact prompt block that the first turn will see in
           its ``previous`` slot. The block treats the parent's answer as
           a *hypothesis* the new run must verify or refute, never as
           ground truth.

        Returns ``None`` if the parent has nothing to share.
        """
        from sqlmodel import select

        from aila.modules.forensics.db_models import (
            ArtifactRecord,
            InvestigationRunRecord,
        )
        from aila.platform.uow import UnitOfWork

        if not self.parent_investigation_id:
            return None

        async with UnitOfWork() as uow:
            parent = (await uow.session.exec(
                select(InvestigationRunRecord).where(
                    InvestigationRunRecord.id == self.parent_investigation_id
                )
            )).first()
            if parent is None:
                return None

            rows = (await uow.session.exec(
                select(ArtifactRecord).where(
                    ArtifactRecord.source_investigation_id == self.parent_investigation_id
                )
            )).all()

        carried = 0
        finding_lines: list[str] = []
        for r in rows:
            try:
                data = json.loads(r.data_json or "{}")
            except (TypeError, ValueError):
                continue
            if not isinstance(data, dict):
                continue
            if r.artifact_type == "investigation_summary":
                continue
            for k, v in data.items():
                if v in (None, "", [], {}):
                    continue
                if k not in self.observables:
                    self.observables[k] = v
                    carried += 1
            label = r.artifact_type
            preview_parts: list[str] = []
            for k, v in list(data.items())[:4]:
                if v in (None, "", [], {}):
                    continue
                txt = str(v) if not isinstance(v, (list, dict)) else json.dumps(v, default=str)
                if len(txt) > 80:
                    txt = txt[:77] + "..."
                preview_parts.append(f"{k}={txt}")
            if preview_parts:
                finding_lines.append(f"  - {label}: " + ", ".join(preview_parts))

        if carried == 0 and not parent.final_answer and not finding_lines:
            return None

        out: list[str] = []
        out.append(
            f"## PRIOR ATTEMPT ENRICHMENT (parent: {self.parent_investigation_id})"
        )
        out.append(
            f"Parent status: {parent.status}, "
            f"attempts used: {parent.attempts_used}/{parent.max_attempts}"
        )
        if parent.final_answer:
            ans = (parent.final_answer or "").strip().replace("\n", " ")
            if len(ans) > 400:
                ans = ans[:397] + "..."
            out.append(
                f"Parent submitted answer: {ans} "
                f"(confidence: {parent.confidence or 'n/a'})"
            )
        else:
            out.append("Parent did NOT submit an answer.")
        if finding_lines:
            out.append(f"Carried-forward findings ({len(finding_lines)} row(s)):")
            out.extend(finding_lines[:30])
            if len(finding_lines) > 30:
                out.append(f"  ... and {len(finding_lines) - 30} more.")
        out.append(f"({carried} observable(s) hydrated into working memory.)")
        out.append(
            "Treat the parent's answer as a HYPOTHESIS to confirm or refute "
            "with fresh evidence in this run. Do NOT copy it without "
            "re-validation. Avoid re-deriving any carried-forward observable."
        )
        rendered = "\n".join(out)
        if len(rendered) > 4000:
            rendered = rendered[:3997] + "..."
        return rendered

    async def _load_operator_steering(self) -> ReasoningOperatorSteering:
        """Return structured analyst steering for the current turn.

        Project-wide directives apply first, then investigation-scoped ones.
        Structured fields (``strategy_family`` / ``required_artifact``) take
        precedence over legacy text conventions like ``strategy: <family>``.
        """
        from sqlmodel import select

        from aila.modules.forensics.db_models import AnalystDirectiveRecord
        from aila.platform.uow import UnitOfWork

        async with UnitOfWork() as uow:
            stmt = select(AnalystDirectiveRecord).where(
                AnalystDirectiveRecord.project_id == self.project_id,
                AnalystDirectiveRecord.active.is_(True),  # type: ignore[union-attr]
                (AnalystDirectiveRecord.investigation_id.is_(None))  # type: ignore[union-attr]
                | (AnalystDirectiveRecord.investigation_id == self.investigation_id),
            )
            rows = (await uow.session.exec(stmt)).all()
        if not rows:
            return ReasoningOperatorSteering()
        rows_sorted = sorted(rows, key=lambda r: (r.investigation_id is not None, r.created_at))

        steering = ReasoningOperatorSteering()
        for row in rows_sorted:
            scope = "I" if row.investigation_id else "P"
            stamp = row.created_at.strftime("%Y-%m-%d %H:%M") if row.created_at else "?"
            text = (row.text or "").strip().replace("\n", " ")
            if len(text) > 600:
                text = text[:597] + "..."
            line = f"[{scope}] {stamp} -- {text}"
            if row.strategy_family and row.verdict is None:
                steering.pinned_strategy_family = row.strategy_family
            if row.required_artifact and row.verdict is None:
                steering.required_artifacts.append(f"[{scope}] {row.required_artifact}")

            lowered = text.lower()
            if lowered.startswith("strategy:") and row.verdict is None and steering.pinned_strategy_family is None:
                candidate = text.split(":", 1)[1].strip().lower()
                if candidate in {
                    "filesystem_triage",
                    "persistence_hunt",
                    "memory_forensics",
                    "network_forensics",
                    "malware_static",
                    "vulnerability_research",
                    "web_pentest",
                    "mobile_reverse",
                    "generic",
                }:
                    steering.pinned_strategy_family = candidate  # type: ignore[assignment]
                    continue
            if lowered.startswith("artifact:") and row.verdict is None and not row.required_artifact:
                artifact = text.split(":", 1)[1].strip()
                if artifact:
                    steering.required_artifacts.append(f"[{scope}] {artifact}")
                    continue
            if row.verdict == "true":
                steering.confirmed_facts.append(line)
            elif row.verdict == "false":
                steering.disproved_hypotheses.append(line)
            else:
                steering.guidance.append(line)
        return steering

    async def _snapshot_artifacts(self) -> str:
        """Compact artefact snapshot for prompt injection.

        Unlike the old agent, this function does NOT inject CTF-shaped
        keywords (``win_apis``, ``telegram_overlay_root``, …). It emits a
        neutral shape: family -> type -> top records -> key=value fields.
        """
        from sqlmodel import select

        from aila.modules.forensics.db_models import ArtifactRecord, LeadRecord
        from aila.platform.uow import UnitOfWork

        async with UnitOfWork() as uow:
            artifacts = (await uow.session.exec(
                select(ArtifactRecord)
                .where(ArtifactRecord.project_id == self.project_id)
                .order_by(ArtifactRecord.lead_score.desc())
                .limit(60)
            )).all()
            leads = (await uow.session.exec(
                select(LeadRecord)
                .where(LeadRecord.project_id == self.project_id)
                .order_by(LeadRecord.score.desc())
                .limit(10)
            )).all()

        if not artifacts and not leads:
            return ""

        sections: list[str] = []

        if leads:
            sections.append("== LEADS (highest score) ==")
            for lead in leads:
                sections.append(
                    f"  [lead:{lead.id}] family={lead.artifact_family} score={lead.score:.0f} reason={lead.reason[:200]}"
                )

        by_family: dict[str, list[ArtifactRecord]] = {}
        for art in artifacts:
            by_family.setdefault(art.artifact_family or "unknown", []).append(art)

        for family, arts in sorted(by_family.items(), key=lambda x: -max((a.lead_score or 0) for a in x[1])):
            sections.append(f"\n== {family.upper()} ({len(arts)} artefacts) ==")
            for art in arts[:8]:
                try:
                    data = json.loads(art.data_json) if art.data_json else {}
                except (json.JSONDecodeError, TypeError):
                    data = {}
                head = f"  [art:{art.id}] type={art.artifact_type} score={art.lead_score or 0:.0f}"
                if isinstance(data, dict):
                    flat: list[str] = []
                    for k, v in list(data.items())[:8]:
                        if k.startswith("_"):
                            continue
                        if v in (None, "", [], {}):
                            continue
                        if isinstance(v, (list, dict)):
                            rendered = json.dumps(v, default=str)[:140]
                        else:
                            rendered = str(v)[:140]
                        flat.append(f"{k}={rendered}")
                    if flat:
                        head = head + " | " + " | ".join(flat)
                sections.append(head)
                if isinstance(data, dict):
                    records = data.get("records")
                    if isinstance(records, list):
                        real = [r for r in records if isinstance(r, dict) and r.get("_type") != "recorddescriptor"]
                        for rec in real[:6]:
                            pairs = [
                                f"{k}={str(v)[:120]}"
                                for k, v in list(rec.items())[:6]
                                if not k.startswith("_") and v not in (None, "", [], {})
                            ]
                            if pairs:
                                sections.append("    - " + " | ".join(pairs))

        return "\n".join(sections)[:18_000]
