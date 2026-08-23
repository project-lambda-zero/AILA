"""liveness_guard -- AST guard for the single task-liveness authority.

Background
----------
Task liveness (is this run still alive, has a turn run too long, should it
be requeued, should its checkpoint cursor be dropped) used to be decided
independently by five different places: the ARQ per-job timeout, the
workflow engine's per-state wall, the heartbeat reaper, the boot orphan
sweep, and the state reconciler. Independent kill/requeue decisions raced
each other -- a live turn got reaped as a zombie, a resumable cursor got
deleted before the requeue path saw it, a timeout crashed a run to a
NON-resumable terminal that the requeue path then refused to touch. The
run went idle with real work stranded.

The fix (§91) makes the workflow ENGINE the single authority for turn
liveness: a per-state wall that RESUMES the state on expiry instead of
crashing it (``StateSpec.timeout_retriable``), an ARQ job wall that sits
strictly ABOVE the engine wall so ARQ never truncates a turn first, and a
reconciler that only ever re-enqueues a resumable cursor (never deletes
one for a liveness reason). The remaining kill / requeue / cursor-delete
primitives live in a small, CLOSED set of authority modules.

What this guard enforces
------------------------
The liveness-decision PRIMITIVES below may appear ONLY inside the
allowlisted authority modules. Any occurrence in another ``src/aila`` file
fails the build. This makes "the authority is a closed surface" a
mechanical invariant instead of a convention: adding a sixth place that
kills or requeues a run requires deliberately editing this allowlist,
which is a visible, reviewable act.

Guarded primitives
- ``raise Retry(...)`` / ``raise arq.Retry(...)`` -- an ARQ requeue decision.
- a call to ``requeue_same_job_id(...)``          -- the resume primitive.
- a call to ``<x>._delete_cursor(...)``           -- checkpoint-cursor kill.
- a SQLAlchemy ``delete(WorkflowStateCursor)``     -- checkpoint-cursor kill.
- raw SQL ``DELETE FROM workflow_state_cursor``    -- checkpoint-cursor kill.
- ``closed_reason="stale_no_progress..."`` outside BRANCH_GC_FILES -- a
  branch stale-abandon decider that is not the sanctioned one.
- a BRANCH_GC_FILES module that does NOT import the shared liveness
  predicate -- a sanctioned decider judging liveness on its own.

The branch-GC rules exist because the stale-branch abandon sweep and the
persona-spawn hard-delete were a SECOND and THIRD independent liveness
decider: they abandoned / deleted a branch mid-turn on ``turn_count`` /
``updated_at``, both of which stay frozen for the whole of a long turn on
a slow node. Routing every branch-GC decider through
``aila.platform.tasks.liveness`` collapses them into the one authority.

Non-goals
- I/O timeouts (``timeout_seconds=``, ``asyncio.wait_for`` on an SSH / HTTP
  / poll call) are NOT liveness decisions and are NOT flagged. This guard
  is deliberately narrow so it produces zero false positives on the
  current tree; a broad ``timeout=`` ban would flag hundreds of legitimate
  I/O deadlines.

Usage
-----
    python -m aila.tools.liveness_guard src/aila

Exits 0 when the authority surface is intact, 1 (with a report) when a
guarded primitive leaked outside it. No dependencies beyond stdlib.
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass
from pathlib import Path

__all__ = ["AUTHORITY_FILES", "Finding", "scan_path", "main"]

# The CLOSED set of modules permitted to make liveness kill / requeue /
# cursor-delete decisions. Paths are POSIX-relative to the scan root's
# repository (matched by suffix so the scan root may be given as
# ``src/aila`` or an absolute path). Adding a file here is the ONLY
# sanctioned way to grow the authority surface, and it must be a reviewed
# change -- that review IS the point of this guard.
AUTHORITY_FILES: frozenset[str] = frozenset({
    # The engine owns the per-state wall and the retriable-timeout resume.
    "aila/platform/workflows/engine.py",
    # The @platform_task wrapper owns the conflict-retry re-raise.
    "aila/platform/tasks/template.py",
    # The one "run this checkpointed job again" primitive lives here.
    "aila/platform/tasks/queue.py",
    # The periodic reaper of orphaned / terminal cursors.
    "aila/platform/tasks/cursor_reaper.py",
    # The on-demand + periodic drift reconciler.
    "aila/platform/tasks/state_reconciler.py",
    # The operator-facing pause / resume / re-enqueue lifecycle service.
    "aila/platform/services/investigation_lifecycle.py",
})

# The CLOSED set of modules sanctioned to make a branch garbage-collection
# decision (abandon a stale branch, or hard-delete a zero-turn loser).
# Each MUST consult the shared liveness predicate in
# ``aila.platform.tasks.liveness`` so a branch that is mid-turn on a slow
# node is never abandoned or deleted on the lying ``turn_count`` /
# ``updated_at`` signals. Growing this set is a reviewed act -- that review
# IS the point of this guard.
BRANCH_GC_FILES: frozenset[str] = frozenset({
    "aila/platform/workflows/persona_spawn.py",
    "aila/platform/services/investigation_finalizers.py",
})

# The single "is a turn in flight" predicate module + its public
# predicates. A branch-GC decider that does not import from it is deciding
# liveness on its own, which is the exact bug this guard prevents.
_LIVENESS_MODULE_SUFFIX = "tasks.liveness"
_LIVENESS_PREDICATES = frozenset({
    "live_investigation_ids",
    "branch_has_live_task",
    "investigation_has_live_task",
})

# The stale-timeout branch-abandon reason token. A ``closed_reason=`` set
# to this value is an automated liveness decision and belongs only in a
# BRANCH_GC_FILES module that consults the predicate above. Matched on the
# closed_reason keyword specifically (not raw text) so a classifier that
# merely NAMES the pseudo-class (resilience.py) is not a false positive.
_STALE_ABANDON_TOKEN = "stale_no_progress"

# Substring matched against raw source (module.py + tests are skipped by the
# walker, so this only sees production files).
_RAW_SQL_CURSOR_DELETE = "DELETE FROM workflow_state_cursor"

_CURSOR_MODEL_NAME = "WorkflowStateCursor"
_REQUEUE_FN = "requeue_same_job_id"
_DELETE_CURSOR_METHOD = "_delete_cursor"

# This guard names the guarded primitives in its own source (constants +
# docstring), so it must exempt itself or it would flag every detection
# string as a violation.
_SELF = "aila/tools/liveness_guard.py"


@dataclass(frozen=True)
class Finding:
    """One guarded primitive found outside the authority surface."""

    path: str
    line: int
    primitive: str
    detail: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: {self.primitive} -- {self.detail}"


def _rel_posix(path: Path, root: Path) -> str:
    """Return ``path`` relative to the repo, as a POSIX string.

    The scan ``root`` may be ``src/aila`` (or an absolute path to it); the
    allowlist is written as ``aila/...`` suffixes, so anchor on the ``aila``
    package directory when it is present and fall back to the raw relative
    path otherwise.
    """
    resolved = path.resolve()
    parts = resolved.parts
    if "aila" in parts:
        idx = len(parts) - 1 - parts[::-1].index("aila")
        return "/".join(parts[idx:])
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _is_retry_raise(node: ast.Raise) -> bool:
    """True when ``node`` is ``raise Retry(...)`` / ``raise arq.Retry(...)``."""
    exc = node.exc
    if isinstance(exc, ast.Call):
        exc = exc.func
    if isinstance(exc, ast.Name):
        return exc.id == "Retry"
    if isinstance(exc, ast.Attribute):
        return exc.attr == "Retry"
    return False


def _call_name(node: ast.Call) -> str | None:
    """Return the bare callee name for ``foo(...)`` / ``obj.foo(...)``."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _delete_targets_cursor(node: ast.Call) -> bool:
    """True when ``node`` is ``delete(WorkflowStateCursor)`` (SQLAlchemy)."""
    if _call_name(node) not in {"delete", "_delete"}:
        return False
    for arg in node.args:
        if isinstance(arg, ast.Name) and arg.id == _CURSOR_MODEL_NAME:
            return True
        if isinstance(arg, ast.Attribute) and arg.attr == _CURSOR_MODEL_NAME:
            return True
    return False


def _imports_liveness_predicate(tree: ast.Module) -> bool:
    """True when the module imports the shared liveness predicate.

    Accepts ``from aila.platform.tasks.liveness import <predicate>``,
    ``from ...tasks import liveness``, or a bare
    ``import aila.platform.tasks.liveness`` -- any form that puts the
    single "is a turn in flight" authority in the module's hands.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.endswith(_LIVENESS_MODULE_SUFFIX):
                return True
            if any(alias.name in _LIVENESS_PREDICATES for alias in node.names):
                return True
            if any(alias.name == "liveness" for alias in node.names):
                return True
        elif isinstance(node, ast.Import) and any(
            alias.name.endswith(_LIVENESS_MODULE_SUFFIX)
            for alias in node.names
        ):
            return True
    return False


def _is_stale_abandon_keyword(node: ast.keyword) -> bool:
    """True when ``node`` is ``closed_reason=<stale-timeout reason>``.

    Detects both the plain ``closed_reason="stale_no_progress..."`` and the
    f-string ``closed_reason=f"stale_no_progress_{n}min"`` forms. Keyed on
    the ``closed_reason`` keyword so a module that merely references the
    reason string as a classifier key is not flagged -- only an actual
    branch-abandon value assignment is.
    """
    if node.arg != "closed_reason":
        return False
    value = node.value
    parts: list[str] = []
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        parts.append(value.value)
    elif isinstance(value, ast.JoinedStr):
        parts.extend(
            part.value
            for part in value.values
            if isinstance(part, ast.Constant) and isinstance(part.value, str)
        )
    return any(_STALE_ABANDON_TOKEN in part for part in parts)


def _scan_source(rel: str, source: str) -> list[Finding]:
    """Return every guarded primitive in one file's source text.

    A file that does not parse is NOT reported as a violation here -- the
    ``compile`` gate (``python -m compileall``) owns syntax errors. We still
    run the raw-SQL text scan on it, so a cursor delete hidden in an
    otherwise-unparseable file is not missed.
    """
    findings: list[Finding] = []
    try:
        tree: ast.Module | None = ast.parse(source)
    except SyntaxError:
        tree = None

    for node in ast.walk(tree) if tree is not None else ():
        if isinstance(node, ast.Raise) and _is_retry_raise(node):
            findings.append(Finding(
                rel, node.lineno, "raise Retry",
                "ARQ requeue decision outside the liveness authority; "
                "the engine / @platform_task wrapper owns retry re-raises",
            ))
        elif isinstance(node, ast.Call):
            name = _call_name(node)
            if name == _REQUEUE_FN:
                findings.append(Finding(
                    rel, node.lineno, f"{_REQUEUE_FN}()",
                    "resume/requeue decision outside the liveness authority; "
                    "route through the reconciler",
                ))
            elif name == _DELETE_CURSOR_METHOD:
                findings.append(Finding(
                    rel, node.lineno, f"{_DELETE_CURSOR_METHOD}()",
                    "checkpoint-cursor delete outside the liveness authority",
                ))
            elif _delete_targets_cursor(node):
                findings.append(Finding(
                    rel, node.lineno, f"delete({_CURSOR_MODEL_NAME})",
                    "checkpoint-cursor delete outside the liveness authority",
                ))
        elif (
            isinstance(node, ast.keyword)
            and _is_stale_abandon_keyword(node)
            and rel not in BRANCH_GC_FILES
        ):
            findings.append(Finding(
                rel, node.value.lineno, "branch stale-abandon",
                "stale-timeout branch abandon outside the sanctioned "
                "branch-GC deciders; a branch mid-turn would be abandoned on "
                "turn_count/updated_at. Route it through a BRANCH_GC_FILES "
                "module that consults aila.platform.tasks.liveness",
            ))

    # A sanctioned branch-GC decider MUST consult the shared liveness
    # predicate; without it the decider is judging liveness on turn_count /
    # updated_at, which lie during a long turn. (Skip when the file did not
    # parse -- the compile gate owns syntax errors.)
    if (
        tree is not None
        and rel in BRANCH_GC_FILES
        and not _imports_liveness_predicate(tree)
    ):
        findings.append(Finding(
            rel, 1, "branch-GC decider missing liveness predicate",
            "abandons / hard-deletes branches but does not import the shared "
            "liveness predicate from aila.platform.tasks.liveness; a branch "
            "mid-turn would be GC'd on turn_count/updated_at",
        ))

    # Raw-SQL cursor deletes never parse into the calls above; scan text.
    if _RAW_SQL_CURSOR_DELETE in source:
        for i, text in enumerate(source.splitlines(), start=1):
            if _RAW_SQL_CURSOR_DELETE in text:
                findings.append(Finding(
                    rel, i, "raw SQL cursor delete",
                    "checkpoint-cursor delete outside the liveness authority",
                ))
    return findings


def scan_path(root: Path) -> list[Finding]:
    """Scan every production ``.py`` under ``root`` outside the authority."""
    findings: list[Finding] = []
    for path in sorted(root.rglob("*.py")):
        parts = path.parts
        if "tests" in parts or "alembic" in parts or "__pycache__" in parts:
            continue
        rel = _rel_posix(path, root)
        if rel in AUTHORITY_FILES or rel == _SELF:
            continue
        try:
            # utf-8-sig strips a leading BOM so BOM-prefixed sources (some
            # legacy module files carry one) parse cleanly.
            source = path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError):
            continue
        findings.extend(_scan_source(rel, source))
    return findings


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    root = Path(args[0]) if args else Path("src/aila")
    if not root.exists():
        print(f"liveness_guard: path not found: {root}", file=sys.stderr)
        return 2
    findings = scan_path(root)
    if not findings:
        print(
            "liveness_guard: authority surface intact "
            f"({len(AUTHORITY_FILES)} authorized modules); no leaked "
            "kill/requeue/cursor-delete primitives.",
        )
        return 0
    print(
        f"liveness_guard: {len(findings)} liveness-decision primitive(s) "
        "found OUTSIDE the authority surface:",
        file=sys.stderr,
    )
    for f in findings:
        print(f"  {f.render()}", file=sys.stderr)
    print(
        "\nEach of these makes an independent task-liveness decision. Move "
        "it into an authority module (see AUTHORITY_FILES) or delete it. If "
        "a new module genuinely must own liveness, add it to AUTHORITY_FILES "
        "in a reviewed change.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
