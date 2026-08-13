"""liveness_audit -- static reachability auditor for AILA.

Complements :mod:`aila.tools.honesty_audit`: honesty flags structural
dishonesty inside a single file. Liveness flags dead paths ACROSS the
tree -- capabilities that are declared, honest, and unreached by any
live caller. The peer review's #1 finding class is exactly this
"wired-but-dead" shape (RFC-208), and two real bugs of that shape
shipped in the current program:

* #104: a ConfigRegistry threshold key was promoted from
  :class:`CalibrationProposalRecord` and stored under
  ``platform.calibration_threshold_{outcome_kind}``, but the LLM
  pipeline gate never read it. Honesty passed; the promotion did
  nothing.
* #135: :class:`VRInvestigationRecord.cost_actual_usd` had no writer.
  Honesty passed; every budget gauge read a permanent $0.

Precision over recall
---------------------

A noisy static auditor is worse than none. Every rule below is written
to over-collect the coverage side (reads for R1, writes for R3) so a
grep for the key/column name anywhere in the tree clears the finding.
The tradeoff is deliberate: false negatives are the price, false
positives are the enemy. Truly dynamic lookups (env-var + concat,
operator-supplied keys in a request body, dict-splatted kwargs) are
invisible to the AST on both sides and belong in the ``--whitelist``
file with a one-line reason.

Rules
-----

R1 ``unread_config_key``
    A ConfigRegistry key that is WRITTEN (declared as a field on any
    ``*ConfigSchema`` model, declared as a ``DynamicKeyFamily`` prefix,
    or passed as the key argument to a ``.set(namespace, key, value)``
    call) but for which NO ``.get(...)`` / ``.get_int(...)`` /
    ``.get_float(...)`` / ``.get_str(...)`` / ``.get_bool(...)`` /
    ``.get_typed(...)`` / ``.get_sync(...)`` read exists anywhere under
    ``src/aila``. Dynamic-suffix keys ("prefix families") are handled
    by prefix-matching on both sides: a templated read
    ``registry.get(ns, f"prefix_{x}")`` covers every written literal
    beginning with ``prefix_``, and a literal read ``ns.prefix_llm_ok``
    covers a written family whose prefix is ``prefix_``.

R3 ``unwritten_column``
    A SQLModel ``table=True`` column that is never the target of an
    attribute assignment, a constructor keyword, or an
    ``update(...).values(col=...)`` clause anywhere under
    ``src/aila``. Excluded from the checked set:

    * primary-key columns (``Field(primary_key=True)`` or the bare
      ``id`` name);
    * foreign-key columns (``Field(foreign_key=...)``);
    * auto-managed timestamps (``created_at`` / ``updated_at``);
    * columns with a Postgres ``server_default=...`` (the DB fills
      them at insert time).

Whitelist file (``--whitelist <path>``)
---------------------------------------

Same shape as :mod:`aila.tools.honesty_audit`'s whitelist: a top-level
``LIVENESS_WHITELIST`` list literal of 3-element string tuples
``(path_or_key, rule, reason)``. A finding is suppressed when its
``rule`` matches AND its message contains both the ``path_or_key`` and
the ``reason`` substrings. The loose match lets one entry cover a
whole family (all reads through one indirection helper) without
demanding a per-line pin.
"""

from __future__ import annotations

import ast
import logging
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

_log = logging.getLogger(__name__)

__all__ = [
    "Finding",
    "LivenessAuditor",
    "RULE_REGISTRY",
    "TreeIndex",
    "Whitelist",
    "load_whitelist",
]


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    """A single liveness finding.

    ``location`` is a human-readable pointer -- a ``path:line`` when the
    write site is known, otherwise a synthetic key like the column's
    fully qualified name. ``message`` always contains the offending
    identifier (key name / column name) so the whitelist's substring
    match is unambiguous.
    """

    rule: str
    location: str
    message: str


Whitelist = set[tuple[str, str, str]]


# ---------------------------------------------------------------------------
# Whitelist loading
# ---------------------------------------------------------------------------


def load_whitelist(path: Path) -> Whitelist:
    """Parse *path* and return the set of ``(path_or_key, rule, reason)`` triples.

    The file must define a top-level ``LIVENESS_WHITELIST`` list literal
    of 3-element string tuples. Non-tuple entries are silently skipped
    (mirrors :func:`aila.tools.honesty_audit.load_whitelist`).
    """
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))

    result: Whitelist = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets = node.targets
            raw_value: ast.expr | None = node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
            raw_value = node.value
        else:
            continue
        for target in targets:
            if not (isinstance(target, ast.Name) and target.id == "LIVENESS_WHITELIST"):
                continue
            value = raw_value
            if not isinstance(value, ast.List):
                continue
            for elt in value.elts:
                if not (
                    isinstance(elt, ast.Tuple)
                    and len(elt.elts) == 3
                    and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in elt.elts)
                ):
                    continue
                triple = tuple(e.value for e in elt.elts)  # type: ignore[union-attr]
                result.add(triple)  # type: ignore[arg-type]
    return result


# ---------------------------------------------------------------------------
# Tree index
# ---------------------------------------------------------------------------


# Paths (as forward-slash suffixes) excluded from BOTH the write and read
# corpora. Alembic migrations define columns without app-writing them and
# reference config keys in string literals we never resolve; the audit
# tools themselves mention every key/column in string form. Including any
# of these files would corrupt the coverage sets in both directions.
_EXCLUDE_PATH_SUFFIXES: tuple[str, ...] = (
    "/aila/tools/honesty_audit.py",
    "/aila/tools/liveness_audit.py",
)
_EXCLUDE_PATH_TOKENS: tuple[str, ...] = (
    "/aila/alembic/",
    "/__pycache__/",
)


@dataclass
class TreeIndex:
    """Parsed ``.py`` files under a scan root, keyed by resolved path."""

    root: Path
    files: dict[Path, ast.Module] = field(default_factory=dict)

    @classmethod
    def build(cls, root: Path) -> TreeIndex:
        idx = cls(root=root)
        for py in sorted(root.rglob("*.py")):
            normalized = str(py).replace("\\", "/")
            if any(normalized.endswith(sfx) for sfx in _EXCLUDE_PATH_SUFFIXES):
                continue
            if any(tok in normalized for tok in _EXCLUDE_PATH_TOKENS):
                continue
            try:
                source = py.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                _log.debug("liveness_audit: unreadable file %s", py)
                continue
            try:
                tree = ast.parse(source, filename=str(py))
            except SyntaxError:
                _log.debug("liveness_audit: syntax error in %s", py)
                continue
            idx.files[py] = tree
        return idx


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def _string_constant(node: ast.expr | None) -> str | None:
    """Return the string value of a ``Constant``, else ``None``."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _fstring_prefix(node: ast.expr | None) -> str | None:
    """Return the leading literal segment of an ``f"..."`` up to the first
    interpolation.

    ``f"calibration_threshold_{outcome_kind}"`` returns
    ``"calibration_threshold_"``; ``f"{x}_suffix"`` returns ``""``;
    a non-JoinedStr returns ``None``.
    """
    if not isinstance(node, ast.JoinedStr):
        return None
    if not node.values:
        return ""
    head = node.values[0]
    if isinstance(head, ast.Constant) and isinstance(head.value, str):
        return head.value
    # Interpolation-first (``f"{x}_foo"``): the prefix is empty. Return "" so
    # the caller can decide to skip empty prefixes at coverage time.
    return ""


def _callee_attr(node: ast.Call) -> str | None:
    """Return the terminal attribute name of a ``Call``'s callee (``foo.bar()``
    yields ``"bar"``; ``foo()`` yields ``None``)."""
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _classdef_is_table(node: ast.ClassDef) -> bool:
    """Return True when a class is declared with the SQLModel ``table=True`` flag."""
    for kw in node.keywords:
        if (
            kw.arg == "table"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is True
        ):
            return True
    return False


def _classdef_base_names(node: ast.ClassDef) -> set[str]:
    """Return the simple names of a class's declared bases."""
    names: set[str] = set()
    for b in node.bases:
        if isinstance(b, ast.Name):
            names.add(b.id)
        elif isinstance(b, ast.Attribute):
            names.add(b.attr)
    return names


# Base-name markers that identify a SQLModel table-record class. A class
# with ``table=True`` normally already qualifies, but the check on the
# base list catches the rare intermediate-base case (an internal Base
# class that other tables subclass) without misfiring on random plain
# Pydantic models.
_SQLMODEL_BASE_MARKERS: frozenset[str] = frozenset({
    "SQLModel", "TeamScopedMixin",
})


# Base-name / class-name markers for ConfigRegistry-managed schemas.
# ``BaseModel`` is deliberately absent: nearly every Pydantic contract in
# the tree subclasses it, and treating every such class as a config
# schema would flag every DTO field as a "config key" -- an 800-finding
# wall of false positives that would render R1 useless. The real
# ConfigRegistry-managed schemas either (a) end in ``ConfigSchema`` or
# (b) subclass :class:`aila.platform.config_base.ModuleConfigBase`, both
# of which the two markers below catch.
_CONFIG_SCHEMA_BASE_MARKERS: frozenset[str] = frozenset({
    "ModuleConfigBase",
})
_CONFIG_SCHEMA_NAME_SUFFIX: str = "ConfigSchema"


# Read-side coverage is DELIBERATELY broad (over-collection on this side is
# strictly safe for R1: it only shrinks the finding set). Every string
# literal that appears as an argument to any Call node, plus every
# ``Attribute`` load (``self.config.<field>``), plus every module-level
# ``NAME = "literal"`` constant used as an arg, feeds the coverage set.
# The old ``_CONFIG_READ_METHODS`` gate was too narrow -- genuine reads
# often go through helper wrappers whose callee terminal name is not
# ``get`` (``_cfg_from_resolved(resolved, "user_agent", ...)``) OR
# resolve the key through a module-level constant
# (``registry.get(CONFIG_NS_PLATFORM, CONFIG_KEY_REDIS_URL)``).

# Write-side method name. ``.set(ns, key, value)`` is the ConfigRegistry
# writer shape; a 3-positional call whose second arg is a string is the
# discriminator. A 2-arg ``.set(key, value)`` on some other API is
# indistinguishable from a config write with a stringly-named key; we
# accept a 2-arg shape too so a wrapper like
# ``config_writer.set(key, value)`` is caught. See the receiver-token
# filter below.
_CONFIG_WRITE_METHOD: str = "set"
_CONFIG_RECEIVER_TOKENS: tuple[str, ...] = (
    "registry", "config", "settings", "cfg",
)


# R3 column-exclusion policy.
_COLUMN_AUTO_MANAGED_NAMES: frozenset[str] = frozenset({
    "id", "created_at", "updated_at",
})


# ---------------------------------------------------------------------------
# R1: config-key coverage
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _WrittenConfigKey:
    """One written key + its source site for the finding message."""

    text: str          # the literal key OR the family prefix
    is_prefix: bool    # True when the key is a DynamicKeyFamily prefix
    location: str      # ``path:line`` for the finding message
    origin: str        # short tag: "schema" | "family" | "set-call"


def _receiver_name_chain(node: ast.expr) -> list[str]:
    """Return the identifier chain of an attribute expression.

    ``self.registry.set`` -> ``["self", "registry", "set"]``.
    Anything else -> ``[]``.
    """
    chain: list[str] = []
    cur: ast.expr | None = node
    while cur is not None:
        if isinstance(cur, ast.Attribute):
            chain.append(cur.attr)
            cur = cur.value
        elif isinstance(cur, ast.Name):
            chain.append(cur.id)
            break
        else:
            break
    return list(reversed(chain))


def _is_config_receiver(chain: list[str]) -> bool:
    """Return True when the receiver chain looks like a ConfigRegistry-family
    binding (contains ``registry`` / ``config`` / ``settings`` / ``cfg``)."""
    joined = "_".join(part.lower() for part in chain)
    return any(tok in joined for tok in _CONFIG_RECEIVER_TOKENS)


def _collect_written_config_keys(
    tree: ast.Module, path: Path,
) -> list[_WrittenConfigKey]:
    """Collect every WRITE-side config key in a single parsed file.

    Three shapes covered:

    * A class whose name ends ``ConfigSchema`` OR whose bases include
      ``ModuleConfigBase`` / ``BaseModel``: every annotated field name is a
      written literal key.
    * A ``DynamicKeyFamily(<prefix>, ...)`` call: the string prefix is a
      written family.
    * A ``<receiver>.set(namespace, key, value)`` call where the receiver
      chain contains ``registry`` / ``config`` / ``settings`` / ``cfg``,
      or a ``.set(key, value)`` on the same shape.
    """
    out: list[_WrittenConfigKey] = []

    # (1) Schema class fields.
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        base_names = _classdef_base_names(node)
        matches_schema = (
            node.name.endswith(_CONFIG_SCHEMA_NAME_SUFFIX)
            or bool(base_names & _CONFIG_SCHEMA_BASE_MARKERS)
        )
        if not matches_schema:
            continue
        for stmt in node.body:
            if not isinstance(stmt, ast.AnnAssign):
                continue
            if not isinstance(stmt.target, ast.Name):
                continue
            field_name = stmt.target.id
            if field_name.startswith("__"):
                continue
            out.append(_WrittenConfigKey(
                text=field_name,
                is_prefix=False,
                location=f"{path}:{stmt.lineno}",
                origin="schema",
            ))

    # (2) DynamicKeyFamily(prefix, ...) calls.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee = node.func
        callee_name = (
            callee.id if isinstance(callee, ast.Name)
            else callee.attr if isinstance(callee, ast.Attribute)
            else None
        )
        if callee_name != "DynamicKeyFamily":
            continue
        # Positional or ``prefix=`` keyword.
        prefix_value: ast.expr | None = None
        if node.args:
            prefix_value = node.args[0]
        for kw in node.keywords:
            if kw.arg == "prefix":
                prefix_value = kw.value
                break
        prefix = _string_constant(prefix_value)
        if prefix is None:
            continue
        out.append(_WrittenConfigKey(
            text=prefix,
            is_prefix=True,
            location=f"{path}:{node.lineno}",
            origin="family",
        ))

    # (3) <receiver>.set(...) calls.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _callee_attr(node) != _CONFIG_WRITE_METHOD:
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        chain = _receiver_name_chain(node.func.value)
        if not _is_config_receiver(chain):
            continue
        # Prefer the (ns, key, value) shape: 3 positional args, take index 1.
        # Otherwise (key, value): 2 positional args, take index 0.
        key_node: ast.expr | None = None
        if len(node.args) >= 3:
            key_node = node.args[1]
        elif len(node.args) == 2:
            key_node = node.args[0]
        # ``key=`` kwarg overrides positional (rare but keep it safe).
        for kw in node.keywords:
            if kw.arg == "key":
                key_node = kw.value
                break
        if key_node is None:
            continue
        lit = _string_constant(key_node)
        if lit is not None:
            out.append(_WrittenConfigKey(
                text=lit,
                is_prefix=False,
                location=f"{path}:{node.lineno}",
                origin="set-call",
            ))
            continue
        prefix = _fstring_prefix(key_node)
        if prefix:
            out.append(_WrittenConfigKey(
                text=prefix,
                is_prefix=True,
                location=f"{path}:{node.lineno}",
                origin="set-call",
            ))
    return out


def _collect_module_string_constants(tree: ast.Module) -> dict[str, str]:
    """Return every top-level ``NAME = "..."`` string constant in a module.

    Handles both ``NAME = "x"`` and ``NAME: str = "x"``. Nested / conditional
    assignments are intentionally out of scope -- the goal is only to unwrap
    the widespread ``CONFIG_KEY_* = "raw_key_name"`` idiom so a
    ``registry.get(NS, CONFIG_KEY_REDIS_URL)`` call resolves to the key
    ``"redis_url"`` at coverage time.
    """
    out: dict[str, str] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign):
            value_node = stmt.value
            targets = [t for t in stmt.targets if isinstance(t, ast.Name)]
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            value_node = stmt.value
            targets = [stmt.target] if isinstance(stmt.target, ast.Name) else []
        else:
            continue
        text = _string_constant(value_node)
        if text is None:
            continue
        for tgt in targets:
            out[tgt.id] = text
    return out


def _collect_write_site_subtree_ids(tree: ast.Module) -> set[int]:
    """Return the ``id()`` of every AST node that lives INSIDE a WRITE-site
    call (``DynamicKeyFamily(...)`` or a ``<receiver>.set(...)`` on a
    config-shaped receiver).

    The READ pass excludes any string constant / f-string reachable
    through one of these ids so a write's own string literal is not
    counted as its own read (that would defeat R1 entirely).
    """
    excluded: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callee_terminal = (
            node.func.id if isinstance(node.func, ast.Name)
            else node.func.attr if isinstance(node.func, ast.Attribute)
            else None
        )
        is_write = False
        if callee_terminal == "DynamicKeyFamily":
            is_write = True
        elif callee_terminal == _CONFIG_WRITE_METHOD and isinstance(
            node.func, ast.Attribute,
        ):
            chain = _receiver_name_chain(node.func.value)
            is_write = _is_config_receiver(chain)
        if not is_write:
            continue
        for sub in ast.walk(node):
            excluded.add(id(sub))
    return excluded


def _collect_read_config_key_corpus(
    tree: ast.Module,
    constants: dict[str, str],
) -> tuple[set[str], set[str]]:
    """Return ``(literal_reads, prefix_reads)`` for a single parsed file.

    Read shapes recognised (deliberately broad -- over-collection here is
    strictly safe for R1):

    * Every ``Attribute`` load anywhere in the file
      (``self.config.nvd_min_interval_seconds``, ``settings.redis_url``).
      Modules commonly bind a config schema instance and read fields as
      plain attributes rather than through ``ConfigRegistry.get``.
    * Every string ``Constant`` node anywhere in the tree that is NOT
      inside a WRITE-site call (see
      :func:`_collect_write_site_subtree_ids`). This covers key names
      that appear in tuples (``for key in (f"llm_..._{tt}", "llm_...")``),
      dict-literal keys used at runtime, docstring mentions, and every
      other lexical shape where the key text lives verbatim in the
      source. False positives on the READ side strictly shrink the
      finding set; they never inflate it.
    * Every ``JoinedStr`` (f-string) contributes its constant leading
      prefix to :attr:`prefix_reads`. A templated read
      ``f"calibration_threshold_{outcome_kind}"`` covers every write
      whose literal begins with ``calibration_threshold_``.
    * Every ``Name`` used as a call argument whose ``id`` resolves via
      the module-level *constants* map to a string. This is the
      ``registry.get(NS, CONFIG_KEY_REDIS_URL)`` idiom -- the key text
      lives in a top-level ``CONFIG_KEY_REDIS_URL = "redis_url"``.
    """
    excluded_ids = _collect_write_site_subtree_ids(tree)
    literals: set[str] = set()
    prefixes: set[str] = set()
    for node in ast.walk(tree):
        node_id = id(node)
        if node_id in excluded_ids:
            continue
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
            literals.add(node.attr)
            continue
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            literals.add(node.value)
            continue
        if isinstance(node, ast.JoinedStr):
            pfx = _fstring_prefix(node)
            if pfx:
                prefixes.add(pfx)
            continue
        if isinstance(node, ast.Call):
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    resolved = constants.get(arg.id)
                    if resolved is not None:
                        literals.add(resolved)
            for kw in node.keywords:
                if isinstance(kw.value, ast.Name):
                    resolved = constants.get(kw.value.id)
                    if resolved is not None:
                        literals.add(resolved)
    return literals, prefixes


def _config_key_is_covered(
    written: _WrittenConfigKey,
    literal_reads: set[str],
    prefix_reads: set[str],
) -> bool:
    """Return True when *written* is covered by some read in the corpus."""
    if written.is_prefix:
        p = written.text
        if any(lit.startswith(p) for lit in literal_reads):
            return True
        # A read-side prefix that overlaps our write-side prefix in either
        # direction (read prefix broader, or equal to / narrower than us)
        # counts as coverage of the family.
        return any(
            (rp.startswith(p) or p.startswith(rp)) and rp != ""
            for rp in prefix_reads
        )
    lit = written.text
    if lit in literal_reads:
        return True
    return any(lit.startswith(rp) for rp in prefix_reads if rp)


def check_unread_config_key(index: TreeIndex) -> list[Finding]:
    """R1: flag every WRITTEN config key with no READ anywhere in the tree."""
    all_written: list[_WrittenConfigKey] = []
    # Pre-pass 1: build the global module-level string-constant map so a
    # ``registry.get(NS, CONFIG_KEY_REDIS_URL)`` in file A can consult the
    # ``CONFIG_KEY_REDIS_URL = "redis_url"`` defined in file B. Bare
    # unqualified names collide across files rarely enough that a global
    # map trades a negligible false-negative risk (one string overriding
    # another with the same NAME) for a large false-positive reduction.
    constants: dict[str, str] = {}
    for tree in index.files.values():
        constants.update(_collect_module_string_constants(tree))
    literal_reads: set[str] = set()
    prefix_reads: set[str] = set()
    for path, tree in index.files.items():
        all_written.extend(_collect_written_config_keys(tree, path))
        lits, prefs = _collect_read_config_key_corpus(tree, constants)
        literal_reads |= lits
        prefix_reads |= prefs

    findings: list[Finding] = []
    seen_written: set[tuple[str, bool]] = set()
    for w in all_written:
        # De-dupe: same key text can appear in multiple write sites (e.g.
        # a schema field and a DynamicKeyFamily). One finding per key.
        marker = (w.text, w.is_prefix)
        if marker in seen_written:
            continue
        if _config_key_is_covered(w, literal_reads, prefix_reads):
            seen_written.add(marker)
            continue
        seen_written.add(marker)
        shape = "family prefix" if w.is_prefix else "literal key"
        message = (
            f"unread_config_key: '{w.text}' ({shape}, {w.origin}) is "
            "written but never read via ConfigRegistry .get*/.get_sync "
            "anywhere under src/aila. Bug #104 shape: a promoted "
            "threshold never consulted by the gate that owns it."
        )
        findings.append(Finding(
            rule="unread_config_key",
            location=w.location,
            message=message,
        ))
    return findings


# ---------------------------------------------------------------------------
# R3: SQLModel column write coverage
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _CheckedColumn:
    """One SQLModel column subject to the write-coverage check."""

    class_name: str
    column: str
    location: str


def _field_call_has_kwarg(node: ast.expr | None, name: str) -> bool:
    """Return True when *node* is a ``Field(...)`` call carrying keyword *name*
    with a non-``None`` value.

    Any nested ``Column(...)`` / ``sa_column`` sub-call is also walked -- a
    ``sa_column=Column(..., server_default=...)`` counts.
    """
    if node is None:
        return False
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        for kw in sub.keywords:
            if kw.arg == name and not (
                isinstance(kw.value, ast.Constant) and kw.value.value is None
            ):
                return True
    return False


def _column_is_excluded(field_name: str, value: ast.expr | None) -> bool:
    """Apply the R3 exclusion policy to a single annotated field."""
    if field_name.startswith("_"):
        return True
    if field_name in _COLUMN_AUTO_MANAGED_NAMES:
        return True
    if _field_call_has_kwarg(value, "primary_key"):
        return True
    if _field_call_has_kwarg(value, "foreign_key"):
        return True
    if _field_call_has_kwarg(value, "server_default"):
        return True
    if _field_call_has_kwarg(value, "default_factory"):
        # ``default_factory=utc_now`` is the AILA convention for
        # auto-managed timestamps and for JSONB defaults filled at the
        # Python side without an operator setting them; exclude to keep
        # precision high.
        return True
    return False


def _collect_checked_columns(
    tree: ast.Module, path: Path,
) -> list[_CheckedColumn]:
    """Return every R3-eligible column defined in a single parsed file."""
    out: list[_CheckedColumn] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        if not _classdef_is_table(node):
            base_names = _classdef_base_names(node)
            if not (base_names & _SQLMODEL_BASE_MARKERS):
                continue
            # A non-``table=True`` class without a SQLModel base isn't a
            # concrete table; skip. Non-table SQLModel bases exist (mixins)
            # but their fields propagate to concrete subclasses and get
            # checked there.
            continue
        for stmt in node.body:
            if not isinstance(stmt, ast.AnnAssign):
                continue
            if not isinstance(stmt.target, ast.Name):
                continue
            fname = stmt.target.id
            if _column_is_excluded(fname, stmt.value):
                continue
            out.append(_CheckedColumn(
                class_name=node.name,
                column=fname,
                location=f"{path}:{stmt.lineno}",
            ))
    return out


def _collect_write_identifiers(
    tree: ast.Module,
) -> set[str]:
    """Return every identifier that could name a column write in a file.

    Two shapes:

    * ``keyword.arg`` of any ``Call`` (covers ``Model(col=...)``,
      ``.values(col=...)``, ``.update().values(col=...)``, ``.filter_by(col=...)``,
      and every other kwarg-carrying call). Over-collection here strictly
      HELPS R3 (fewer false positives).
    * ``Attribute`` target of an ``Assign`` / ``AugAssign`` / ``AnnAssign``
      -- ``record.col = ...`` / ``record.col += ...``.

    The ``AnnAssign`` case is deliberate: a SQLModel table declares
    ``foo: int = Field(...)`` as an AnnAssign, and while THAT one is a
    field DEFINITION not a write, its target is a bare ``Name`` (not an
    ``Attribute``), so it never lands in this identifier set.
    """
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg is not None:
                    out.add(kw.arg)
            continue
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets: list[ast.expr]
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
            else:
                targets = [node.target]
            for tgt in targets:
                if isinstance(tgt, ast.Attribute):
                    out.add(tgt.attr)
            continue
        # Dict-literal string keys catch the ``values = {"col": v};
        # stmt.values(**values)`` idiom (splatting a locally-built dict
        # into ``.values(**dict)`` -- the ``**`` denies us the kwarg
        # names, but the source-of-truth dict literal STILL names
        # every column) as well as ``session.execute(text("INSERT
        # ..."), {"col": v})`` param-dict binds. Over-collection on
        # writes strictly shrinks R3 findings (some columns whose only
        # write is a raw SQL text() clause will still be missed, but
        # any column that appears as a dict-literal string key is
        # accepted as written).
        if isinstance(node, ast.Dict):
            for key in node.keys:
                text = _string_constant(key)
                if text is not None:
                    out.add(text)
    return out


def check_unwritten_column(index: TreeIndex) -> list[Finding]:
    """R3: flag every table column with no writer anywhere in the tree."""
    checked: list[_CheckedColumn] = []
    writes: set[str] = set()
    for path, tree in index.files.items():
        checked.extend(_collect_checked_columns(tree, path))
        writes |= _collect_write_identifiers(tree)

    findings: list[Finding] = []
    for col in checked:
        if col.column in writes:
            continue
        message = (
            f"unwritten_column: {col.class_name}.{col.column} is a "
            "SQLModel table column with no writer (no attribute "
            "assignment, no constructor keyword, no update().values() "
            "clause) anywhere under src/aila. Bug #135 shape: a live "
            "column whose stored value is a permanent zero because no "
            "app-code ever writes it."
        )
        findings.append(Finding(
            rule="unwritten_column",
            location=col.location,
            message=message,
        ))
    return findings


# ---------------------------------------------------------------------------
# Rule registry + auditor
# ---------------------------------------------------------------------------


RULE_REGISTRY: dict[str, Callable[[TreeIndex], list[Finding]]] = {
    "unread_config_key": check_unread_config_key,
    "unwritten_column": check_unwritten_column,
}


class LivenessAuditor:
    """Run every registered rule against a tree and apply the whitelist."""

    def __init__(self, whitelist: Whitelist | None = None) -> None:
        self._whitelist: Whitelist = whitelist if whitelist is not None else set()

    def _is_whitelisted(self, finding: Finding) -> bool:
        # ``reason`` is informational -- it lives in the whitelist file so a
        # reader knows WHY the entry exists, but the auto-generated finding
        # message never contains it. Match on rule + path_or_key only.
        for path_or_key, rule, _reason in self._whitelist:
            if rule != finding.rule:
                continue
            if path_or_key and path_or_key not in finding.message:
                continue
            return True
        return False

    def audit_directory(self, directory: Path) -> list[Finding]:
        """Audit every ``*.py`` under *directory* and return unsuppressed findings."""
        index = TreeIndex.build(directory)
        findings: list[Finding] = []
        for rule_name, rule_fn in RULE_REGISTRY.items():
            del rule_name
            for finding in rule_fn(index):
                if not self._is_whitelisted(finding):
                    findings.append(finding)
        return findings


# ---------------------------------------------------------------------------
# __main__ entrypoint
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str]) -> tuple[Path, Path | None]:
    """Return ``(target_dir, whitelist_path | None)`` from *argv*."""
    if not argv:
        _log.error(
            "Usage: python -m aila.tools.liveness_audit <directory> "
            "[--whitelist <path>]"
        )
        sys.exit(2)
    target = Path(argv[0])
    whitelist_path: Path | None = None
    i = 1
    while i < len(argv):
        if argv[i] == "--whitelist" and i + 1 < len(argv):
            whitelist_path = Path(argv[i + 1])
            i += 2
        else:
            i += 1
    return target, whitelist_path


_DEFAULT_WHITELIST_NAMES: tuple[str, ...] = (
    "liveness_whitelist.py",
    "src/aila/tools/liveness_whitelist.py",
)


def _find_default_whitelist(target: Path) -> Path | None:
    """Walk up from *target* looking for the default whitelist file."""
    candidates: Iterable[Path] = [target] + list(target.parents)
    for directory in candidates:
        for name in _DEFAULT_WHITELIST_NAMES:
            candidate = directory / name
            if candidate.exists():
                return candidate
    return None


def _main(argv: list[str]) -> int:
    """CLI entrypoint: run every rule, print findings, return exit code."""
    target, whitelist_path = _parse_args(argv)
    if whitelist_path is None:
        whitelist_path = _find_default_whitelist(target)
        if whitelist_path is not None:
            _log.debug(
                "liveness_audit: auto-loaded whitelist from %s", whitelist_path,
            )
    whitelist: Whitelist = set()
    if whitelist_path is not None:
        if not whitelist_path.exists():
            _log.error("whitelist file not found: %s", whitelist_path)
            return 2
        whitelist = load_whitelist(whitelist_path)
    auditor = LivenessAuditor(whitelist=whitelist)
    if not target.exists():
        _log.error("target not found: %s", target)
        return 2
    if target.is_file():
        _log.error(
            "liveness_audit requires a directory target; %s is a file", target,
        )
        return 2
    findings = auditor.audit_directory(target)
    for f in findings:
        _log.warning("%s: [%s] %s", f.location, f.rule, f.message)
    by_rule: dict[str, int] = {}
    for f in findings:
        by_rule[f.rule] = by_rule.get(f.rule, 0) + 1
    parts = ", ".join(f"{k}={v}" for k, v in sorted(by_rule.items())) or "none"
    _log.warning("liveness_audit: %d findings (%s)", len(findings), parts)
    return 1 if findings else 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(message)s")
    sys.exit(_main(sys.argv[1:]))
