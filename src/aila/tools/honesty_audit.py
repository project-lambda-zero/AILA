"""honesty_audit -- AST-based structural honesty checker for Python code.

Detects thirty-six categories of structural dishonesty:

1. unused_parameter    -- function parameter accepted but never referenced in body.
2. misleading_name     -- function name implies intelligence but body only forwards.
3. docstring_mismatch  -- docstring claims caching/persistence but body has none.
4. import_boundary     -- module imports from another module's package.
5. dead_isinstance     -- isinstance check on a parameter that already has a type annotation.
6. redundant_conversion -- str(already_str), int(already_int), Path(already_path).
7. private_in_all      -- underscore-prefixed name exported in __all__.
8. bare_exception_wrap -- except Exception that raises a less-specific type (destroys info).
9. always_true_default -- parameter with Optional/None default that is ALWAYS overridden by callers.
10. god_object_dispatch -- single function with 4+ if/elif branches on a string action parameter.
11. todo_in_code        -- TODO/FIXME/HACK/XXX comment in production source.
12. silent_exception    -- except Exception with pass or bare default assignment (no logging).
13. production_assert   -- assert statement in production code (stripped under -O).
14. do_nothing_wrapper  -- function body is a single return of another call with no added logic.
15. dead_config_field   -- Pydantic/config field declared but never read anywhere in the codebase.
16. sync_in_async       -- sync session_scope() called inside async def without asyncio.to_thread.
17. api_imports_module_internals -- api/platform/storage code imports modules/ internals.
18. asyncio_in_module   -- asyncio.to_thread/run, ThreadPoolExecutor or concurrent.futures in modules/.
19. response_model_dict -- @router.* decorator specifies response_model=dict/Dict.
20. bare_dict_return_endpoint -- endpoint handler returns a raw dict literal or dict() call.
21. noqa_inline         -- inline # noqa comment in production source (use honesty_whitelist.py instead).
22. http_client_in_module -- module imports httpx/requests/urllib3/aiohttp directly (use platform services).
23. direct_db_in_module -- module imports sqlalchemy.create_engine/asyncpg/psycopg2 directly (use platform UoW).
24. tautological_docstring -- docstring restates function name with no additional information.
25. commented_out_code  -- commented-out Python statement (import/def/class/if/for/return/raise).
26. except_return_default -- except handler returns an empty default ([], {}, None, 0, "") hiding real failures.
27. nested_if_collapsible -- if body is a single if with no else; can be combined with `and`.
28. pointless_pass      -- pass as sole body of non-abstract, non-stub function.
29. f_string_no_interpolation -- f-string with no embedded expressions (plain string suffices).
30. single_use_variable -- variable assigned then immediately returned with no other reference.
31. placeholder_return  -- function body is only a docstring + return {} or return []; no real logic.
32. log_format_concat   -- logging call uses string concatenation/f-string instead of %-formatting.
33. broad_exception_catch -- except Exception without a justifying comment (catches everything indiscriminately).
34. hoisted_enum_redeclared -- a unified vr/malware module redeclares a StrEnum owned by platform.contracts.enums (RFC-01).
35. unnamed_derived_constraint -- a unified vr/malware table hard-codes a UQ name instead of deriving via TabledUq.
36. shadowed_platform_base -- a unified vr/malware table recreates a platform base's columns instead of subclassing it.
37. module_config_schema_base -- a module config schema subclasses bare BaseModel instead of ModuleConfigBase (loses extra=forbid).
38. service_copy_of_platform -- a vr/malware service file is a full copy of a platform service instead of a thin binding.
39. cost_read_stored_actual -- a vr/malware lifecycle api_router reads the dead cost_actual_usd column in a response instead of aggregating live cost.
40. lifecycle_handler_bypass_service -- a pause/resume/re-enqueue route handler writes investigation .status directly instead of calling the platform lifecycle service.
41. workflow_state_copy_of_platform -- a vr/malware investigation state file duplicates a platform workflow-state base instead of binding the factory.
42. agent_primitive_reimplementation -- a module agents/ file defines a platform-owned agent primitive (auto-steering injector / intent classifier) at top level instead of importing it.
43. agent_llm_chat_bypass -- a module agents/ file calls llm_client.chat/chat_json/chat_structured directly instead of routing through platform idempotent_llm_call (double-pays the model on retry).

Usage (CLI):
    python -m aila.tools.honesty_audit src/
    python -m aila.tools.honesty_audit src/ --whitelist honesty_whitelist.py

Exit code 0 = no findings (clean).
Exit code 1 = findings exist.

Whitelist:
    honesty_whitelist.py defines HONESTY_WHITELIST as a list of
    (filename_suffix, function_name, detail) tuples.  A finding is suppressed
    when the finding's file ends with filename_suffix AND function_name appears
    in the finding's message AND detail appears in the finding's message.

Design constraints (D-04):
    AST analysis only -- no runtime inspection.
    No external dependencies beyond stdlib (ast, sys, pathlib, dataclasses).
"""

from __future__ import annotations

import ast
import difflib
import logging
import re as _re
import sys
from dataclasses import dataclass
from pathlib import Path

_log = logging.getLogger(__name__)

__all__ = ["Finding", "HonestyAuditor", "load_whitelist"]

# ---------------------------------------------------------------------------
# Keyword sets
# ---------------------------------------------------------------------------

_MISLEADING_NAME_KEYWORDS: frozenset[str] = frozenset(
    {"planner", "manager", "manage", "helper", "coordinator", "processor", "handler"}
)

_CACHE_DOC_CLAIM_PHRASES: tuple[str, ...] = (
    "caches the",
    "cached result",
    "caches results",
    "persists the result",
    "memoizes",
    "stores the result in memory",
    "stores result in cache",
)

_CACHE_IMPL_IDENTIFIERS: frozenset[str] = frozenset(
    {"cache", "_cache", "lru_cache", "functools", "memo", "_store", "persist"}
)

# Decorator names that indicate a stub body is intentional.
_STUB_DECORATORS: frozenset[str] = frozenset({"abstractmethod", "overload"})

# Type names that make isinstance checks redundant (rule 5).
_TYPED_BUILTINS: frozenset[str] = frozenset(
    {"str", "int", "float", "bool", "dict", "list", "tuple", "set", "bytes"}
)

# Redundant conversions where the annotation already guarantees the type (rule 6).
_IDENTITY_CONVERSIONS: dict[str, str] = {
    "str": "str", "int": "int", "float": "float", "bool": "bool",
    "Path": "Path",
}

# Action-dispatch keywords that indicate a God Object pattern (rule 10).
_ACTION_PARAM_NAMES: frozenset[str] = frozenset({"action", "operation", "command", "mode"})

# Comment markers that indicate unfinished promises (rule 11).
_TODO_PATTERN = _re.compile(r"#\s*(TODO|FIXME|HACK|XXX)\b", _re.IGNORECASE)

# Rule 21 -- noqa inline comments.
_NOQA_PATTERN = _re.compile(r"#\s*noqa\b")

# Rule 18 -- asyncio threading primitives banned from modules/.
# These identifiers flag usage of asyncio.to_thread, asyncio.run,
# ThreadPoolExecutor, and concurrent.futures imports inside module files.
_ASYNCIO_THREAD_ATTRS: frozenset[str] = frozenset({
    "to_thread", "run", "run_until_complete", "run_in_executor",
})
_THREAD_CLASS_NAMES: frozenset[str] = frozenset({"ThreadPoolExecutor"})

# Files that are self-exempt from Rule 21 (they ARE the audit/whitelist tools).
_NOQA_SELF_EXEMPT_SUFFIXES: tuple[str, ...] = (
    "aila/tools/honesty_audit.py",
    "aila/tools/honesty_whitelist.py",
)

# Alembic paths are exempt from Rule 21.
# Both the auto-generated migration files (alembic/versions/) and the hand-written
# alembic/env.py legitimately use # noqa: F401 for side-effect imports that populate
# SQLModel.metadata -- they cannot use honesty_whitelist.py because the import must
# appear at the module level and ruff processes it independently.
_ALEMBIC_PATH_PATTERN = _re.compile(r"[/\\]alembic[/\\]")

# Rule 22 -- HTTP client libraries banned from modules/.
# Modules must use platform HTTP services (SSHService, IDA bridge, etc.),
# not construct their own httpx/requests/aiohttp clients.
_HTTP_CLIENT_MODULES: frozenset[str] = frozenset({
    "httpx", "requests", "urllib3", "aiohttp",
})

# Rule 23 -- Direct DB connection libraries banned from modules/.
# Modules use UnitOfWork from aila.platform.uow for all DB access.
# Direct engine/connection construction bypasses team scoping and audit.
_DIRECT_DB_MODULES: frozenset[str] = frozenset({
    "asyncpg", "psycopg2", "psycopg", "sqlite3",
})
_DIRECT_DB_CALLABLES: frozenset[str] = frozenset({
    "create_engine", "create_async_engine",
})

# Rule 25 -- Commented-out code detection.
# Matches lines that look like commented-out Python statements.
_COMMENTED_CODE_RE = _re.compile(
    r'^\s*#\s*'
    r'(import\s|from\s|def\s|class\s|if\s|elif\s|for\s|while\s'
    r'|return\s|raise\s|try:|except\s|with\s|async\s|await\s|yield\s'
    r'|assert\s|pass$|break$|continue$)',
)
# Lines containing these phrases are documentation examples, not dead code.
_COMMENTED_CODE_EXEMPTIONS: tuple[str, ...] = (
    "example", "e.g.", "usage:", "like:", "such as", "pattern:",
    "alternative:", "note:", "see:", "returns:", "yields:",
    "template", "scaffold", "optional", "placeholder", "disabled",
    "investigation", "documentation", "explanation", "describes",
)

# Rule 29 -- f-string without interpolation.
# Ruff F541 catches this too but may be disabled; this is the structural backup.

# Rule 32 -- Logging calls using string concatenation or f-strings.
# Correct: _log.info("x=%s", x).  Wrong: _log.info(f"x={x}") or _log.info("x=" + str(x)).
_LOG_METHODS: frozenset[str] = frozenset({
    "debug", "info", "warning", "warn", "error", "exception", "critical",
})

# Names that indicate logging is present (rule 12 -- silent exception check).
_LOGGING_IDENTIFIERS: frozenset[str] = frozenset({
    "logger", "logging", "log", "LOGGER", "LOG",
    "warn", "warning", "error", "info", "debug", "exception", "critical",
})

# ---------------------------------------------------------------------------
# Module-boundary detection helpers
# ---------------------------------------------------------------------------

_MODULE_PATH_PATTERN = _re.compile(
    r"[/\\]aila[/\\]modules[/\\]([a-z][a-z0-9_]*)[/\\]"
)


def _owning_module_id(filepath: str) -> str | None:
    """Return the aila module_id if *filepath* is inside aila/modules/{id}/, else None."""
    match = _MODULE_PATH_PATTERN.search(filepath.replace("\\", "/"))
    return match.group(1) if match else None


def _endpoint_route_path(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> str | None:
    """Return the route path from a ``@router.<verb>("...")`` decorator.

    Returns the first positional string argument of the first router verb
    decorator on *node*, or None when the function is not a route handler.
    """
    for dec in node.decorator_list:
        if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
            continue
        if dec.func.attr not in {"get", "post", "put", "delete", "patch"}:
            continue
        if (
            dec.args
            and isinstance(dec.args[0], ast.Constant)
            and isinstance(dec.args[0].value, str)
        ):
            return dec.args[0].value
    return None


_BOUNDARY_GUARDED_PATTERN = _re.compile(r"[/\\]aila[/\\](api|platform|storage)[/\\]")


def _is_boundary_guarded_file(filepath: str) -> bool:
    """Return True if *filepath* is inside a boundary-guarded package."""
    return bool(_BOUNDARY_GUARDED_PATTERN.search(filepath.replace("\\", "/")))


_MODULE_FILE_PATTERN = _re.compile(r"[/\\]aila[/\\]modules[/\\]")

# Rule 37 -- module config schemas must subclass ModuleConfigBase.
_CONFIG_SCHEMA_PATH_PATTERN = _re.compile(
    r"[/\\]aila[/\\]modules[/\\][a-z][a-z0-9_]*[/\\]config_schema\.py$"
)


def _is_module_file(filepath: str) -> bool:
    """Return True if *filepath* is inside the aila/modules/ package."""
    return bool(_MODULE_FILE_PATTERN.search(filepath.replace("\\", "/")))


# ---------------------------------------------------------------------------
# AST walk helpers
# ---------------------------------------------------------------------------

_NESTED_DEF_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _walk_returns_shallow(node: ast.AST):
    """Yield Return nodes from *node*'s subtree without recursing into nested function/class bodies.

    Unlike ``ast.walk``, this generator stops at any ``FunctionDef``,
    ``AsyncFunctionDef``, or ``ClassDef`` node -- so return statements inside
    nested helper functions are invisible to the caller.  This prevents false
    positives in Rule 20 (bare_dict_return_endpoint) where an outer endpoint
    delegates work to an inner ``async def _helper()`` that legitimately
    returns a plain dict for internal use only.
    """
    for child in ast.iter_child_nodes(node):
        if isinstance(child, _NESTED_DEF_TYPES):
            continue
        if isinstance(child, ast.Return):
            yield child
        yield from _walk_returns_shallow(child)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    """A single honesty violation found in a source file."""

    file: str
    line: int
    rule: str
    message: str


Whitelist = set[tuple[str, str, str]]


# ---------------------------------------------------------------------------
# Whitelist loading
# ---------------------------------------------------------------------------


def load_whitelist(path: Path) -> Whitelist:
    """Parse *path* and return the set of (filename_suffix, func_name, detail) triples.

    The file must define a top-level ``HONESTY_WHITELIST`` list literal of
    3-element string tuples.  Non-tuple entries are silently skipped.
    """
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))

    result: Whitelist = set()
    for node in ast.walk(tree):
        # Handle both plain assignment and annotated assignment:
        #   HONESTY_WHITELIST = [...]
        #   HONESTY_WHITELIST: list[...] = _validate([...])
        if isinstance(node, ast.Assign):
            targets = node.targets
            raw_value: ast.expr | None = node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
            raw_value = node.value
        else:
            continue
        for target in targets:
            if not (isinstance(target, ast.Name) and target.id == "HONESTY_WHITELIST"):
                continue
            value = raw_value
            # Unwrap _validate([...]) → the inner list literal.
            if isinstance(value, ast.Call) and value.args:
                value = value.args[0]
            if not isinstance(value, ast.List):
                continue
            for elt in value.elts:
                if (
                    isinstance(elt, ast.Tuple)
                    and len(elt.elts) == 3
                    and all(isinstance(e, ast.Constant) for e in elt.elts)
                ):
                    triple = tuple(e.value for e in elt.elts)  # type: ignore[union-attr]
                    result.add(triple)  # type: ignore[arg-type]
    return result


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def _decorator_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """Return the simple names of all decorators on *func*."""
    names: list[str] = []
    for dec in func.decorator_list:
        if isinstance(dec, ast.Name):
            names.append(dec.id)
        elif isinstance(dec, ast.Attribute):
            names.append(dec.attr)
    return names


def _is_stub_body(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True when the function body is a bare ``...`` (Ellipsis) stub.

    Protocol / ABC abstract methods have ``...`` as their entire body.  They
    declare signatures but contain no executable code -- flagging unused params
    there is meaningless.
    """
    stmts = func.body
    if len(stmts) == 1:
        stmt = stmts[0]
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is ...:
            return True
    return False


def _has_stub_decorator(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if the function carries @abstractmethod or @overload."""
    return bool(_STUB_DECORATORS & set(_decorator_names(func)))


def _collect_body_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Collect all ast.Name ids that appear anywhere in the function body."""
    names: set[str] = set()
    for node in ast.walk(ast.Module(body=func.body, type_ignores=[])):
        if isinstance(node, ast.Name):
            names.add(node.id)
    return names


def _collect_body_identifiers(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Collect all Name ids AND Attribute attrs from the function body AND decorators."""
    ids: set[str] = set()
    # Include decorator names (e.g. @lru_cache, @functools.cache).
    for dec in func.decorator_list:
        for node in ast.walk(dec):
            if isinstance(node, ast.Name):
                ids.add(node.id)
            elif isinstance(node, ast.Attribute):
                ids.add(node.attr)
    for node in ast.walk(ast.Module(body=func.body, type_ignores=[])):
        if isinstance(node, ast.Name):
            ids.add(node.id)
        elif isinstance(node, ast.Attribute):
            ids.add(node.attr)
    return ids


def _param_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """Return parameter names that are subject to the unused-parameter check.

    Excluded:
      - self, cls  (conventional receiver names)
      - _          (intentional discard sentinel)
      - *args arguments (vararg)
      - **kwargs arguments (kwarg)
    """
    args = func.args
    excluded = {"self", "cls", "_"}
    result: list[str] = []
    # positional + keyword
    all_args = list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
    for arg in all_args:
        if arg.arg not in excluded and not arg.arg.startswith("_"):
            result.append(arg.arg)
    return result

_DEPENDENCY_DEFAULT_NAMES = {"Depends", "Security"}


def _decorator_identifiers(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Return Name ids and Attribute attrs appearing in decorators."""
    ids: set[str] = set()
    for dec in func.decorator_list:
        for node in ast.walk(dec):
            if isinstance(node, ast.Name):
                ids.add(node.id)
            elif isinstance(node, ast.Attribute):
                ids.add(node.attr)
    return ids


def _parameter_arg_map(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
 ) -> dict[str, ast.arg]:
    """Return a mapping of parameter name to ast.arg node."""
    args = func.args
    all_args = list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)
    return {arg.arg: arg for arg in all_args}


def _parameter_defaults(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
 ) -> dict[str, ast.expr]:
    """Return a mapping of parameter name to its default expression."""
    args = func.args
    pos_args = list(args.posonlyargs) + list(args.args)
    defaults: dict[str, ast.expr] = {}
    if args.defaults:
        start = len(pos_args) - len(args.defaults)
        for arg, default in zip(pos_args[start:], args.defaults, strict=True):
            defaults[arg.arg] = default
    for arg, default in zip(args.kwonlyargs, args.kw_defaults, strict=True):
        if default is not None:
            defaults[arg.arg] = default
    return defaults


def _is_dependency_default(node: ast.expr | None) -> bool:
    """Return True if a default expression is a FastAPI dependency marker."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in _DEPENDENCY_DEFAULT_NAMES
    if isinstance(func, ast.Attribute):
        return func.attr in _DEPENDENCY_DEFAULT_NAMES
    return False


def _is_request_annotation(node: ast.expr | None) -> bool:
    """Return True if an annotation refers to Request."""
    if node is None:
        return False
    if isinstance(node, ast.Name):
        return node.id == "Request"
    if isinstance(node, ast.Attribute):
        return node.attr == "Request"
    return False


def _parameter_is_framework_used(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    param_name: str,
 ) -> bool:
    """Return True when a parameter is consumed declaratively by framework contracts."""
    defaults = _parameter_defaults(func)
    if _is_dependency_default(defaults.get(param_name)):
        return True

    decorator_ids = _decorator_identifiers(func)
    arg_map = _parameter_arg_map(func)
    arg_node = arg_map.get(param_name)
    if (
        param_name == "request"
        and _is_request_annotation(arg_node.annotation if arg_node else None)
        and ("limit" in decorator_ids or func.name.endswith("_handler"))
    ):
        return True

    if param_name == "ctx":
        return True

    return False

def _root_name(node: ast.expr) -> str | None:
    """Walk attribute chains and return the root Name id, or None."""
    while isinstance(node, ast.Attribute):
        node = node.value
    if isinstance(node, ast.Name):
        return node.id
    return None


def _is_forward_call_body(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if the body is a single pure-forward call statement.

    A forward call is: the single statement is a Return (or Expr) of an
    ast.Call where the callable is an ast.Attribute whose root receiver is
    ``self`` or the first positional argument.  This covers both
    ``self.run(x)`` and chained ``self.delegate.run(x)`` patterns.

    An optional leading docstring is allowed and does not count against the
    "single statement" limit.
    """
    stmts = func.body
    if not stmts:
        return False

    # Strip leading docstring if present.
    real_stmts = stmts
    if (
        len(stmts) >= 1
        and isinstance(stmts[0], ast.Expr)
        and isinstance(stmts[0].value, ast.Constant)
        and isinstance(stmts[0].value.value, str)
    ):
        real_stmts = stmts[1:]

    if len(real_stmts) != 1:
        return False

    stmt = real_stmts[0]

    # Extract the expression -- could be Return or bare Expr.
    if isinstance(stmt, ast.Return) and stmt.value is not None:
        expr = stmt.value
    elif isinstance(stmt, ast.Expr):
        expr = stmt.value
    else:
        return False

    # Must be a simple Call.
    if not isinstance(expr, ast.Call):
        return False

    func_node = expr.func
    # Must be attribute access (self.x, self.delegate.x, first_arg.x, etc.).
    if not isinstance(func_node, ast.Attribute):
        return False

    root = _root_name(func_node.value)
    if root is None:
        return False

    # Allowed roots: self, or the first positional parameter name.
    allowed_roots = {"self"}
    all_params = list(func.args.posonlyargs) + list(func.args.args)
    if all_params:
        allowed_roots.add(all_params[0].arg)

    return root in allowed_roots


def _get_docstring(func: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """Return the docstring of *func* if it has one, else None."""
    if not func.body:
        return None
    first = func.body[0]
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
        val = first.value.value
        if isinstance(val, str):
            return val
    return None


def _docstring_claims_caching(docstring: str) -> bool:
    """Return True if the docstring claims THIS function caches/persists results.

    Only flags phrases like 'caches the result' or 'memoizes' -- not functions
    that merely interact with a cache ('reads from cache', 'updates cache entry').
    """
    low = docstring.lower()
    return any(phrase in low for phrase in _CACHE_DOC_CLAIM_PHRASES)


def _body_has_cache_impl(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if the body contains any identifier associated with caching."""
    body_ids = _collect_body_identifiers(func)
    return bool(body_ids & _CACHE_IMPL_IDENTIFIERS)


# ---------------------------------------------------------------------------
# RFC-01 re-duplication guardrails (rules 34-36)
# ---------------------------------------------------------------------------

# The enums hoisted to aila.platform.contracts.enums. A module must import
# these rather than redeclare them. Module-owned enums (WorkspaceTheme,
# TargetKind, etc.) are deliberately absent from this set.
_HOISTED_ENUM_NAMES: frozenset[str] = frozenset({
    "WorkspaceStatus", "TargetStatus", "AnalysisState", "TargetTagSource",
    "BranchStatus", "PersonaVoice", "BranchOperation", "InvestigationStatus",
    "InvestigationPauseReason", "OutcomeConfidence", "OutcomeDispatchStatus",
    "SenderKind", "OperatorIntent", "PatternStatus", "PatternScope",
    "PatternConfidence", "HypothesisState", "StageState", "StageName",
})

# Modules whose investigation-engine tables RFC-01 unified onto the platform
# record bases. Other modules (forensics, vulnerability) keep independent
# table shapes and are outside the scope of the derived-name + subclass rules.
_RFC01_UNIFIED_MODULES: frozenset[str] = frozenset({"vr", "malware"})

# Unified table role (tablename with the module prefix removed) mapped to the
# platform base class the concrete must subclass.
_UNIFIED_ROLE_BASES: dict[str, str] = {
    "workspaces": "WorkspaceRecordBase",
    "targets": "TargetRecordBase",
    "target_tag_index": "TargetTagIndexBase",
    "investigations": "InvestigationRecordBase",
    "investigation_messages": "MessageRecordBase",
    "investigation_branches": "BranchRecordBase",
    "investigation_outcomes": "OutcomeRecordBase",
    "outcome_reviews": "OutcomeReviewRecordBase",
    "mcp_call_log": "McpCallLogRecordBase",
    "investigation_targets": "InvestigationTargetRecordBase",
    "patterns": "PatternRecordBase",
    "projects": "ProjectRecordBase",
}

# Platform base class mapped to the *_base.py file under platform/contracts/
# that defines it (two share target_base.py).
_BASE_FILE_BY_CLASS: dict[str, str] = {
    "WorkspaceRecordBase": "workspace_base.py",
    "TargetRecordBase": "target_base.py",
    "TargetTagIndexBase": "target_base.py",
    "InvestigationRecordBase": "investigation_base.py",
    "MessageRecordBase": "message_base.py",
    "BranchRecordBase": "branch_base.py",
    "OutcomeRecordBase": "outcome_base.py",
    "OutcomeReviewRecordBase": "outcome_review_base.py",
    "McpCallLogRecordBase": "mcp_call_log_base.py",
    "InvestigationTargetRecordBase": "investigation_target_base.py",
    "PatternRecordBase": "pattern_base.py",
    "ProjectRecordBase": "project_base.py",
}

# Cache of platform base field-name sets, keyed by (base_file_path, class_name).
_BASE_FIELD_CACHE: dict[tuple[str, str], frozenset[str]] = {}

_CONTRACTS_DIR_PATTERN = _re.compile(r"^(.*/aila)/modules/")

# Rule 38 -- module service files must not be full copies of a platform
# service. Scoped to the vr/malware copy set (forensics keeps an
# independent machine_readiness variant, outside the check).
_SERVICE_COPY_SCOPE_PATTERN = _re.compile(
    r"[/\\]aila[/\\]modules[/\\](?:vr|malware)[/\\]services[/\\][^/\\]+\.py$"
)
_PLATFORM_SERVICE_SUBDIRS: tuple[str, ...] = ("services", "mcp", "tasks")
_SERVICE_COPY_THRESHOLD: float = 0.75
_SERVICE_CORPUS_CACHE: dict[str, dict[str, str]] = {}


def _platform_service_corpus(filepath: str) -> dict[str, str]:
    """Return {relpath: normalized_source} for every platform service file.

    Reads platform/services, platform/mcp, and platform/tasks so a module
    service copied from any of them is caught. Each source is normalized via
    ast.unparse (comments and formatting removed); cached per aila root.
    """
    match = _CONTRACTS_DIR_PATTERN.search(filepath.replace("\\", "/"))
    if match is None:
        return {}
    aila_root = match.group(1)
    cached = _SERVICE_CORPUS_CACHE.get(aila_root)
    if cached is not None:
        return cached
    corpus: dict[str, str] = {}
    for subdir in _PLATFORM_SERVICE_SUBDIRS:
        base = Path(aila_root) / "platform" / subdir
        if not base.is_dir():
            continue
        for py in sorted(base.glob("*.py")):
            if py.name == "__init__.py":
                continue
            try:
                normalized = ast.unparse(ast.parse(py.read_text(encoding="utf-8")))
            except (OSError, SyntaxError, ValueError, RecursionError):
                continue
            corpus[f"{subdir}/{py.name}"] = normalized
    _SERVICE_CORPUS_CACHE[aila_root] = corpus
    return corpus


# Rule 41 -- module workflow-state files must not be full copies of a
# platform workflow-state base. Scoped to the vr/malware investigation
# engine states (setup/loop/emit), which RFC-02 Phase 4 extracted to
# platform/workflows/investigation_*_base.py.
_WORKFLOW_STATE_SCOPE_PATTERN = _re.compile(
    r"[/\\]aila[/\\]modules[/\\](?:vr|malware)[/\\]workflow[/\\]states[/\\]"
    r"investigation_(?:setup|loop|emit)\.py$"
)
_WORKFLOW_BASE_CORPUS_CACHE: dict[str, dict[str, str]] = {}

# Rule 42 -- module agents/ files must not re-implement a platform agent
# primitive. RFC-03 Phase 1 lifted the operator-intent classifier and the
# auto-steering injector to platform/agents/; modules import them. A
# top-level def of a lifted primitive is a copy that drifted back in.
_AGENTS_SCOPE_PATTERN = _re.compile(
    r"[/\\]aila[/\\]modules[/\\][^/\\]+[/\\]agents[/\\]"
)
_LIFTED_AGENT_PRIMITIVES: frozenset[str] = frozenset({
    "maybe_post_auto_steering",
    "classify_intent",
})


def _workflow_base_corpus(filepath: str) -> dict[str, str]:
    """Return {relpath: normalized_source} for platform workflow-state bases.

    Reads platform/workflows/investigation_*_base.py so a module state
    file copied back from a platform base is caught. Normalized via
    ast.unparse; cached per aila root.
    """
    match = _CONTRACTS_DIR_PATTERN.search(filepath.replace("\\", "/"))
    if match is None:
        return {}
    aila_root = match.group(1)
    cached = _WORKFLOW_BASE_CORPUS_CACHE.get(aila_root)
    if cached is not None:
        return cached
    corpus: dict[str, str] = {}
    base = Path(aila_root) / "platform" / "workflows"
    if base.is_dir():
        for py in sorted(base.glob("investigation_*_base.py")):
            try:
                normalized = ast.unparse(
                    ast.parse(py.read_text(encoding="utf-8")),
                )
            except (OSError, SyntaxError, ValueError, RecursionError):
                continue
            corpus[f"workflows/{py.name}"] = normalized
    _WORKFLOW_BASE_CORPUS_CACHE[aila_root] = corpus
    return corpus


def _classdef_is_table(node: ast.ClassDef) -> bool:
    """Return True when a class is declared with the SQLModel table=True flag."""
    for kw in node.keywords:
        if kw.arg == "table" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _classdef_tablename(node: ast.ClassDef) -> str | None:
    """Return the literal __tablename__ string assigned in a class body, or None."""
    for stmt in node.body:
        if not isinstance(stmt, ast.Assign):
            continue
        value = stmt.value
        if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
            continue
        for target in stmt.targets:
            if isinstance(target, ast.Name) and target.id == "__tablename__":
                return value.value
    return None


def _classdef_base_names(node: ast.ClassDef) -> set[str]:
    """Return the simple names of a class's declared bases."""
    names: set[str] = set()
    for base in node.bases:
        if isinstance(base, ast.Name):
            names.add(base.id)
        elif isinstance(base, ast.Attribute):
            names.add(base.attr)
    return names


def _sqlmodel_field_names(node: ast.ClassDef) -> set[str]:
    """Return the annotated (non-dunder) field names declared directly on a class."""
    names: set[str] = set()
    for stmt in node.body:
        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            field = stmt.target.id
            if not field.startswith("__"):
                names.add(field)
    return names


def _unique_constraint_literal_names(node: ast.ClassDef):
    """Yield (literal_name, lineno) for each UniqueConstraint(name=<str>) in the class body."""
    for stmt in node.body:
        if not (isinstance(stmt, ast.Assign) and _assigns_table_args(stmt)):
            continue
        for call in ast.walk(stmt.value):
            if not isinstance(call, ast.Call):
                continue
            callee = call.func
            is_uq = (isinstance(callee, ast.Name) and callee.id == "UniqueConstraint") or (
                isinstance(callee, ast.Attribute) and callee.attr == "UniqueConstraint"
            )
            if not is_uq:
                continue
            for kw in call.keywords:
                if kw.arg == "name" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    yield kw.value.value, call.lineno


def _assigns_table_args(stmt: ast.Assign) -> bool:
    """Return True when an assignment targets __table_args__."""
    return any(isinstance(t, ast.Name) and t.id == "__table_args__" for t in stmt.targets)


def _strip_module_prefix(tablename: str, module_id: str) -> str:
    """Return the table role: the tablename with a leading '<module_id>_' removed."""
    prefix = f"{module_id}_"
    return tablename[len(prefix):] if tablename.startswith(prefix) else tablename


def _platform_contracts_dir(filepath: str) -> Path | None:
    """Resolve the platform/contracts directory from a module file path, or None."""
    match = _CONTRACTS_DIR_PATTERN.search(filepath.replace("\\", "/"))
    if match is None:
        return None
    return Path(match.group(1)) / "platform" / "contracts"


def _platform_base_field_names(base_file: Path, base_class: str) -> frozenset[str]:
    """Return the field-name set of a platform base class, read via AST and cached.

    Returns an empty set when the file or class cannot be resolved so the caller
    skips defensively rather than raising inside the gate.
    """
    cache_key = (str(base_file), base_class)
    cached = _BASE_FIELD_CACHE.get(cache_key)
    if cached is not None:
        return cached
    result: frozenset[str] = frozenset()
    try:
        tree = ast.parse(base_file.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        _BASE_FIELD_CACHE[cache_key] = result
        return result
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == base_class:
            result = frozenset(_sqlmodel_field_names(node))
            break
    _BASE_FIELD_CACHE[cache_key] = result
    return result


# ---------------------------------------------------------------------------
# Main auditor class
# ---------------------------------------------------------------------------


class _HonestyVisitor(ast.NodeVisitor):
    """AST visitor that accumulates Finding objects."""

    def _emit(self, line: int, rule: str, message: str) -> None:
        finding = Finding(file=self.filename, line=line, rule=rule, message=message)
        if not self._is_whitelisted(finding):
            self.findings.append(finding)

    def _is_whitelisted(self, finding: Finding) -> bool:
        # Normalize to forward slashes for cross-platform suffix matching.
        normalized_file = finding.file.replace("\\", "/")
        for suffix, func_name, detail in self.whitelist:
            normalized_suffix = suffix.replace("\\", "/")
            if (
                normalized_file.endswith(normalized_suffix)
                and func_name in finding.message
                and detail in finding.message
            ):
                return True
        return False

    # ------------------------------------------------------------------
    # Visitor entry points
    # ------------------------------------------------------------------

    def __init__(self, filename: str, whitelist: Whitelist) -> None:
        self.filename = filename
        self.whitelist = whitelist
        self.findings: list[Finding] = []
        self._in_protocol_class: bool = False

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        # Detect Protocol classes -- skip their methods for unused_parameter
        is_protocol = any(
            (isinstance(b, ast.Name) and b.id == "Protocol")
            or (isinstance(b, ast.Attribute) and b.attr == "Protocol")
            for b in node.bases
        )
        old = self._in_protocol_class
        if is_protocol:
            self._in_protocol_class = True
        self.generic_visit(node)
        self._in_protocol_class = old

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Rule implementations
    # ------------------------------------------------------------------

    def _check_function(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        self._check_unused_parameter(func)
        self._check_misleading_name(func)
        self._check_docstring_mismatch(func)
        self._check_dead_isinstance(func)
        self._check_god_object_dispatch(func)
        self._check_do_nothing_wrapper(func)

    def _check_unused_parameter(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        """Rule: unused_parameter."""
        # Skip stubs -- Protocol/ABC abstract bodies.
        if _is_stub_body(func) or _has_stub_decorator(func):
            return
        # Skip Protocol class methods -- they define interfaces, not implementations.
        if self._in_protocol_class:
            return

        params = _param_names(func)
        if not params:
            return

        body_names = _collect_body_names(func)
        for param in params:
            if param in body_names:
                continue
            if _parameter_is_framework_used(func, param):
                continue
            self._emit(
                func.lineno,
                "unused_parameter",
                f"function '{func.name}' has unused parameter '{param}'",
            )

    def _check_misleading_name(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Rule: misleading_name."""
        name_lower = func.name.lower()
        if not any(kw in name_lower for kw in _MISLEADING_NAME_KEYWORDS):
            return

        if _is_forward_call_body(func):
            self._emit(
                func.lineno,
                "misleading_name",
                (
                    f"function '{func.name}' name implies intelligent logic "
                    f"but body only forwards the call"
                ),
            )

    def _check_docstring_mismatch(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        """Rule: docstring_mismatch."""
        docstring = _get_docstring(func)
        if docstring is None:
            return
        if not _docstring_claims_caching(docstring):
            return
        if _body_has_cache_impl(func):
            return

        self._emit(
            func.lineno,
            "docstring_mismatch",
            (
                f"function '{func.name}' docstring claims caching/persistence "
                f"but body has no caching implementation"
            ),
        )

    def _check_dead_isinstance(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        """Rule: dead_isinstance -- isinstance check on a typed parameter."""
        # Build a map of param_name → annotation_type_name
        typed_params: dict[str, str] = {}
        for arg in list(func.args.args) + list(func.args.kwonlyargs):
            if arg.annotation and isinstance(arg.annotation, ast.Name) and arg.annotation.id in _TYPED_BUILTINS:
                typed_params[arg.arg] = arg.annotation.id

        if not typed_params:
            return

        for node in ast.walk(ast.Module(body=func.body, type_ignores=[])):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Name) or node.func.id != "isinstance":
                continue
            if len(node.args) < 2:
                continue
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Name) and first_arg.id in typed_params:
                self._emit(
                    node.lineno,
                    "dead_isinstance",
                    f"function '{func.name}' checks isinstance({first_arg.id}, ...) "
                    f"but '{first_arg.id}' is already annotated as '{typed_params[first_arg.id]}'",
                )

    def _check_god_object_dispatch(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        """Rule: god_object_dispatch -- 4+ if/elif branches on an action string parameter."""
        # Check if any parameter has an action-like name
        action_params = set()
        for arg in list(func.args.args) + list(func.args.kwonlyargs):
            if arg.arg in _ACTION_PARAM_NAMES:
                action_params.add(arg.arg)

        if not action_params:
            return

        # Count if/elif branches that compare the action param
        branch_count = 0
        for node in ast.walk(ast.Module(body=func.body, type_ignores=[])):
            if isinstance(node, ast.Compare):
                # Check if left side is the action param
                if isinstance(node.left, ast.Name) and node.left.id in action_params:
                    branch_count += 1
                # Check normalized_action pattern
                for name_node in ast.walk(node):
                    if (
                        isinstance(name_node, ast.Name)
                        and "action" in name_node.id.lower()
                        and any(isinstance(c, ast.Constant) and isinstance(c.value, str) for c in node.comparators)
                    ):
                        branch_count += 1
                        break

        # CRUD tools (upsert/list/get/delete on one resource) are acceptable
        # at 3-5 branches. Flag only when branches exceed 6 -- indicating
        # multiple unrelated concerns in one tool, not standard CRUD.
        if branch_count >= 7:
            self._emit(
                func.lineno,
                "god_object_dispatch",
                f"function '{func.name}' has {branch_count} action-dispatch branches -- "
                f"consider splitting into separate single-concern tools",
            )

    def _check_private_in_all(self, tree: ast.Module) -> None:
        """Rule: private_in_all -- underscore-prefixed name in __all__."""
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if not isinstance(target, ast.Name) or target.id != "__all__":
                    continue
                if not isinstance(node.value, (ast.List, ast.Tuple)):
                    continue
                for elt in node.value.elts:
                    if (
                        isinstance(elt, ast.Constant)
                        and isinstance(elt.value, str)
                        and elt.value.startswith("_")
                    ):
                        self._emit(
                            elt.lineno if hasattr(elt, "lineno") else node.lineno,
                            "private_in_all",
                            f"'__all__' exports private name '{elt.value}' \u2014 "
                            "underscore prefix contradicts public API declaration",
                        )

    def _check_bare_exception_wrap(self, tree: ast.Module) -> None:
        """Rule: bare_exception_wrap -- except Exception that raises a less-specific type."""
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            # Only flag broad 'except Exception' catches
            if node.type is None:
                continue
            if not isinstance(node.type, ast.Name) or node.type.id != "Exception":
                continue
            # Check if the handler body raises RuntimeError (destroys type info)
            for stmt in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                if (
                    isinstance(stmt, ast.Raise)
                    and stmt.exc is not None
                    and isinstance(stmt.exc, ast.Call)
                    and isinstance(stmt.exc.func, ast.Name)
                    and stmt.exc.func.id == "RuntimeError"
                ):
                    self._emit(
                        node.lineno,
                        "bare_exception_wrap",
                        "'except Exception' catches typed errors then raises "
                        "RuntimeError \u2014 original exception type is destroyed",
                    )
                    break

    def _check_todo_in_code(self, source: str) -> None:
        """Rule: todo_in_code -- TODO/FIXME/HACK/XXX in production source.

        Scans raw source lines for comment markers.  A TODO is a promise
        embedded in code that nobody tracks -- either do the work or file
        an issue and delete the comment.
        """
        for lineno, line in enumerate(source.splitlines(), start=1):
            match = _TODO_PATTERN.search(line)
            if match:
                tag = match.group(1).upper()
                self._emit(
                    lineno,
                    "todo_in_code",
                    f"'{tag}' comment found -- either resolve it or track it in an issue",
                )

    def _check_silent_exception(self, tree: ast.Module) -> None:
        """Rule: silent_exception -- except Exception with pass or bare assignment, no logging.

        Catches the pattern where an exception is swallowed silently:
        ``except Exception: pass`` or ``except Exception: x = {}``.
        If the handler body references any logging identifier, it is not silent.
        Finalizer methods (__del__) are excluded -- silent cleanup is standard there.
        """
        # Build a set of line ranges for __del__ methods -- silent cleanup is standard there.
        del_ranges: set[range] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "__del__":
                del_ranges.add(range(node.lineno, node.end_lineno + 1 if node.end_lineno else node.lineno + 50))

        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if node.type is None:
                continue
            if not isinstance(node.type, ast.Name) or node.type.id != "Exception":
                continue

            # Skip if inside a __del__ method
            if any(node.lineno in r for r in del_ranges):
                continue

            body = node.body
            if not body:
                continue

            body_ids: set[str] = set()
            for child in ast.walk(ast.Module(body=body, type_ignores=[])):
                if isinstance(child, ast.Name):
                    body_ids.add(child.id)
                elif isinstance(child, ast.Attribute):
                    body_ids.add(child.attr)

            if body_ids & _LOGGING_IDENTIFIERS:
                continue  # has logging -- not silent

            # Check for raise -- if it re-raises, it's not silent
            has_raise = any(isinstance(s, ast.Raise) for s in body)
            if has_raise:
                continue

            # Check if the body is trivially silent: pass, or single assignment
            is_silent = False
            if len(body) == 1:
                stmt = body[0]
                if isinstance(stmt, ast.Pass):
                    is_silent = True
                elif isinstance(stmt, ast.Assign) and isinstance(stmt.value, (ast.Dict, ast.List, ast.Constant)):
                    # bare default assignment like `x = {}` or `x = []` or `x = None`
                    is_silent = True

            if is_silent:
                self._emit(
                    node.lineno,
                    "silent_exception",
                    "'except Exception' silently swallows errors with no logging or re-raise",
                )

    def _check_production_assert(self, tree: ast.Module) -> None:
        """Rule: production_assert -- assert in non-test code.

        ``assert`` statements are stripped when Python runs with ``-O``.
        Production invariants must use explicit ``if not x: raise`` instead.
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                self._emit(
                    node.lineno,
                    "production_assert",
                    "'assert' in production code -- stripped under python -O, use explicit raise",
                )

    def _check_do_nothing_wrapper(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        """Rule: do_nothing_wrapper -- function body is a single return of a call.

        Flags functions whose entire body (excluding docstring) is
        ``return some_function(args)`` where the function adds no validation,
        transformation, or error handling.  These can be inlined at call sites.

        Excluded:
        - Dunder methods and framework contracts (forward, handle, run, _execute).
        - Private helpers (underscore prefix) -- internal delegation is fine.
        - Named accessors/factories under 4 statements (to_payload, create_*, get_*).
        - Property-style accessors (modules, tools, keys, etc.).
        """
        # Skip framework-contract and dunder method names
        if func.name in {
            "forward", "forward_trusted", "handle", "run", "_execute",
            "__init__", "__del__", "__enter__", "__exit__", "format",
        }:
            return

        # Skip private helpers -- internal delegation is a valid pattern
        if func.name.startswith("_"):
            return

        # Skip named accessors, factories, and serialization helpers
        _accessor_prefixes = ("get_", "create_", "build_", "to_", "from_", "is_", "has_")
        if any(func.name.startswith(p) for p in _accessor_prefixes):
            return

        # Skip property-style collection accessors and named domain helpers
        _collection_accessors = {
            "modules", "tools", "keys", "values", "items", "entries",
            "utc_now", "minimum_score", "all_tool_keys", "arrivals",
            "departures", "order_group", "criticality_rank",
        }
        if func.name in _collection_accessors:
            return

        if "property" in _decorator_identifiers(func):
            return

        stmts = func.body
        if not stmts:
            return

        # Strip leading docstring
        real_stmts = stmts
        if (
            len(stmts) >= 1
            and isinstance(stmts[0], ast.Expr)
            and isinstance(stmts[0].value, ast.Constant)
            and isinstance(stmts[0].value.value, str)
        ):
            real_stmts = stmts[1:]

        if len(real_stmts) != 1:
            return

        stmt = real_stmts[0]
        if not isinstance(stmt, ast.Return) or stmt.value is None:
            return
        if not isinstance(stmt.value, ast.Call):
            return

        # The return value is a single function call -- this is a do-nothing wrapper
        # Get the callee name for the message
        callee = stmt.value.func
        if isinstance(callee, ast.Attribute):
            callee_name = callee.attr
        elif isinstance(callee, ast.Name):
            callee_name = callee.id
        else:
            callee_name = "?"

        self._emit(
            func.lineno,
            "do_nothing_wrapper",
            f"function '{func.name}' body is just 'return {callee_name}(...)' -- "
            f"consider inlining at call sites",
        )

    def _check_sync_session_in_async(self, tree: ast.Module) -> None:
        """Rule: sync_in_async -- session_scope() called directly in async def.

        The correct pattern is to define a sync inner function that uses
        session_scope(), then pass it to asyncio.to_thread().  Calling
        session_scope() directly inside an async def body blocks the event loop.

        This check walks the tree for AsyncFunctionDef nodes and reports any
        call to session_scope() that appears at the async function body level
        (i.e., NOT inside a nested sync def).
        """
        for node in ast.walk(tree):
            if not isinstance(node, ast.AsyncFunctionDef):
                continue
            # Collect line ranges of nested sync functions -- calls inside
            # those are fine (they run via asyncio.to_thread).
            sync_ranges: list[range] = []
            for child in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                if isinstance(child, ast.FunctionDef):
                    end = child.end_lineno if child.end_lineno else child.lineno + 50
                    sync_ranges.append(range(child.lineno, end + 1))

            # Now find session_scope() calls in the async body
            for child in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                if not isinstance(child, ast.Call):
                    continue
                callee = child.func
                callee_name: str | None = None
                if isinstance(callee, ast.Name):
                    callee_name = callee.id
                elif isinstance(callee, ast.Attribute):
                    callee_name = callee.attr
                if callee_name != "session_scope":
                    continue
                # Check if this call is inside a nested sync def
                call_line = child.lineno
                inside_sync = any(call_line in r for r in sync_ranges)
                if not inside_sync:
                    self._emit(
                        child.lineno,
                        "sync_in_async",
                        f"sync 'session_scope()' called directly in async def "
                        f"'{node.name}' -- wrap in a sync helper and use "
                        f"asyncio.to_thread()",
                    )

    def _check_api_imports_modules(self, tree: ast.Module) -> None:
        """Rule: api_imports_module_internals -- guarded layers import module internals.

        Files under aila/api/, aila/platform/, and aila/storage/ must not import
        directly from aila.modules.*. Those layers must use module contracts,
        registry lookups, or injected adapters instead.
        """
        layer = "boundary-guarded"
        normalized = self.filename.replace("\\", "/")
        if "/aila/api/" in normalized:
            layer = "api/"
        elif "/aila/platform/" in normalized:
            layer = "platform/"
        elif "/aila/storage/" in normalized:
            layer = "storage/"
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("aila.modules."):
                        self._emit(
                            node.lineno,
                            "api_imports_module_internals",
                            f"{layer} file imports '{alias.name}' -- use module contracts, registry lookups, or injected adapters instead",
                        )
                continue

            if isinstance(node, ast.ImportFrom):
                if node.module is None:
                    continue
                if node.module.startswith("aila.modules."):
                    self._emit(
                        node.lineno,
                        "api_imports_module_internals",
                        f"{layer} file imports from '{node.module}' -- use module contracts, registry lookups, or injected adapters instead",
                    )

    def _check_import_boundary(self, tree: ast.Module, module_id: str) -> None:
        """Rule: import_boundary.

        Emits a finding for any import of aila.modules.{other_id} in a file that
        belongs to aila.modules.{module_id}.
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self._check_boundary_name(alias.name, node.lineno, module_id)
                continue

            if isinstance(node, ast.ImportFrom):
                if node.module is None:
                    continue
                self._check_boundary_name(node.module, node.lineno, module_id)

    def _check_boundary_name(self, dotted: str, lineno: int, module_id: str) -> None:
        """Emit import_boundary if dotted refers to a different aila module."""
        # Only care about aila.modules.* imports.
        if not dotted.startswith("aila.modules."):
            return
        # aila.modules.{segment}...
        rest = dotted[len("aila.modules."):]
        # rest may be empty (bare "aila.modules" import -- not a violation) or
        # "{other_id}" or "{other_id}.something"
        if not rest:
            return
        other_id = rest.split(".")[0]
        if other_id == module_id:
            return
        self._emit(
            lineno,
            "import_boundary",
            f"import of 'aila.modules.{other_id}' violates module boundary "
            f"(file belongs to 'aila.modules.{module_id}')",
        )

    def _check_module_session_scope_import(self, tree: ast.Module) -> None:
        """Rule: module_imports_session_scope.

        Files under aila/modules/ must not import session_scope or
        async_session_scope from storage.database. Data access must go
        through Platform Services (SDA-05).

        Phase 165: rule added with whitelist for all existing violators.
        Phase 166: whitelist entries removed after migration.
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module is None:
                    continue
                if "storage.database" in node.module:
                    for alias in (node.names or []):
                        if alias.name in ("session_scope", "async_session_scope"):
                            self._emit(
                                node.lineno,
                                "module_imports_session_scope",
                                f"module_imports_session_scope: module file imports "
                                f"'{alias.name}' from storage.database -- use "
                                f"Platform Services (SDA-05)",
                            )

    def _check_asyncio_in_module(self, tree: ast.Module) -> None:
        """Rule 18: asyncio_in_module -- threading primitives banned from modules/.

        Platform services own the threading boundary. Module code must never
        call asyncio.to_thread, asyncio.run, loop.run_until_complete,
        loop.run_in_executor, construct a ThreadPoolExecutor, or import from
        concurrent.futures. These are platform-layer responsibilities.
        """
        for node in ast.walk(tree):
            # concurrent.futures import -- flag the import itself
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith("concurrent.futures") or alias.name == "concurrent":
                            self._emit(
                                node.lineno,
                                "asyncio_in_module",
                                f"asyncio_in_module: 'import {alias.name}' -- "
                                f"threading belongs to the platform layer, not modules",
                            )
                elif isinstance(node, ast.ImportFrom):
                    mod = node.module or ""
                    if mod.startswith("concurrent.futures") or mod == "concurrent":
                        self._emit(
                            node.lineno,
                            "asyncio_in_module",
                            f"asyncio_in_module: 'from {mod} import ...' -- "
                            f"threading belongs to the platform layer, not modules",
                        )
                continue

            # asyncio.to_thread / asyncio.run / loop.run_until_complete / loop.run_in_executor
            if not isinstance(node, ast.Call):
                continue
            func_node = node.func
            if isinstance(func_node, ast.Attribute):
                attr = func_node.attr
                if attr in _ASYNCIO_THREAD_ATTRS:
                    # asyncio.to_thread and asyncio.run: object must be 'asyncio'
                    root = _root_name(func_node.value)
                    if attr in ("to_thread", "run"):
                        if root == "asyncio":
                            self._emit(
                                node.lineno,
                                "asyncio_in_module",
                                f"asyncio_in_module: 'asyncio.{attr}()' call -- "
                                f"threading belongs to the platform layer, not modules",
                            )
                    else:
                        # run_until_complete / run_in_executor -- any object (loop variable)
                        self._emit(
                            node.lineno,
                            "asyncio_in_module",
                            f"asyncio_in_module: '.{attr}()' call -- "
                            f"threading belongs to the platform layer, not modules",
                        )
            elif isinstance(func_node, ast.Name) and func_node.id in _THREAD_CLASS_NAMES:
                self._emit(
                    node.lineno,
                    "asyncio_in_module",
                    f"asyncio_in_module: '{func_node.id}()' construction \u2014 "
                    "threading belongs to the platform layer, not modules",
                )

    def _check_http_client_in_module(self, tree: ast.Module) -> None:
        """Rule 22: http_client_in_module -- direct HTTP client imports in modules/.

        Modules must not construct their own HTTP clients. HTTP transport
        is a platform concern -- use SSHService, IDABridgeTool, or platform
        HTTP helpers. Direct httpx/requests/urllib3/aiohttp imports bypass
        platform connection management and observability.
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top in _HTTP_CLIENT_MODULES:
                        self._emit(
                            node.lineno,
                            "http_client_in_module",
                            f"http_client_in_module: 'import {alias.name}' -- "
                            f"HTTP clients belong to the platform layer, not modules",
                        )
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                top = mod.split(".")[0]
                if top in _HTTP_CLIENT_MODULES:
                    self._emit(
                        node.lineno,
                        "http_client_in_module",
                        f"http_client_in_module: 'from {mod} import ...' -- "
                        f"HTTP clients belong to the platform layer, not modules",
                    )

    def _check_direct_db_in_module(self, tree: ast.Module) -> None:
        """Rule 23: direct_db_in_module -- direct DB driver imports in modules/.

        Modules access the database exclusively through ``UnitOfWork`` from
        ``aila.platform.uow``. Direct imports of connection-layer libraries
        (asyncpg, psycopg2, sqlite3) or engine-construction functions
        (create_engine, create_async_engine) bypass team scoping, audit
        trails, and connection-pool management.
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top in _DIRECT_DB_MODULES:
                        self._emit(
                            node.lineno,
                            "direct_db_in_module",
                            f"direct_db_in_module: 'import {alias.name}' -- "
                            f"use UnitOfWork from aila.platform.uow instead",
                        )
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                top = mod.split(".")[0]
                if top in _DIRECT_DB_MODULES:
                    self._emit(
                        node.lineno,
                        "direct_db_in_module",
                        f"direct_db_in_module: 'from {mod} import ...' -- "
                        f"use UnitOfWork from aila.platform.uow instead",
                    )
                # Also catch create_engine / create_async_engine from sqlalchemy
                if mod.startswith("sqlalchemy"):
                    for alias in (node.names or []):
                        if alias.name in _DIRECT_DB_CALLABLES:
                            self._emit(
                                node.lineno,
                                "direct_db_in_module",
                                f"direct_db_in_module: 'from {mod} import {alias.name}' -- "
                                f"use UnitOfWork from aila.platform.uow instead",
                            )

    # ------------------------------------------------------------------
    # Rules 24–33: AI slop detection
    # ------------------------------------------------------------------

    def _check_tautological_docstring(self, tree: ast.Module) -> None:
        """Rule 24: docstring that just restates the function/class name."""
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            doc = ast.get_docstring(node)
            if not doc or len(doc.split()) > 6:
                continue
            name_words = set(_re.findall(r'[a-z]+', node.name.lower()))
            doc_words = set(_re.findall(r'[a-z]+', doc.lower()))
            # Tautological if every name word appears in the docstring and
            # the docstring adds at most one filler word ("the", "a", etc.).
            filler = {"the", "a", "an", "of", "for", "to", "in", "on", "is", "and"}
            extra = doc_words - name_words - filler
            if name_words and not extra:
                self._emit(
                    node.lineno,
                    "tautological_docstring",
                    f"tautological_docstring: '{node.name}' docstring \"{doc}\" "
                    f"restates the name with no added information",
                )

    def _check_commented_out_code(self, source: str, filepath: str) -> None:
        """Rule 25: commented-out Python statements."""
        normalized = filepath.replace("\\", "/")
        if _ALEMBIC_PATH_PATTERN.search(normalized):
            return  # migrations legitimately have commented SQL/Python
        for suffix in _NOQA_SELF_EXEMPT_SUFFIXES:
            if normalized.endswith(suffix):
                return  # audit tool itself has commented-out examples
        for lineno, line in enumerate(source.splitlines(), start=1):
            if not _COMMENTED_CODE_RE.match(line):
                continue
            lower = line.lower()
            if any(ex in lower for ex in _COMMENTED_CODE_EXEMPTIONS):
                continue
            self._emit(
                lineno,
                "commented_out_code",
                "commented_out_code: line looks like commented-out Python -- "
                "delete dead code instead of commenting it out",
            )

    def _check_except_return_default(self, tree: ast.Module) -> None:
        """Rule 26: except handler that returns an empty default, hiding failures."""
        _empty_defaults = (type(None), int, float, str)  # None, 0, 0.0, ""
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if len(node.body) != 1 or not isinstance(node.body[0], ast.Return):
                continue
            val = node.body[0].value
            is_empty = False
            if val is None:
                is_empty = True
            elif isinstance(val, ast.Constant) and type(val.value) in _empty_defaults:
                if val.value in (None, 0, 0.0, ""):
                    is_empty = True
            elif isinstance(val, ast.Dict) and not val.keys:
                is_empty = True
            elif isinstance(val, (ast.List, ast.Tuple, ast.Set)) and not val.elts:
                is_empty = True
            if is_empty:
                self._emit(
                    node.lineno,
                    "except_return_default",
                    "except_return_default: except returns empty default -- "
                    "this silently hides failures; log or propagate instead",
                )

    def _check_nested_if_collapsible(self, tree: ast.Module) -> None:
        """Rule 27: if whose body is a single if (no else on either) -- combine with and."""
        for node in ast.walk(tree):
            if not isinstance(node, ast.If):
                continue
            if node.orelse:
                continue
            if len(node.body) != 1:
                continue
            inner = node.body[0]
            if isinstance(inner, ast.If) and not inner.orelse:
                self._emit(
                    node.lineno,
                    "nested_if_collapsible",
                    "nested_if_collapsible: nested if with no else on either branch "
                    "-- combine with 'and' for readability",
                )

    def _check_pointless_pass(self, tree: ast.Module) -> None:
        """Rule 28: pass as sole body of non-abstract, non-decorator-stub function."""
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Strip docstring
            body = [s for s in node.body
                    if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
                            and isinstance(s.value.value, str))]
            if len(body) != 1 or not isinstance(body[0], ast.Pass):
                continue
            dec_names = set()
            for d in node.decorator_list:
                if isinstance(d, ast.Attribute):
                    dec_names.add(d.attr)
                elif isinstance(d, ast.Name):
                    dec_names.add(d.id)
            exempt = {"abstractmethod", "overload", "platform_task"}
            if dec_names & exempt:
                continue
            self._emit(
                node.lineno,
                "pointless_pass",
                f"pointless_pass: '{node.name}()' body is only 'pass' "
                f"-- implement or mark @abstractmethod",
            )

    def _check_f_string_no_interpolation(self, tree: ast.Module) -> None:
        """Rule 29: f-string with no embedded expressions.

        Skips JoinedStr nodes that appear as format_spec inside a
        FormattedValue -- those are formatting directives (e.g. ``<6``
        in ``f"{'ID':<6}"``) and are not independent f-strings.
        """
        format_spec_ids: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.FormattedValue) and isinstance(node.format_spec, ast.JoinedStr):
                format_spec_ids.add(id(node.format_spec))
        for node in ast.walk(tree):
            if not isinstance(node, ast.JoinedStr):
                continue
            if id(node) in format_spec_ids:
                continue
            if not any(isinstance(v, ast.FormattedValue) for v in node.values):
                self._emit(
                    node.lineno,
                    "f_string_no_interpolation",
                    "f_string_no_interpolation: f-string has no interpolated expressions "
                    "\u2014 use a plain string instead",
                )

    def _check_single_use_variable(self, tree: ast.Module) -> None:
        """Rule 30: variable assigned then immediately returned with no other use."""
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            body = node.body
            if len(body) < 2:
                continue
            last = body[-1]
            prev = body[-2]
            if not (isinstance(last, ast.Return) and isinstance(last.value, ast.Name)):
                continue
            if not (isinstance(prev, ast.Assign) and len(prev.targets) == 1
                    and isinstance(prev.targets[0], ast.Name)):
                continue
            name = last.value.id
            if prev.targets[0].id != name:
                continue
            # Count all references to this name in the entire function body
            refs = sum(1 for n in ast.walk(node)
                       if isinstance(n, ast.Name) and n.id == name)
            if refs == 2:  # one assign target, one return value
                self._emit(
                    prev.lineno,
                    "single_use_variable",
                    f"single_use_variable: '{name}' is assigned and immediately returned "
                    f"-- return the expression directly",
                )

    def _check_placeholder_return(self, tree: ast.Module) -> None:
        """Rule 31: function body is only docstring + return {} or return []."""
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            body = [s for s in node.body
                    if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
                            and isinstance(s.value.value, str))]
            if len(body) != 1 or not isinstance(body[0], ast.Return):
                continue
            val = body[0].value
            if isinstance(val, ast.Dict) and not val.keys:
                self._emit(node.lineno, "placeholder_return",
                           f"placeholder_return: '{node.name}()' returns empty dict {{}} "
                           f"-- implement or raise NotImplementedError")
            elif isinstance(val, (ast.List, ast.Tuple)) and not val.elts:
                self._emit(node.lineno, "placeholder_return",
                           f"placeholder_return: '{node.name}()' returns empty collection "
                           f"-- implement or raise NotImplementedError")

    def _check_log_format_concat(self, tree: ast.Module) -> None:
        """Rule 32: logging call uses f-string or concatenation instead of %-formatting."""
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr in _LOG_METHODS):
                continue
            if not node.args:
                continue
            first_arg = node.args[0]
            if isinstance(first_arg, ast.JoinedStr):
                self._emit(node.lineno, "log_format_concat",
                           f"log_format_concat: logging.{func.attr}(f'...') -- "
                           f"use %-formatting: .{func.attr}('x=%s', x)")
            elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add):
                self._emit(node.lineno, "log_format_concat",
                           f"log_format_concat: logging.{func.attr}('...' + ...) -- "
                           f"use %-formatting: .{func.attr}('x=%s', x)")

    def _check_broad_exception_catch(self, tree: ast.Module) -> None:
        """Rule 33: except Exception without a justifying comment."""
        try:
            ast.unparse(tree)  # validate the AST round-trips before walking
        except (ValueError, TypeError):
            return
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if node.type is None:
                # bare except: -- even worse, but rule 12 covers this
                continue
            exc_name = ""
            if isinstance(node.type, ast.Name):
                exc_name = node.type.id
            elif isinstance(node.type, ast.Attribute):
                exc_name = node.type.attr
            if exc_name != "Exception":
                continue
            self._emit(
                node.lineno,
                "broad_exception_catch",
                "broad_exception_catch: 'except Exception' catches everything indiscriminately "
                "-- catch specific exception types",
            )

    def _check_response_model_dict(self, tree: ast.Module) -> None:
        """Rule 19: response_model_dict -- @router.* with response_model=dict/Dict.

        FastAPI endpoints must return a typed Pydantic schema, not a bare dict.
        Using response_model=dict bypasses response validation and schema
        generation, hiding what the endpoint actually returns.
        """
        _dict_names: frozenset[str] = frozenset({"dict", "Dict"})

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call):
                    continue
                # The decorator must be router.get / router.post / etc.
                dec_func = dec.func
                if not isinstance(dec_func, ast.Attribute):
                    continue
                if dec_func.attr not in {"get", "post", "put", "delete", "patch"}:
                    continue
                # Check keywords for response_model=dict / response_model=Dict
                for kw in dec.keywords:
                    if kw.arg != "response_model":
                        continue
                    val = kw.value
                    # response_model=dict or response_model=Dict
                    if isinstance(val, ast.Name) and val.id in _dict_names:
                        self._emit(
                            dec.lineno,
                            "response_model_dict",
                            f"response_model_dict: endpoint '{node.name}' uses "
                            f"response_model={val.id} -- use a typed Pydantic schema instead",
                        )
                    # response_model=typing.Dict
                    elif isinstance(val, ast.Attribute) and val.attr == "Dict":
                        self._emit(
                            dec.lineno,
                            "response_model_dict",
                            f"response_model_dict: endpoint '{node.name}' uses "
                            f"response_model=typing.Dict -- use a typed Pydantic schema instead",
                        )
                    # response_model=dict | None  (BinOp with left=dict)
                    elif isinstance(val, ast.BinOp):
                        left = val.left
                        if isinstance(left, ast.Name) and left.id in _dict_names:
                            self._emit(
                                dec.lineno,
                                "response_model_dict",
                                f"response_model_dict: endpoint '{node.name}' uses "
                                f"response_model={left.id} | ... -- use a typed Pydantic schema instead",
                            )

    def _check_bare_dict_return_endpoint(self, tree: ast.Module) -> None:
        """Rule 20: bare_dict_return_endpoint -- endpoint handler returns a raw dict.

        Functions decorated with @router.* must return a Pydantic model instance,
        not a plain dict literal or dict() call. Raw dict returns bypass response
        validation and OpenAPI schema generation.

        Also flags JSONResponse(content={...}) which is another form of the same
        anti-pattern: ad-hoc dict at the response boundary instead of a typed model.
        """
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Check if decorated with @router.*
            is_endpoint = False
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                    if dec.func.attr in {"get", "post", "put", "delete", "patch"}:
                        is_endpoint = True
                        break
                elif isinstance(dec, ast.Attribute) and dec.attr in {"get", "post", "put", "delete", "patch"}:
                    is_endpoint = True
                    break

            if not is_endpoint:
                continue

            # Walk the function body for Return nodes with dict values.
            # Use _walk_returns_shallow to avoid false positives from nested
            # helper functions (e.g. async def _query()) that return dicts
            # internally while the outer endpoint returns a typed Pydantic model.
            for child in _walk_returns_shallow(node):
                if not isinstance(child, ast.Return) or child.value is None:
                    continue
                ret_val = child.value

                # return {"key": val}  -- ast.Dict literal
                if isinstance(ret_val, ast.Dict):
                    self._emit(
                        child.lineno,
                        "bare_dict_return_endpoint",
                        f"bare_dict_return_endpoint: endpoint '{node.name}' returns a raw "
                        f"dict literal -- return a typed Pydantic model instead",
                    )
                    continue

                # return dict(...)  -- dict() constructor call
                if (
                    isinstance(ret_val, ast.Call)
                    and isinstance(ret_val.func, ast.Name)
                    and ret_val.func.id == "dict"
                ):
                    self._emit(
                        child.lineno,
                        "bare_dict_return_endpoint",
                        f"bare_dict_return_endpoint: endpoint '{node.name}' returns dict() -- "
                        f"return a typed Pydantic model instead",
                    )
                    continue

                # return JSONResponse(content={...})
                if isinstance(ret_val, ast.Call):
                    func_node = ret_val.func
                    callee_name = None
                    if isinstance(func_node, ast.Name):
                        callee_name = func_node.id
                    elif isinstance(func_node, ast.Attribute):
                        callee_name = func_node.attr
                    if callee_name == "JSONResponse":
                        for kw in ret_val.keywords:
                            if kw.arg == "content" and isinstance(kw.value, ast.Dict):
                                self._emit(
                                    child.lineno,
                                    "bare_dict_return_endpoint",
                                    f"bare_dict_return_endpoint: endpoint '{node.name}' returns "
                                    f"JSONResponse(content={{...}}) -- return a typed Pydantic model instead",
                                )
                                break

    def _check_noqa_inline(self, source: str, filepath: str) -> None:
        """Rule 21: noqa_inline -- inline # noqa comments in production source.

        All linter suppressions must go through honesty_whitelist.py with a
        documented justification. Inline # noqa is banned because it silently
        hides violations without requiring a reason.

        Self-exempt files: honesty_audit.py and honesty_whitelist.py themselves.
        Alembic migration files are also exempt (auto-generated code).
        """
        normalized = filepath.replace("\\", "/")

        # Self-exemption: audit tool and whitelist are allowed to reference noqa
        for suffix in _NOQA_SELF_EXEMPT_SUFFIXES:
            if normalized.endswith(suffix):
                return

        # Alembic migrations are auto-generated -- exempt from this rule
        if _ALEMBIC_PATH_PATTERN.search(normalized):
            return

        for lineno, line in enumerate(source.splitlines(), start=1):
            if _NOQA_PATTERN.search(line):
                self._emit(
                    lineno,
                    "noqa_inline",
                    f"noqa_inline: inline '# noqa' comment on line {lineno} -- "
                    f"use honesty_whitelist.py with a documented justification instead",
                )

    def _check_hoisted_enum_redeclared(self, tree: ast.Module, module_id: str) -> None:
        """Rule 34: hoisted_enum_redeclared -- a unified module redeclares a platform enum.

        The enums in _HOISTED_ENUM_NAMES are owned by
        aila.platform.contracts.enums. A vr/malware contracts file must import
        them, never declare its own StrEnum of the same name. Scoped to the
        unified modules: forensics and vulnerability keep independent enums that
        happen to share a class name (e.g. their own InvestigationStatus).
        """
        if module_id not in _RFC01_UNIFIED_MODULES:
            return
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef) or node.name not in _HOISTED_ENUM_NAMES:
                continue
            if "StrEnum" not in _classdef_base_names(node):
                continue
            self._emit(
                node.lineno,
                "hoisted_enum_redeclared",
                f"hoisted_enum_redeclared: enum '{node.name}' is owned by "
                f"platform.contracts.enums -- import it instead of redeclaring",
            )

    def _check_unnamed_derived_constraint(self, tree: ast.Module, module_id: str) -> None:
        """Rule 35: unnamed_derived_constraint -- a unified table hand-names a UQ.

        A vr/malware investigation-engine table must derive its unique-constraint
        name from the tablename via TabledUq, not hard-code a literal. Scoped to
        the unified tables so other modules keep their own constraint names.
        """
        if module_id not in _RFC01_UNIFIED_MODULES:
            return
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef) or not _classdef_is_table(node):
                continue
            tablename = _classdef_tablename(node)
            if tablename is None:
                continue
            if _strip_module_prefix(tablename, module_id) not in _UNIFIED_ROLE_BASES:
                continue
            derived_prefix = f"uq_{tablename}_"
            for literal, lineno in _unique_constraint_literal_names(node):
                if not literal.startswith(derived_prefix):
                    self._emit(
                        lineno,
                        "unnamed_derived_constraint",
                        f"unnamed_derived_constraint: table '{tablename}' hard-codes "
                        f"constraint name '{literal}' -- derive it via TabledUq "
                        f"({derived_prefix}...)",
                    )

    def _check_shadowed_platform_base(self, tree: ast.Module, module_id: str) -> None:
        """Rule 36: shadowed_platform_base -- a unified table recreates base columns.

        A vr/malware investigation-engine table whose role maps to a platform
        base must subclass that base, not redeclare its columns. Fires when the
        class does not subclass the base yet redeclares four or more of its
        fields. The base field set is read from platform/contracts via AST.
        """
        if module_id not in _RFC01_UNIFIED_MODULES:
            return
        contracts_dir = _platform_contracts_dir(self.filename)
        if contracts_dir is None:
            return
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef) or not _classdef_is_table(node):
                continue
            tablename = _classdef_tablename(node)
            if tablename is None:
                continue
            base_class = _UNIFIED_ROLE_BASES.get(_strip_module_prefix(tablename, module_id))
            if base_class is None or base_class in _classdef_base_names(node):
                continue
            base_file = contracts_dir / _BASE_FILE_BY_CLASS[base_class]
            base_fields = _platform_base_field_names(base_file, base_class)
            if not base_fields:
                continue
            overlap = _sqlmodel_field_names(node) & base_fields
            if len(overlap) >= 4:
                self._emit(
                    node.lineno,
                    "shadowed_platform_base",
                    f"shadowed_platform_base: table '{tablename}' recreates "
                    f"{len(overlap)} columns of {base_class} -- subclass "
                    f"{base_class} instead",
                )

    def _check_config_schema_base(self, tree: ast.Module) -> None:
        """Rule 37: module_config_schema_base -- a module config schema must
        subclass ModuleConfigBase.

        A ``*ConfigSchema`` class in a ``modules/<name>/config_schema.py``
        file must subclass ``aila.platform.config_base.ModuleConfigBase``,
        which bakes in ``extra=forbid``. Subclassing bare ``BaseModel``
        lets an undeclared config key pass at construction instead of
        failing closed -- the gap vulnerability carried before RFC-04
        Phase 2.
        """
        if not _CONFIG_SCHEMA_PATH_PATTERN.search(self.filename.replace("\\", "/")):
            return
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef) or not node.name.endswith("ConfigSchema"):
                continue
            if "ModuleConfigBase" in _classdef_base_names(node):
                continue
            self._emit(
                node.lineno,
                "module_config_schema_base",
                f"module_config_schema_base: config schema '{node.name}' must "
                "subclass ModuleConfigBase (bakes in extra=forbid) instead of "
                "bare BaseModel",
            )

    def _check_service_copy_of_platform(self, tree: ast.Module) -> None:
        """Rule 38: service_copy_of_platform -- a vr/malware service duplicates
        a platform service.

        A file under modules/vr/services or modules/malware/services whose
        comment- and format-normalized body matches a platform service above
        the similarity threshold is the copy-and-rename pattern RFC-04 lifted
        out. After a service is lifted the module keeps only a thin binding, so
        a high-similarity match means a full copy slipped back in. Length
        asymmetry keeps thin bindings well under the threshold; only a
        same-size copy trips it. Scoped to the vr/malware copy set; forensics
        keeps an independent variant.
        """
        if not _SERVICE_COPY_SCOPE_PATTERN.search(self.filename.replace("\\", "/")):
            return
        try:
            own = ast.unparse(tree)
        except (ValueError, RecursionError):
            return
        if not own.strip():
            return
        best_name = ""
        best_ratio = 0.0
        own_len = len(own)
        for name, platform_src in _platform_service_corpus(self.filename).items():
            p_len = len(platform_src)
            if p_len == 0:
                continue
            # Length ceiling: the best achievable ratio is 2*min/(sum). Below
            # the threshold the pair cannot match, so skip the O(n*m) compare.
            # This prunes every thin binding (short) against a full platform
            # impl (long) in O(1).
            if 2 * min(own_len, p_len) / (own_len + p_len) < _SERVICE_COPY_THRESHOLD:
                continue
            matcher = difflib.SequenceMatcher(None, own, platform_src)
            if matcher.quick_ratio() < _SERVICE_COPY_THRESHOLD:
                continue
            ratio = matcher.ratio()
            if ratio > best_ratio:
                best_ratio = ratio
                best_name = name
        if best_ratio >= _SERVICE_COPY_THRESHOLD:
            self._emit(
                1,
                "service_copy_of_platform",
                f"service_copy_of_platform: normalized body is {best_ratio:.0%} "
                f"similar to platform/{best_name}; lift the shared logic to the "
                "platform and keep a thin binding here",
            )

    def _check_workflow_state_copy_of_platform(self, tree: ast.Module) -> None:
        """Rule 41: workflow_state_copy_of_platform -- a vr/malware
        investigation state file duplicates a platform state base.

        RFC-02 Phase 4 extracted the setup/loop/emit turn engine to
        platform/workflows/investigation_*_base.py; each module keeps only
        a thin factory binding. A file whose normalized body matches a
        platform base above the similarity threshold is a copy that
        slipped back in. The length ceiling keeps thin bindings well under
        the threshold; only a same-size copy trips it.
        """
        if not _WORKFLOW_STATE_SCOPE_PATTERN.search(
            self.filename.replace("\\", "/"),
        ):
            return
        try:
            own = ast.unparse(tree)
        except (ValueError, RecursionError):
            return
        if not own.strip():
            return
        best_name = ""
        best_ratio = 0.0
        own_len = len(own)
        for name, base_src in _workflow_base_corpus(self.filename).items():
            b_len = len(base_src)
            if b_len == 0:
                continue
            if 2 * min(own_len, b_len) / (own_len + b_len) < _SERVICE_COPY_THRESHOLD:
                continue
            matcher = difflib.SequenceMatcher(None, own, base_src)
            if matcher.quick_ratio() < _SERVICE_COPY_THRESHOLD:
                continue
            ratio = matcher.ratio()
            if ratio > best_ratio:
                best_ratio = ratio
                best_name = name
        if best_ratio >= _SERVICE_COPY_THRESHOLD:
            self._emit(
                1,
                "workflow_state_copy_of_platform",
                f"workflow_state_copy_of_platform: normalized body is "
                f"{best_ratio:.0%} similar to platform/{best_name}; bind the "
                "platform state factory instead of copying it",
            )

    def _check_agent_llm_chat_bypass(self, tree: ast.Module) -> None:
        """Rule 43: agent_llm_chat_bypass -- a module agents/ file calls the
        raw llm_client.chat() instead of the idempotent wrapper.

        RFC-03 Phase 2 routes the module agent LLM calls through
        platform.agents.idempotent_llm_call so a retried worker replays the
        cached response instead of paying the model API a second time. A
        direct ``<x>.llm_client.chat(...)`` / ``.chat_json(...)`` /
        ``.chat_structured(...)`` (or the same on ``self._llm``) in a module
        agents/ file is a bypass that reintroduces the double-pay.
        """
        if not _AGENTS_SCOPE_PATTERN.search(self.filename.replace("\\", "/")):
            return
        _methods = ("chat", "chat_json", "chat_structured")
        _receivers = ("llm_client", "_llm")
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if not (isinstance(fn, ast.Attribute) and fn.attr in _methods):
                continue
            recv = fn.value
            if isinstance(recv, ast.Attribute) and recv.attr in _receivers:
                self._emit(
                    node.lineno,
                    "agent_llm_chat_bypass",
                    "agent_llm_chat_bypass: route this LLM call through "
                    "platform.agents.idempotent_llm_call for retry safety",
                )

    def _check_agent_primitive_reimplementation(self, tree: ast.Module) -> None:
        """Rule 42: agent_primitive_reimplementation -- a module agents/ file
        defines a platform-owned agent primitive at top level.

        RFC-03 Phase 1 extracted the operator-intent classifier and the
        auto-steering injector to platform/agents/. Modules import them; a
        top-level (re)definition is a copy that drifts from the platform
        version. Import re-exports are statements, not defs, so they never
        trip this.
        """
        if not _AGENTS_SCOPE_PATTERN.search(self.filename.replace("\\", "/")):
            return
        for node in tree.body:
            is_def = isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef),
            )
            if is_def and node.name in _LIFTED_AGENT_PRIMITIVES:
                self._emit(
                    node.lineno,
                    "agent_primitive_reimplementation",
                    f"agent_primitive_reimplementation: '{node.name}' is owned "
                    "by platform/agents/; import it instead of redefining it",
                )

    def _check_cost_read_stored_actual(
        self, tree: ast.Module, module_id: str,
    ) -> None:
        """Rule 39: cost_read_stored_actual -- a lifecycle api_router reads the
        dead ``cost_actual_usd`` column in a response instead of aggregating
        live cost.

        The ``cost_actual_usd`` column has no writers, so any read of it in a
        response body reports a permanent $0. The live gauge comes from
        ``compute_live_investigation_cost`` (sum LLMCostRecord by run_id). A
        handler that reads ``record.cost_actual_usd`` without an aggregator
        call in the same function has drifted back to the broken read. Scoped
        to the vr/malware api_router; the create-time ``cost_actual_usd=0.0``
        keyword is an insert, not an attribute read, so it never trips.
        """
        if module_id not in _RFC01_UNIFIED_MODULES:
            return
        if not self.filename.replace("\\", "/").endswith("/api_router.py"):
            return
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            reads = [
                n for n in ast.walk(node)
                if isinstance(n, ast.Attribute)
                and n.attr == "cost_actual_usd"
                and isinstance(n.ctx, ast.Load)
            ]
            if not reads:
                continue
            has_aggregator = any(
                isinstance(c, ast.Call)
                and (
                    (isinstance(c.func, ast.Name)
                     and c.func.id == "compute_live_investigation_cost")
                    or (isinstance(c.func, ast.Attribute)
                        and c.func.attr == "compute_live_investigation_cost")
                )
                for c in ast.walk(node)
            )
            if has_aggregator:
                continue
            self._emit(
                reads[0].lineno,
                "cost_read_stored_actual",
                f"cost_read_stored_actual: '{node.name}' reads "
                "record.cost_actual_usd in a response; that column has no "
                "writers (always $0). Aggregate live cost via "
                "compute_live_investigation_cost instead",
            )

    def _check_lifecycle_handler_bypass(
        self, tree: ast.Module, module_id: str,
    ) -> None:
        """Rule 40: lifecycle_handler_bypass_service -- a pause / resume /
        re-enqueue route handler writes ``.status`` directly instead of
        routing through the platform investigation lifecycle service.

        The four-source-of-truth transition (inv row, cursor, taskrecord,
        ARQ) is a platform property; a handler that assigns ``.status``
        itself is the drift that left the malware lifecycle broken. Scoped to
        the vr/malware api_router pause / resume / re-enqueue routes. ``reset``
        is intentionally excluded: it is a full-wipe that legitimately resets
        ``status`` to CREATED and does not go through the lifecycle service.
        """
        if module_id not in _RFC01_UNIFIED_MODULES:
            return
        if not self.filename.replace("\\", "/").endswith("/api_router.py"):
            return
        _lifecycle_suffixes = ("/pause", "/resume", "/re-enqueue")
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            route = _endpoint_route_path(node)
            if route is None or not route.endswith(_lifecycle_suffixes):
                continue
            for sub in ast.walk(node):
                if not isinstance(sub, ast.Assign):
                    continue
                if any(
                    isinstance(tgt, ast.Attribute) and tgt.attr == "status"
                    for tgt in sub.targets
                ):
                    self._emit(
                        sub.lineno,
                        "lifecycle_handler_bypass_service",
                        f"lifecycle_handler_bypass_service: '{node.name}' writes "
                        ".status directly; route pause / resume / re-enqueue "
                        "through the platform investigation lifecycle service",
                    )
                    break


class HonestyAuditor:
    """Audit one or more Python source files for structural dishonesty.

    Runs as a pre-commit CI gate: ``python -m aila.tools.honesty_audit src/``
    exits with code 1 if any finding is reported, 0 if clean.  Run with
    ``--whitelist honesty_whitelist.py`` to suppress known acceptable violations.

    The whitelist file (honesty_whitelist.py at the project root) defines
    HONESTY_WHITELIST as a list of (filename_suffix, function_name, detail) string
    triples.  A finding is suppressed when all three fields match -- this prevents
    accidentally suppressing findings in other files with the same function name.

    All analysis is AST-based (D-04 constraint): no imports are executed, no
    runtime state is inspected.  This makes the auditor safe to run on any Python
    file regardless of its dependencies.

    Args:
        whitelist: Set of (filename_suffix, function_name, detail) triples
            that suppress matching findings.  Load via ``load_whitelist(path)``
            or pass an empty set (or None) to disable suppression.
    """

    def __init__(self, whitelist: Whitelist | None = None) -> None:
        self._whitelist: Whitelist = whitelist if whitelist is not None else set()

    def audit_file(self, path: Path) -> list[Finding]:
        """Parse *path* and return all honesty findings (unsuppressed)."""
        source = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            return []

        visitor = _HonestyVisitor(filename=str(path), whitelist=self._whitelist)
        visitor.visit(tree)
        # Module-level checks (not per-function)
        visitor._check_private_in_all(tree)
        visitor._check_bare_exception_wrap(tree)
        visitor._check_todo_in_code(source)
        visitor._check_silent_exception(tree)
        visitor._check_production_assert(tree)
        visitor._check_sync_session_in_async(tree)
        module_id = _owning_module_id(str(path))
        if module_id is not None:
            visitor._check_import_boundary(tree, module_id)
            visitor._check_hoisted_enum_redeclared(tree, module_id)
            visitor._check_unnamed_derived_constraint(tree, module_id)
            visitor._check_shadowed_platform_base(tree, module_id)
            visitor._check_service_copy_of_platform(tree)
            visitor._check_workflow_state_copy_of_platform(tree)
            visitor._check_cost_read_stored_actual(tree, module_id)
            visitor._check_lifecycle_handler_bypass(tree, module_id)
            visitor._check_agent_primitive_reimplementation(tree)
            visitor._check_agent_llm_chat_bypass(tree)
        if _is_boundary_guarded_file(str(path)):
            visitor._check_api_imports_modules(tree)
        if _is_module_file(str(path)):
            visitor._check_module_session_scope_import(tree)
            visitor._check_asyncio_in_module(tree)
            visitor._check_http_client_in_module(tree)
            visitor._check_direct_db_in_module(tree)
        # Rules 19 and 20 apply to all router files (api/ and module routers alike)
        visitor._check_response_model_dict(tree)
        visitor._check_bare_dict_return_endpoint(tree)
        # Rule 21 applies to all Python source files (self-exemption handled inside)
        visitor._check_noqa_inline(source, str(path))
        # Rules 24–33: AI slop detection (apply to all Python source files)
        visitor._check_tautological_docstring(tree)
        visitor._check_commented_out_code(source, str(path))
        visitor._check_except_return_default(tree)
        visitor._check_nested_if_collapsible(tree)
        visitor._check_pointless_pass(tree)
        visitor._check_f_string_no_interpolation(tree)
        visitor._check_single_use_variable(tree)
        visitor._check_placeholder_return(tree)
        visitor._check_log_format_concat(tree)
        visitor._check_broad_exception_catch(tree)
        visitor._check_config_schema_base(tree)
        return visitor.findings

    def audit_directory(self, directory: Path) -> list[Finding]:
        """Recursively audit all *.py files under *directory*."""
        findings: list[Finding] = []
        for py_file in sorted(directory.rglob("*.py")):
            findings.extend(self.audit_file(py_file))
        return findings


# ---------------------------------------------------------------------------
# __main__ entrypoint
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str]) -> tuple[Path, Path | None]:
    """Return (target_dir, whitelist_path | None) from *argv*."""
    if not argv:
        _log.error("Usage: python -m aila.tools.honesty_audit <directory> [--whitelist <path>]")
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
    "honesty_whitelist.py",
    "src/aila/tools/honesty_whitelist.py",
)


def _find_default_whitelist(target: Path) -> Path | None:
    """Look for honesty_whitelist.py relative to the target directory or cwd.

    Walks up from the target directory looking for the project root (where
    pyproject.toml lives), then checks standard locations.
    """
    # Walk up to find project root (contains pyproject.toml or src/)
    candidates = [target] + list(target.parents)
    for directory in candidates:
        for name in _DEFAULT_WHITELIST_NAMES:
            candidate = directory / name
            if candidate.exists():
                return candidate
    return None


def _main(argv: list[str]) -> int:
    """CLI entrypoint: audit target and print findings to stdout.

    When no --whitelist argument is given, automatically searches for
    honesty_whitelist.py relative to the target directory. This allows
    ``python -m aila.tools.honesty_audit src/`` to automatically load
    the project whitelist without requiring an explicit --whitelist flag.

    Args:
        argv: Command-line arguments excluding the script name.

    Returns:
        Exit code: 0 if no findings, 1 if findings exist, 2 on usage error.
    """
    target, whitelist_path = _parse_args(argv)

    # Auto-discover whitelist if not explicitly specified
    if whitelist_path is None:
        whitelist_path = _find_default_whitelist(target)
        if whitelist_path is not None:
            _log.debug("honesty_audit: auto-loaded whitelist from %s", whitelist_path)

    whitelist: Whitelist = set()
    if whitelist_path is not None:
        if not whitelist_path.exists():
            _log.error("whitelist file not found: %s", whitelist_path)
            return 2
        whitelist = load_whitelist(whitelist_path)

    auditor = HonestyAuditor(whitelist=whitelist)

    if target.is_file():
        findings = auditor.audit_file(target)
    elif target.is_dir():
        findings = auditor.audit_directory(target)
    else:
        _log.error("target not found: %s", target)
        return 2

    for f in findings:
        _log.warning("%s:%d: [%s] %s", f.file, f.line, f.rule, f.message)

    return 1 if findings else 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    sys.exit(_main(sys.argv[1:]))
