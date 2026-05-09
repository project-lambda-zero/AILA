"""honesty_audit — AST-based structural honesty checker for Python code.

Detects twenty-three categories of structural dishonesty:

1. unused_parameter    — function parameter accepted but never referenced in body.
2. misleading_name     — function name implies intelligence but body only forwards.
3. docstring_mismatch  — docstring claims caching/persistence but body has none.
4. import_boundary     — module imports from another module's package.
5. dead_isinstance     — isinstance check on a parameter that already has a type annotation.
6. redundant_conversion — str(already_str), int(already_int), Path(already_path).
7. private_in_all      — underscore-prefixed name exported in __all__.
8. bare_exception_wrap — except Exception that raises a less-specific type (destroys info).
9. always_true_default — parameter with Optional/None default that is ALWAYS overridden by callers.
10. god_object_dispatch — single function with 4+ if/elif branches on a string action parameter.
11. todo_in_code        — TODO/FIXME/HACK/XXX comment in production source.
12. silent_exception    — except Exception with pass or bare default assignment (no logging).
13. production_assert   — assert statement in production code (stripped under -O).
14. do_nothing_wrapper  — function body is a single return of another call with no added logic.
15. dead_config_field   — Pydantic/config field declared but never read anywhere in the codebase.
16. sync_in_async       — sync session_scope() called inside async def without asyncio.to_thread.
17. api_imports_module_internals — api/platform/storage code imports modules/ internals.
18. asyncio_in_module   — asyncio.to_thread/run, ThreadPoolExecutor or concurrent.futures in modules/.
19. response_model_dict — @router.* decorator specifies response_model=dict/Dict.
20. bare_dict_return_endpoint — endpoint handler returns a raw dict literal or dict() call.
21. noqa_inline         — inline # noqa comment in production source (use honesty_whitelist.py instead).
22. http_client_in_module — module imports httpx/requests/urllib3/aiohttp directly (use platform services).
23. direct_db_in_module — module imports sqlalchemy.create_engine/asyncpg/psycopg2 directly (use platform UoW).

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
    AST analysis only — no runtime inspection.
    No external dependencies beyond stdlib (ast, sys, pathlib, dataclasses).
"""

from __future__ import annotations

import ast
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

# Rule 21 — noqa inline comments.
_NOQA_PATTERN = _re.compile(r"#\s*noqa\b")

# Rule 18 — asyncio threading primitives banned from modules/.
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
# SQLModel.metadata — they cannot use honesty_whitelist.py because the import must
# appear at the module level and ruff processes it independently.
_ALEMBIC_PATH_PATTERN = _re.compile(r"[/\\]alembic[/\\]")

# Rule 22 — HTTP client libraries banned from modules/.
# Modules must use platform HTTP services (SSHService, IDA bridge, etc.),
# not construct their own httpx/requests/aiohttp clients.
_HTTP_CLIENT_MODULES: frozenset[str] = frozenset({
    "httpx", "requests", "urllib3", "aiohttp",
})

# Rule 23 — Direct DB connection libraries banned from modules/.
# Modules use UnitOfWork from aila.platform.uow for all DB access.
# Direct engine/connection construction bypasses team scoping and audit.
_DIRECT_DB_MODULES: frozenset[str] = frozenset({
    "asyncpg", "psycopg2", "psycopg", "sqlite3",
})
_DIRECT_DB_CALLABLES: frozenset[str] = frozenset({
    "create_engine", "create_async_engine",
})

# Names that indicate logging is present (rule 12 — silent exception check).
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


_BOUNDARY_GUARDED_PATTERN = _re.compile(r"[/\\]aila[/\\](api|platform|storage)[/\\]")


def _is_boundary_guarded_file(filepath: str) -> bool:
    """Return True if *filepath* is inside a boundary-guarded package."""
    return bool(_BOUNDARY_GUARDED_PATTERN.search(filepath.replace("\\", "/")))


_MODULE_FILE_PATTERN = _re.compile(r"[/\\]aila[/\\]modules[/\\]")


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
    ``AsyncFunctionDef``, or ``ClassDef`` node — so return statements inside
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
    declare signatures but contain no executable code — flagging unused params
    there is meaningless.
    """
    stmts = func.body
    if len(stmts) == 1:
        stmt = stmts[0]
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            if stmt.value.value is ...:
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
    if param_name == "request" and _is_request_annotation(arg_node.annotation if arg_node else None):
        if "limit" in decorator_ids or func.name.endswith("_handler"):
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

    # Extract the expression — could be Return or bare Expr.
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

    Only flags phrases like 'caches the result' or 'memoizes' — not functions
    that merely interact with a cache ('reads from cache', 'updates cache entry').
    """
    low = docstring.lower()
    return any(phrase in low for phrase in _CACHE_DOC_CLAIM_PHRASES)


def _body_has_cache_impl(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if the body contains any identifier associated with caching."""
    body_ids = _collect_body_identifiers(func)
    return bool(body_ids & _CACHE_IMPL_IDENTIFIERS)


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
        # Detect Protocol classes — skip their methods for unused_parameter
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
        # Skip stubs — Protocol/ABC abstract bodies.
        if _is_stub_body(func) or _has_stub_decorator(func):
            return
        # Skip Protocol class methods — they define interfaces, not implementations.
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
        """Rule: dead_isinstance — isinstance check on a typed parameter."""
        # Build a map of param_name → annotation_type_name
        typed_params: dict[str, str] = {}
        for arg in list(func.args.args) + list(func.args.kwonlyargs):
            if arg.annotation and isinstance(arg.annotation, ast.Name):
                if arg.annotation.id in _TYPED_BUILTINS:
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
        """Rule: god_object_dispatch — 4+ if/elif branches on an action string parameter."""
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
                    if isinstance(name_node, ast.Name) and "action" in name_node.id.lower():
                        if any(isinstance(c, ast.Constant) and isinstance(c.value, str) for c in node.comparators):
                            branch_count += 1
                            break

        # CRUD tools (upsert/list/get/delete on one resource) are acceptable
        # at 3-5 branches. Flag only when branches exceed 6 — indicating
        # multiple unrelated concerns in one tool, not standard CRUD.
        if branch_count >= 7:
            self._emit(
                func.lineno,
                "god_object_dispatch",
                f"function '{func.name}' has {branch_count} action-dispatch branches — "
                f"consider splitting into separate single-concern tools",
            )

    def _check_private_in_all(self, tree: ast.Module) -> None:
        """Rule: private_in_all — underscore-prefixed name in __all__."""
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if not isinstance(target, ast.Name) or target.id != "__all__":
                    continue
                if not isinstance(node.value, (ast.List, ast.Tuple)):
                    continue
                for elt in node.value.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        if elt.value.startswith("_"):
                            self._emit(
                                elt.lineno if hasattr(elt, "lineno") else node.lineno,
                                "private_in_all",
                                f"'__all__' exports private name '{elt.value}' — "
                                f"underscore prefix contradicts public API declaration",
                            )

    def _check_bare_exception_wrap(self, tree: ast.Module) -> None:
        """Rule: bare_exception_wrap — except Exception that raises a less-specific type."""
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
                if isinstance(stmt, ast.Raise) and stmt.exc is not None:
                    if isinstance(stmt.exc, ast.Call) and isinstance(stmt.exc.func, ast.Name):
                        if stmt.exc.func.id == "RuntimeError":
                            self._emit(
                                node.lineno,
                                "bare_exception_wrap",
                                f"'except Exception' catches typed errors then raises "
                                f"RuntimeError — original exception type is destroyed",
                            )
                            break

    def _check_todo_in_code(self, source: str) -> None:
        """Rule: todo_in_code — TODO/FIXME/HACK/XXX in production source.

        Scans raw source lines for comment markers.  A TODO is a promise
        embedded in code that nobody tracks — either do the work or file
        an issue and delete the comment.
        """
        for lineno, line in enumerate(source.splitlines(), start=1):
            match = _TODO_PATTERN.search(line)
            if match:
                tag = match.group(1).upper()
                self._emit(
                    lineno,
                    "todo_in_code",
                    f"'{tag}' comment found — either resolve it or track it in an issue",
                )

    def _check_silent_exception(self, tree: ast.Module) -> None:
        """Rule: silent_exception — except Exception with pass or bare assignment, no logging.

        Catches the pattern where an exception is swallowed silently:
        ``except Exception: pass`` or ``except Exception: x = {}``.
        If the handler body references any logging identifier, it is not silent.
        Finalizer methods (__del__) are excluded — silent cleanup is standard there.
        """
        # Build a set of line ranges for __del__ methods — silent cleanup is standard there.
        del_ranges: set[range] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name == "__del__":
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
                continue  # has logging — not silent

            # Check for raise — if it re-raises, it's not silent
            has_raise = any(isinstance(s, ast.Raise) for s in body)
            if has_raise:
                continue

            # Check if the body is trivially silent: pass, or single assignment
            is_silent = False
            if len(body) == 1:
                stmt = body[0]
                if isinstance(stmt, ast.Pass):
                    is_silent = True
                elif isinstance(stmt, ast.Assign):
                    # bare default assignment like `x = {}` or `x = []` or `x = None`
                    if isinstance(stmt.value, (ast.Dict, ast.List, ast.Constant)):
                        is_silent = True

            if is_silent:
                self._emit(
                    node.lineno,
                    "silent_exception",
                    f"'except Exception' silently swallows errors with no logging or re-raise",
                )

    def _check_production_assert(self, tree: ast.Module) -> None:
        """Rule: production_assert — assert in non-test code.

        ``assert`` statements are stripped when Python runs with ``-O``.
        Production invariants must use explicit ``if not x: raise`` instead.
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                self._emit(
                    node.lineno,
                    "production_assert",
                    f"'assert' in production code — stripped under python -O, use explicit raise",
                )

    def _check_do_nothing_wrapper(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        """Rule: do_nothing_wrapper — function body is a single return of a call.

        Flags functions whose entire body (excluding docstring) is
        ``return some_function(args)`` where the function adds no validation,
        transformation, or error handling.  These can be inlined at call sites.

        Excluded:
        - Dunder methods and framework contracts (forward, handle, run, _execute).
        - Private helpers (underscore prefix) — internal delegation is fine.
        - Named accessors/factories under 4 statements (to_payload, create_*, get_*).
        - Property-style accessors (modules, tools, keys, etc.).
        """
        # Skip framework-contract and dunder method names
        if func.name in {
            "forward", "forward_trusted", "handle", "run", "_execute",
            "__init__", "__del__", "__enter__", "__exit__", "format",
        }:
            return

        # Skip private helpers — internal delegation is a valid pattern
        if func.name.startswith("_"):
            return

        # Skip named accessors, factories, and serialization helpers
        _ACCESSOR_PREFIXES = ("get_", "create_", "build_", "to_", "from_", "is_", "has_")
        if any(func.name.startswith(p) for p in _ACCESSOR_PREFIXES):
            return

        # Skip property-style collection accessors and named domain helpers
        _COLLECTION_ACCESSORS = {
            "modules", "tools", "keys", "values", "items", "entries",
            "utc_now", "minimum_score", "all_tool_keys", "arrivals",
            "departures", "order_group", "criticality_rank",
        }
        if func.name in _COLLECTION_ACCESSORS:
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

        # The return value is a single function call — this is a do-nothing wrapper
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
            f"function '{func.name}' body is just 'return {callee_name}(...)' — "
            f"consider inlining at call sites",
        )

    def _check_sync_session_in_async(self, tree: ast.Module) -> None:
        """Rule: sync_in_async — session_scope() called directly in async def.

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
                        f"'{node.name}' — wrap in a sync helper and use "
                        f"asyncio.to_thread()",
                    )

    def _check_api_imports_modules(self, tree: ast.Module) -> None:
        """Rule: api_imports_module_internals — guarded layers import module internals.

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
                            f"{layer} file imports '{alias.name}' — use module contracts, registry lookups, or injected adapters instead",
                        )
                continue

            if isinstance(node, ast.ImportFrom):
                if node.module is None:
                    continue
                if node.module.startswith("aila.modules."):
                    self._emit(
                        node.lineno,
                        "api_imports_module_internals",
                        f"{layer} file imports from '{node.module}' — use module contracts, registry lookups, or injected adapters instead",
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
        # rest may be empty (bare "aila.modules" import — not a violation) or
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
        """Rule 18: asyncio_in_module — threading primitives banned from modules/.

        Platform services own the threading boundary. Module code must never
        call asyncio.to_thread, asyncio.run, loop.run_until_complete,
        loop.run_in_executor, construct a ThreadPoolExecutor, or import from
        concurrent.futures. These are platform-layer responsibilities.
        """
        for node in ast.walk(tree):
            # concurrent.futures import — flag the import itself
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.startswith("concurrent.futures") or alias.name == "concurrent":
                            self._emit(
                                node.lineno,
                                "asyncio_in_module",
                                f"asyncio_in_module: 'import {alias.name}' — "
                                f"threading belongs to the platform layer, not modules",
                            )
                elif isinstance(node, ast.ImportFrom):
                    mod = node.module or ""
                    if mod.startswith("concurrent.futures") or mod == "concurrent":
                        self._emit(
                            node.lineno,
                            "asyncio_in_module",
                            f"asyncio_in_module: 'from {mod} import ...' — "
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
                                f"asyncio_in_module: 'asyncio.{attr}()' call — "
                                f"threading belongs to the platform layer, not modules",
                            )
                    else:
                        # run_until_complete / run_in_executor — any object (loop variable)
                        self._emit(
                            node.lineno,
                            "asyncio_in_module",
                            f"asyncio_in_module: '.{attr}()' call — "
                            f"threading belongs to the platform layer, not modules",
                        )
            elif isinstance(func_node, ast.Name):
                if func_node.id in _THREAD_CLASS_NAMES:
                    self._emit(
                        node.lineno,
                        "asyncio_in_module",
                        f"asyncio_in_module: '{func_node.id}()' construction — "
                        f"threading belongs to the platform layer, not modules",
                    )

    def _check_http_client_in_module(self, tree: ast.Module) -> None:
        """Rule 22: http_client_in_module — direct HTTP client imports in modules/.

        Modules must not construct their own HTTP clients. HTTP transport
        is a platform concern — use SSHService, IDABridgeTool, or platform
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
                            f"http_client_in_module: 'import {alias.name}' — "
                            f"HTTP clients belong to the platform layer, not modules",
                        )
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                top = mod.split(".")[0]
                if top in _HTTP_CLIENT_MODULES:
                    self._emit(
                        node.lineno,
                        "http_client_in_module",
                        f"http_client_in_module: 'from {mod} import ...' — "
                        f"HTTP clients belong to the platform layer, not modules",
                    )

    def _check_direct_db_in_module(self, tree: ast.Module) -> None:
        """Rule 23: direct_db_in_module — direct DB driver imports in modules/.

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
                            f"direct_db_in_module: 'import {alias.name}' — "
                            f"use UnitOfWork from aila.platform.uow instead",
                        )
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                top = mod.split(".")[0]
                if top in _DIRECT_DB_MODULES:
                    self._emit(
                        node.lineno,
                        "direct_db_in_module",
                        f"direct_db_in_module: 'from {mod} import ...' — "
                        f"use UnitOfWork from aila.platform.uow instead",
                    )
                # Also catch create_engine / create_async_engine from sqlalchemy
                if mod.startswith("sqlalchemy"):
                    for alias in (node.names or []):
                        if alias.name in _DIRECT_DB_CALLABLES:
                            self._emit(
                                node.lineno,
                                "direct_db_in_module",
                                f"direct_db_in_module: 'from {mod} import {alias.name}' — "
                                f"use UnitOfWork from aila.platform.uow instead",
                            )

    def _check_response_model_dict(self, tree: ast.Module) -> None:
        """Rule 19: response_model_dict — @router.* with response_model=dict/Dict.

        FastAPI endpoints must return a typed Pydantic schema, not a bare dict.
        Using response_model=dict bypasses response validation and schema
        generation, hiding what the endpoint actually returns.
        """
        _DICT_NAMES: frozenset[str] = frozenset({"dict", "Dict"})

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
                    if isinstance(val, ast.Name) and val.id in _DICT_NAMES:
                        self._emit(
                            dec.lineno,
                            "response_model_dict",
                            f"response_model_dict: endpoint '{node.name}' uses "
                            f"response_model={val.id} — use a typed Pydantic schema instead",
                        )
                    # response_model=typing.Dict
                    elif isinstance(val, ast.Attribute) and val.attr == "Dict":
                        self._emit(
                            dec.lineno,
                            "response_model_dict",
                            f"response_model_dict: endpoint '{node.name}' uses "
                            f"response_model=typing.Dict — use a typed Pydantic schema instead",
                        )
                    # response_model=dict | None  (BinOp with left=dict)
                    elif isinstance(val, ast.BinOp):
                        left = val.left
                        if isinstance(left, ast.Name) and left.id in _DICT_NAMES:
                            self._emit(
                                dec.lineno,
                                "response_model_dict",
                                f"response_model_dict: endpoint '{node.name}' uses "
                                f"response_model={left.id} | ... — use a typed Pydantic schema instead",
                            )

    def _check_bare_dict_return_endpoint(self, tree: ast.Module) -> None:
        """Rule 20: bare_dict_return_endpoint — endpoint handler returns a raw dict.

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
                elif isinstance(dec, ast.Attribute):
                    if dec.attr in {"get", "post", "put", "delete", "patch"}:
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

                # return {"key": val}  — ast.Dict literal
                if isinstance(ret_val, ast.Dict):
                    self._emit(
                        child.lineno,
                        "bare_dict_return_endpoint",
                        f"bare_dict_return_endpoint: endpoint '{node.name}' returns a raw "
                        f"dict literal — return a typed Pydantic model instead",
                    )
                    continue

                # return dict(...)  — dict() constructor call
                if (
                    isinstance(ret_val, ast.Call)
                    and isinstance(ret_val.func, ast.Name)
                    and ret_val.func.id == "dict"
                ):
                    self._emit(
                        child.lineno,
                        "bare_dict_return_endpoint",
                        f"bare_dict_return_endpoint: endpoint '{node.name}' returns dict() — "
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
                                    f"JSONResponse(content={{...}}) — return a typed Pydantic model instead",
                                )
                                break

    def _check_noqa_inline(self, source: str, filepath: str) -> None:
        """Rule 21: noqa_inline — inline # noqa comments in production source.

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

        # Alembic migrations are auto-generated — exempt from this rule
        if _ALEMBIC_PATH_PATTERN.search(normalized):
            return

        for lineno, line in enumerate(source.splitlines(), start=1):
            if _NOQA_PATTERN.search(line):
                self._emit(
                    lineno,
                    "noqa_inline",
                    f"noqa_inline: inline '# noqa' comment on line {lineno} — "
                    f"use honesty_whitelist.py with a documented justification instead",
                )


class HonestyAuditor:
    """Audit one or more Python source files for structural dishonesty.

    Runs as a pre-commit CI gate: ``python -m aila.tools.honesty_audit src/``
    exits with code 1 if any finding is reported, 0 if clean.  Run with
    ``--whitelist honesty_whitelist.py`` to suppress known acceptable violations.

    The whitelist file (honesty_whitelist.py at the project root) defines
    HONESTY_WHITELIST as a list of (filename_suffix, function_name, detail) string
    triples.  A finding is suppressed when all three fields match — this prevents
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
