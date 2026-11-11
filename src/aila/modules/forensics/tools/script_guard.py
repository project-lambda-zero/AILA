"""AST-level policy for agent- and retrieval-generated analyzer scripts.

``ScriptExecutorTool.forward`` is the single execution chokepoint for every
consumer (investigator, file retriever, direct tool callers). It calls
:func:`script_rejection` before any SSH, temp-file, upload, or run side effect.
"""
from __future__ import annotations

import ast

__all__ = ["script_rejection"]

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


def script_rejection(script: str) -> str | None:
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
