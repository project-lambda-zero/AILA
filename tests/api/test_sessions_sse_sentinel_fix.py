"""Test: SSE done-sentinel is not yielded inside a finally block.

RED phase: This test validates the structural fix -- the `cancelled` flag
pattern must exist in _stream_generator so the done sentinel is only
yielded on normal (non-cancelled) completion, outside the finally block.
"""
from __future__ import annotations

import ast
import inspect


def test_stream_generator_has_cancelled_flag() -> None:
    """_stream_generator must use a `cancelled` flag to guard the done sentinel yield."""
    from aila.api.routers.sessions import _stream_message

    source = inspect.getsource(_stream_message)
    assert "cancelled = False" in source, (
        "Expected `cancelled = False` initializer in _stream_message/_stream_generator"
    )
    assert "if not cancelled" in source, (
        "Expected `if not cancelled` guard before done sentinel yield"
    )


def test_done_sentinel_yield_not_in_finally() -> None:
    """The done sentinel yield must NOT be inside a finally block.

    Parse the AST of sessions.py and verify that no Yield node inside a
    finally body contains the string 'done'.
    """
    import pathlib

    sessions_path = pathlib.Path("src/aila/api/routers/sessions.py")
    tree = ast.parse(sessions_path.read_text(encoding="utf-8"))

    # Walk the AST looking for Try nodes with finally bodies
    for node in ast.walk(tree):
        if isinstance(node, ast.Try) and node.finalbody:
            for finally_node in ast.walk(ast.Module(body=node.finalbody, type_ignores=[])):
                if isinstance(finally_node, ast.Yield):
                    # Check if the yield contains 'done' in its string representation
                    yield_source = ast.dump(finally_node)
                    assert "done" not in yield_source.lower(), (
                        "Found a yield with 'done' inside a finally block -- "
                        "the done sentinel must be yielded outside finally"
                    )
