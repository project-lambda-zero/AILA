"""Structural guards for the SSE chat streaming path.

_stream_message awaits the async platform handle directly and streams the
resolved summary. Two invariants matter: the handle must be awaited (never
called without await or bridged through a worker thread), and the done
sentinel must not be yielded from inside a finally block (a cancelled stream
must not emit a completion event).
"""
from __future__ import annotations

import ast
import inspect


def test_stream_generator_awaits_handle() -> None:
    """_stream_message must await the async platform handle, not bridge it via a thread."""
    from aila.api.routers.sessions import _stream_message

    source = inspect.getsource(_stream_message)
    assert "await platform.handle" in source, (
        "Expected _stream_generator to await platform.handle(); the async handle "
        "must not be called without await"
    )
    assert "asyncio.to_thread" not in source, (
        "Streaming must not bridge the async handle through a worker thread"
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
