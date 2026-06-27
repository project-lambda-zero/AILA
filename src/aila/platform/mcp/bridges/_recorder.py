"""Bridge call-recorder protocol + no-op default.

Each bridge accepts an optional ``recorder`` argument at construction
time. When provided, the bridge wraps every dispatch in
``async with recorder(server_id=..., base_url=..., action=...) as ctx``
and writes ``ctx["status"]`` / ``ctx["error_excerpt"]`` /
``ctx["http_status"]`` as the call progresses. Module authors typically
wire ``recorder`` to a ``record_call`` async context manager that
persists one row per call to a module-specific audit-log table.

When ``recorder`` is omitted the bridge falls back to
:func:`noop_recorder`: an empty context that discards every annotation.
This keeps the bridges usable from tests, ad-hoc scripts, and any code
path that does not need audit logging.
"""
from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any

__all__ = ["BridgeRecorder", "noop_recorder"]


BridgeRecorder = Callable[..., AbstractAsyncContextManager[dict[str, Any]]]
"""Async context manager factory: ``(server_id=..., base_url=..., action=...) -> CM``.

Each invocation MUST yield a mutable ``dict[str, Any]`` that the bridge
populates with at least ``status``, ``error_excerpt``, and
``http_status`` keys as the call progresses. The recorder owns the
final write (typically inside the context manager's ``finally`` block).
"""


@asynccontextmanager
async def noop_recorder(**_kwargs: Any) -> AsyncIterator[dict[str, Any]]:
    """Default no-op recorder -- yields an empty dict, ignores kwargs.

    Bridges fall back to this when no recorder was passed to the
    constructor. Useful for tests and any caller that doesn't want
    per-call audit logging.
    """
    yield {}
