"""Platform-owned bridges for blocking I/O invoked from async code.

Modules MUST NOT manage threading directly (Honesty Audit rule 18).  When
a module needs to invoke a blocking external library -- a synchronous HTTP
client, a sync DB driver, or a C-extension call -- it requests background
execution from the platform via :func:`run_blocking_io`.  The platform
layer owns the thread pool and the bridge primitive; modules only express
the intent ("this operation blocks; run it without stalling the loop").

Centralising the boundary here keeps SDA-05 honest: every sync-to-async
hop in the codebase passes through a single, named platform entry point
that we can audit, instrument, or replace.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import TypeVar

__all__ = ["run_blocking_io"]

T = TypeVar("T")


async def run_blocking_io(func: Callable[..., T], /, *args, **kwargs) -> T:
    """Run a blocking callable on a platform-owned worker thread.

    Used by module code (e.g. the NVD intel tool) to invoke a synchronous
    upstream library without blocking the event loop.  Returning through
    this single helper keeps the threading touchpoint inside the platform
    layer where it belongs.

    Args:
        func: Synchronous callable to invoke.
        *args: Positional arguments forwarded to ``func``.
        **kwargs: Keyword arguments forwarded to ``func``.

    Returns:
        Whatever ``func`` returns.
    """
    return await asyncio.to_thread(func, *args, **kwargs)
