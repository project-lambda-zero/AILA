"""Shared helpers used by every collection lane.

All collectors depend on a small number of plumbing utilities: a safe
truncation marker, OS-aware shell quoting, and an emitter wrapper that
no-ops when an emitter wasn't provided. Keeping these in a single file
avoids per-lane drift and makes the collectors themselves small and
readable.
"""
from __future__ import annotations

import logging
import shlex
from typing import Any

__all__ = ["DEFAULT_OUTPUT_LIMIT", "truncate", "sq", "err_sink", "safe_emit", "vol_cmd"]

_log = logging.getLogger(__name__)

DEFAULT_OUTPUT_LIMIT = 8000


def truncate(text: str, limit: int = DEFAULT_OUTPUT_LIMIT) -> str:
    """Truncate text with an explicit marker so consumers know data was cut."""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n\n[TRUNCATED -- original output was {len(text):,} bytes]"


def sq(path: str, analyzer_os: str) -> str:
    """Shell-quote a path for the analyzer OS."""
    if analyzer_os == "windows":
        return f'"{path}"'
    return shlex.quote(path)


def vol_cmd(analyzer_os: str) -> str:
    """Return the correct Volatility3 invocation prefix for ``analyzer_os``.

    Three traps we have to avoid:

    1. A bare ``vol`` on Windows PATH resolves to ``C:\\Windows\\System32\\vol.exe``
       (the built-in Volume Label utility), exits 0.3s with ``The system
       cannot find the drive specified``.
    2. ``python -m volatility3`` and ``python -m volatility3.cli`` both
       fail -- neither package ships a ``__main__``.
    3. ``python -c "from volatility3.cli import main; main()"`` works
       technically, but argparse's error messages show the prog as
       ``-c`` (because Python sets ``sys.argv[0]='-c'``) which led me
       down a debugging rabbit hole.

    The reliable form is ``python -c "<CODE>" ...extra_args`` where
    ``<CODE>`` rewrites ``sys.argv[0]`` to ``'vol'`` before calling the
    Vol3 CLI entrypoint. This preserves all remaining argv, routes
    stdio cleanly through paramiko, and avoids every PATH collision.

    Timeouts are enforced by the caller through ``ssh.run_command(timeout_seconds=...)``,
    not by shell-wrapping -- wrapping in ``timeout N cmd /c ...`` on Windows
    consumes the trailing ``-f <path>`` argv tokens and makes Vol3 see
    "-f unexpected".
    """
    snippet = (
        "import sys;sys.argv=['vol']+sys.argv[1:];"
        "from volatility3.cli import main;main()"
    )
    if analyzer_os == "windows":
        return f'python -c "{snippet}"'
    return f"python3 -c \"{snippet}\""


def err_sink(analyzer_os: str) -> str:
    """Return the OS-appropriate stderr redirection suffix."""
    return "2>NUL" if analyzer_os == "windows" else "2>/dev/null"


async def safe_emit(emitter: Any, stage: str, message: str, meta: dict[str, Any] | None = None) -> None:
    """Emit a collection progress event if an emitter is provided.

    Failures are logged at debug only so instrumentation never crashes
    the caller. Use in collectors: ``await safe_emit(emitter, "tshark_done", ...)``.
    """
    if emitter is None:
        return
    try:
        await emitter.emit("collection", message, {"stage": stage, **(meta or {})})
    except (OSError, RuntimeError, TimeoutError) as exc:
        _log.debug("collection emitter failed (non-fatal): %s", exc)
