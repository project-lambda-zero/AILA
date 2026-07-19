"""Secret-redaction boundary helpers (C6).

Command lines and process stderr routinely carry inline credentials
(``-p hunter2``, ``password=...``, ``authorization: bearer ...``). Before
any such text reaches a structured log, an exception message, or an audit
row, it passes through :func:`redact_command_line`, which masks the value
that follows a known secret marker up to the next whitespace.

The helper is intentionally dependency-free so every trust boundary can
call it without importing storage, config, or model code.
"""
from __future__ import annotations

__all__ = ["redact_command_line"]

_REDACTED = "[REDACTED]"

# Substrings after which everything up to the next whitespace is a secret.
_INLINE_SECRET_MARKERS: tuple[str, ...] = (
    "password=",
    "passwd=",
    "pass=",
    "token=",
    "authorization: bearer ",
    "apikey=",
    "api_key=",
    "secret=",
    "-p ",
    "--password ",
    "--token ",
    "--api-key ",
)


def redact_command_line(command: str) -> str:
    """Mask inline secrets in a command line or captured stderr.

    For every known secret marker, the run of non-whitespace characters
    that follows it is replaced with ``[REDACTED]``. Text without a marker
    is returned unchanged.
    """
    if not command:
        return command
    out = command
    lower = out.lower()
    for marker in _INLINE_SECRET_MARKERS:
        idx = lower.find(marker)
        while idx != -1:
            start = idx + len(marker)
            end = start
            while end < len(out) and not out[end].isspace():
                end += 1
            out = out[:start] + _REDACTED + out[end:]
            lower = out.lower()
            idx = lower.find(marker, start + len(_REDACTED))
    return out
