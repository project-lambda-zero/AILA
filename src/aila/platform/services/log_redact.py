"""Secret-redaction boundary helpers (C6).

Command lines and process stderr routinely carry inline credentials
(``-p hunter2``, ``password=...``, ``authorization: bearer ...``). Before
any such text reaches a structured log, an exception message, or an audit
row, it passes through :func:`redact_command_line`, which masks the value
that follows a known secret marker up to the next whitespace.

Provider error strings (raised by upstream HTTP clients like ``openai`` /
``anthropic``) can echo the same material without the command-line
framing -- a bare ``Bearer <token>`` without the ``authorization: ``
prefix, or an inline ``sk-...`` key that never sat behind a marker at
all. :func:`redact_secrets` covers those shapes on top of every
command-line marker.

Both helpers are dependency-free so any trust boundary can call them
without importing storage, config, or model code.
"""
from __future__ import annotations

import re

__all__ = ["redact_command_line", "redact_secrets"]

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

# Extra markers that surface in provider error text without the
# command-line framing. ``bearer `` (case-insensitive) catches
# HTTP client exception strings that echo the raw ``Authorization``
# header value without the ``authorization: `` prefix.
_PROVIDER_ERROR_MARKERS: tuple[str, ...] = (
    "bearer ",
)

# Bare API-key shapes ("sk-live-abc123", "sk-ant-api03-...") that appear
# inline in provider error text without any preceding marker. The 6-char
# floor avoids matching short identifiers like ``sk-abc``.
_BARE_KEY_PATTERN = re.compile(r"sk-[A-Za-z0-9_\-]{6,}")


def _mask_after_markers(text: str, markers: tuple[str, ...]) -> str:
    """Mask non-whitespace runs following any of the given markers.

    Marker match is case-insensitive; the original casing of the input
    outside the redacted spans is preserved.
    """
    out = text
    lower = out.lower()
    for marker in markers:
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


def redact_command_line(command: str) -> str:
    """Mask inline secrets in a command line or captured stderr.

    For every known secret marker, the run of non-whitespace characters
    that follows it is replaced with ``[REDACTED]``. Text without a marker
    is returned unchanged.
    """
    if not command:
        return command
    return _mask_after_markers(command, _INLINE_SECRET_MARKERS)


def redact_secrets(text: str) -> str:
    """Mask inline secrets in arbitrary text (provider errors, log lines).

    Superset of :func:`redact_command_line`:

    * Sweeps every command-line marker (``password=``, ``token=``,
      ``authorization: bearer ``, etc.).
    * Adds a bare ``bearer `` marker for provider errors that echo the
      raw ``Authorization`` header value without the ``authorization: ``
      prefix.
    * Regex-masks bare ``sk-`` prefixed API keys (OpenAI, Anthropic)
      that appear inline without any preceding marker.

    Empty input is returned unchanged.
    """
    if not text:
        return text
    out = _mask_after_markers(
        text, _INLINE_SECRET_MARKERS + _PROVIDER_ERROR_MARKERS,
    )
    return _BARE_KEY_PATTERN.sub(_REDACTED, out)
