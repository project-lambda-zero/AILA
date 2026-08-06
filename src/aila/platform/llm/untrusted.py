"""Fence-wrap third-party bytes before they reach an LLM prompt.

Companion to :mod:`aila.platform.llm.sanitize`. Where ``sanitize_input``
strips known injection patterns (D-01 through D-05), this module marks
the boundary between platform-authored instructions and untrusted data
that flowed in from an MCP bridge, HTTP fetch, SSH command, or a
persisted third-party field. The two defences compose -- callers who
want both call ``sanitize_input`` first, then ``sanitize_untrusted``.

Design reference: ``.run/designs/DESIGN_injection_evidence.md`` issue
#43 finding 43-1. The tool-loop at ``client.py:_tool_loop`` appended
tool results raw, so untrusted output could inject fresh instructions
into the next model turn. Wrapping with a constant literal fence gives
the model a clear signal to treat the payload as quoted data, and
escaping any occurrence of the fence sentinel inside the payload
guarantees the third-party bytes cannot close the outer fence early.

The wrapper preserves content verbatim -- it does not strip, truncate,
normalise, or otherwise mutate the payload semantics. Any character
budgeting or pattern stripping is a caller decision made before this
helper runs.
"""

from __future__ import annotations

from typing import Final

__all__ = [
    "BEGIN_FENCE_PREFIX",
    "END_FENCE",
    "sanitize_untrusted",
]

# Constant literal tags. The prefix is the invariant substring the
# escape pass looks for -- the actual opening tag adds a ``source``
# attribute after the prefix, and the closing tag has no attributes.
BEGIN_FENCE_PREFIX: Final[str] = "<untrusted-input"
END_FENCE: Final[str] = "</untrusted-input>"

_ESCAPED_BEGIN: Final[str] = "<untrusted_ESCAPED_input"
_ESCAPED_END: Final[str] = "</untrusted_ESCAPED_input>"

_SOURCE_MAX_LEN: Final[int] = 120
_SOURCE_BANNED: Final[tuple[str, ...]] = (
    "<", ">", "\n", "\r", "\t", '"', "'", "\x00",
)


def _clean_source(source: str) -> str:
    """Neutralise fence-injection via the ``source`` attribute value.

    The source is rendered inside the opening tag's double-quoted
    attribute. Stripping quote characters, angle brackets, newlines,
    and NULs keeps the source from either closing the tag early or
    smuggling a second attribute the wrapper never declared.
    """
    cleaned = str(source)
    for ch in _SOURCE_BANNED:
        cleaned = cleaned.replace(ch, "_")
    return cleaned[:_SOURCE_MAX_LEN]


def _escape_fence_sentinels(payload: str) -> str:
    """Mangle any fence-sentinel substring found inside ``payload``.

    Applied in specific-then-general order so a payload containing the
    close tag stays syntactically valid text after escaping.  The
    replacement is deterministic -- calling twice produces the same
    result, and the mangled form has no substring that matches either
    the begin prefix or the end sentinel, so a downstream re-wrap or
    idempotency check does not re-mangle.
    """
    payload = payload.replace(END_FENCE, _ESCAPED_END)
    payload = payload.replace(BEGIN_FENCE_PREFIX, _ESCAPED_BEGIN)
    return payload


def sanitize_untrusted(text: str, *, source: str) -> str:
    """Wrap ``text`` in a constant-literal fence marking it as data.

    The ``source`` label rides inside the opening tag as an attribute
    so the model can distinguish content that flowed from an audit-mcp
    bridge from content that flowed from a persisted fact field. Any
    occurrence of the fence sentinel already present in ``text`` is
    mangled before wrapping so third-party bytes cannot break out of
    the outer fence.

    Content is otherwise preserved verbatim. Callers that also need
    known-pattern stripping (e.g. ``ignore previous instructions``,
    role prefixes) should call :func:`sanitize_input` on the payload
    before passing it here; the two defences compose.
    """
    cleaned_source = _clean_source(source)
    escaped_body = _escape_fence_sentinels(str(text))
    return (
        f'<untrusted-input source="{cleaned_source}">\n'
        f"{escaped_body}\n"
        f"{END_FENCE}"
    )
