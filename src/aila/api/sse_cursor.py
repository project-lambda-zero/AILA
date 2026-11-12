"""Resume-cursor resolution for Redis-Stream backed progress SSE endpoints.

Progress frames carry an ``id:`` line holding their Redis stream id
(``<ms>-<seq>``). A client resumes in one of two ways: it passes the last id
it saw as the ``last_id`` query argument, or an ``EventSource`` reconnect
resends it in the ``Last-Event-ID`` header. :func:`resolve_stream_cursor`
defines the precedence once for every endpoint that serves such a stream:

1. an explicit ``last_id`` query argument wins; a malformed value is a
   caller error and raises ``HTTPException(400)``;
2. otherwise a ``Last-Event-ID`` header; browsers resend whatever id they
   last saw, so a malformed value is ignored and the connection is treated
   as fresh;
3. otherwise the zero cursor, which replays the whole stream.
"""
from __future__ import annotations

import re
from typing import Final

from fastapi import HTTPException, status

__all__ = ["MAX_CURSOR_LENGTH", "ZERO_CURSOR", "resolve_stream_cursor"]

ZERO_CURSOR: Final[str] = "0"
MAX_CURSOR_LENGTH: Final[int] = 64

# ``0`` is the documented replay-everything cursor; every other accepted value
# is a full ``<ms>-<seq>`` stream id. A bare ``<ms>`` is rejected because
# ``ProgressStream.catchup`` drops the entry whose id equals the cursor
# string, so a partial id would replay the entry the client already has.
_CURSOR_RE: Final[re.Pattern[str]] = re.compile(r"0|\d+-\d+")


def _is_valid_cursor(value: str) -> bool:
    return len(value) <= MAX_CURSOR_LENGTH and _CURSOR_RE.fullmatch(value) is not None


def resolve_stream_cursor(query_cursor: str | None, last_event_id: str | None) -> str:
    """Return the Redis stream id a progress stream must resume after.

    Args:
        query_cursor: The explicit ``last_id`` query argument, or ``None``
            when the caller did not supply one.
        last_event_id: The ``Last-Event-ID`` request header, or ``None``.

    Raises:
        HTTPException: 400 when ``query_cursor`` is supplied but is neither
            ``0`` nor a ``<ms>-<seq>`` stream id of at most
            ``MAX_CURSOR_LENGTH`` characters.
    """
    if query_cursor is not None:
        if not _is_valid_cursor(query_cursor):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "last_id must be '0' or a Redis stream id of the form "
                    f"'<ms>-<seq>' (at most {MAX_CURSOR_LENGTH} characters)."
                ),
            )
        return query_cursor
    if last_event_id is not None and _is_valid_cursor(last_event_id.strip()):
        return last_event_id.strip()
    return ZERO_CURSOR
