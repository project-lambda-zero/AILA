"""Resume-cursor resolution for the polling-backed VR SSE streams.

The VR project event stream and the investigation-message stream poll
timestamped rows. Every data frame carries an ``id:`` line of the form
``<iso-8601 UTC timestamp>|<row id>`` identifying the row's position in the
stream order ``(timestamp, row id)``. Row ids compare as raw strings
(``COLLATE "C"`` in SQL, code-point order in Python) so the database and the
in-process cursor agree on the order of rows that share a timestamp.

:func:`resolve_stream_cursor` picks where a connection starts, with this
precedence:

1. an explicit ``since_iso`` query argument wins and keeps its original
   meaning: rows with a timestamp strictly newer than it. A malformed value is
   a caller error and raises ``HTTPException(422)``;
2. otherwise a ``Last-Event-ID`` header (an ``EventSource`` reconnect resends
   the last frame id it saw): rows strictly after that ``(timestamp, row id)``
   position, so a row sharing the cursor's timestamp with a later id is
   delivered and the represented row is not replayed. Browsers resend
   whatever id they last saw, so a malformed or over-long value is ignored and
   the connection is treated as fresh;
3. otherwise a fresh connection that starts at the current time.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from fastapi import HTTPException, status
from sqlalchemy import and_, or_

from aila.platform.contracts import utc_now

__all__ = [
    "MAX_EVENT_ID_LENGTH",
    "StreamCursor",
    "format_event_id",
    "parse_event_id",
    "resolve_stream_cursor",
]

_log = logging.getLogger(__name__)

MAX_EVENT_ID_LENGTH: Final[int] = 128
_ID_SEPARATOR: Final[str] = "|"


def _as_utc(ts: datetime) -> datetime:
    return ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class StreamCursor:
    """A position in the ``(timestamp, row id)`` stream order.

    ``row_id`` is ``None`` for a pure timestamp cursor (explicit ``since_iso``
    or a fresh connection): only rows with a strictly newer timestamp follow
    it. Once a row has been emitted the cursor carries that row's id, and rows
    sharing its timestamp follow it only if their id sorts after.
    """

    ts: datetime
    row_id: str | None = None

    def sql_after(self, ts_column: Any, id_column: Any) -> Any:
        """SQL predicate selecting rows strictly after this cursor."""
        if self.row_id is None:
            return ts_column > self.ts
        return or_(
            ts_column > self.ts,
            and_(ts_column == self.ts, id_column.collate("C") > self.row_id),
        )

    def is_before(self, ts: datetime, row_id: str) -> bool:
        """True when ``(ts, row_id)`` sorts strictly after this cursor."""
        if ts > self.ts:
            return True
        return self.row_id is not None and ts == self.ts and row_id > self.row_id

    def advanced_to(self, ts: datetime, row_id: str) -> StreamCursor:
        """Return the cursor moved to ``(ts, row_id)`` when that is later."""
        return StreamCursor(ts, row_id) if self.is_before(ts, row_id) else self


def format_event_id(ts: datetime, row_id: str) -> str:
    """Return the SSE ``id`` value for the row at ``(ts, row_id)``."""
    return f"{_as_utc(ts).isoformat()}{_ID_SEPARATOR}{row_id}"


def parse_event_id(raw: str) -> StreamCursor | None:
    """Parse a frame id; ``None`` when malformed, naive, or too long."""
    value = raw.strip()
    if not value or len(value) > MAX_EVENT_ID_LENGTH:
        return None
    ts_text, sep, row_id = value.partition(_ID_SEPARATOR)
    if not sep or not row_id:
        return None
    try:
        ts = datetime.fromisoformat(ts_text)
    except ValueError:
        _log.debug("Last-Event-ID timestamp %r is not ISO-8601; treating as fresh", ts_text)
        return None
    if ts.tzinfo is None:
        return None
    return StreamCursor(ts, row_id)


def resolve_stream_cursor(since_iso: str | None, last_event_id: str | None) -> StreamCursor:
    """Return the position a VR stream must resume after.

    Args:
        since_iso: The explicit ``since_iso`` query argument, or ``None``.
        last_event_id: The ``Last-Event-ID`` request header, or ``None``.

    Raises:
        HTTPException: 422 when ``since_iso`` is supplied but is not an
            ISO-8601 timestamp.
    """
    if since_iso:
        try:
            return StreamCursor(datetime.fromisoformat(since_iso.replace("Z", "+00:00")))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid since_iso: {since_iso!r}",
            ) from None
    if last_event_id is not None:
        parsed = parse_event_id(last_event_id)
        if parsed is not None:
            return parsed
    return StreamCursor(utc_now())
