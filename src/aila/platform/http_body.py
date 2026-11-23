"""Bounded HTTP response-body reader shared by platform and module HTTP callers.

Kept dependency-light (stdlib only) so it can be imported from the MCP layer
without pulling ``aila.platform.services``, whose package init reaches the
storage models.
"""

from __future__ import annotations

from collections.abc import AsyncIterable

__all__ = ["BodyTooLargeError", "read_bounded_body"]


class BodyTooLargeError(ValueError):
    """A response body grew past the caller's byte ceiling."""


async def read_bounded_body(chunks: AsyncIterable[bytes], *, max_bytes: int) -> bytes:
    """Join a streamed body, rejecting it once it exceeds ``max_bytes``.

    Pass ``response.aiter_bytes()``. A body of exactly ``max_bytes`` is accepted.
    The size is checked before each chunk is appended, so the stream is abandoned
    at the crossing chunk and no more than ``max_bytes`` is ever buffered.
    """
    buffer = bytearray()
    async for chunk in chunks:
        if len(buffer) + len(chunk) > max_bytes:
            raise BodyTooLargeError(f"response body exceeds {max_bytes} bytes")
        buffer.extend(chunk)
    return bytes(buffer)
