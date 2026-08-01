"""Bounded ``UploadFile`` readers that guard against DoS on multipart uploads.

Closes #57. The FastAPI/Starlette ``_reject_oversized_requests`` middleware
in :mod:`aila.api.app` only inspects the ``Content-Length`` header. A
chunked-transfer request that omits the header slips past that check
entirely, so an unbounded ``await file.read()`` on the endpoint side
would stream the full body into worker memory and OOM the process.

The helpers here enforce a per-endpoint byte cap during the read loop
itself. When the running total crosses ``max_bytes`` on any chunk, they
raise :class:`HTTPException` with status ``413`` so the client learns the
request is rejected AND worker RAM never grows past ``max_bytes`` plus a
single chunk, regardless of whether the client advertised a size or
streamed chunked-without-length.

Two shapes cover the two use cases in the API layer today:

* :func:`read_upload_bounded` -- accumulates into a bytes buffer, capped.
  Callers that need the full body in RAM (e.g. to hash it and forward
  via ``httpx`` multipart) use this.
* :func:`iter_upload_bounded` -- async iterator over the same chunks
  without buffering. Callers that stream to disk or to another HTTP
  client without ever holding the full body use this.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Final

from fastapi import HTTPException, UploadFile, status

__all__ = [
    "DEFAULT_UPLOAD_CHUNK_BYTES",
    "DEFAULT_UPLOAD_MAX_BYTES",
    "iter_upload_bounded",
    "read_upload_bounded",
]

# 1 MiB matches the SpooledTemporaryFile roll-over threshold Starlette
# picks for UploadFile, so a chunk read never straddles the memory/disk
# boundary of the underlying spool.
DEFAULT_UPLOAD_CHUNK_BYTES: Final[int] = 1 << 20

# Sane default cap when a caller does not supply its own. 512 MiB is
# generous enough for large firmware images / kernel dumps / APKs while
# still preventing a single request from consuming multi-GB of worker
# memory. Every audited endpoint overrides this from its module config.
DEFAULT_UPLOAD_MAX_BYTES: Final[int] = 512 * 1024 * 1024


def _payload_too_large(max_bytes: int) -> HTTPException:
    """Uniform 413 response body for both helpers below."""
    return HTTPException(
        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        detail=(
            "Upload exceeds the per-endpoint cap of "
            f"{max_bytes} bytes ({max_bytes // (1024 * 1024)} MiB)."
        ),
    )


def _validated_cap(max_bytes: int) -> int:
    if max_bytes <= 0:
        raise ValueError(
            f"max_bytes must be positive; got {max_bytes!r}. "
            "Callers must pass a real cap, not 0 or negative."
        )
    return max_bytes


async def read_upload_bounded(
    file: UploadFile,
    max_bytes: int = DEFAULT_UPLOAD_MAX_BYTES,
    *,
    chunk_size: int = DEFAULT_UPLOAD_CHUNK_BYTES,
) -> bytes:
    """Read the full body of ``file`` into memory, refusing overruns with 413.

    Reads in ``chunk_size`` chunks so the worker aborts as soon as the
    running total crosses ``max_bytes``. The cap is enforced on the
    running-total AFTER the next chunk would land, so a client that
    sends a single oversized chunk still fails the check without the
    over-cap bytes ever being appended to the buffer.

    Suitable for endpoints that need the full body in RAM (e.g. to hash
    it and forward it via ``httpx`` multipart in one shot).
    """
    cap = _validated_cap(max_bytes)
    buf = bytearray()
    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        if len(buf) + len(chunk) > cap:
            raise _payload_too_large(cap)
        buf.extend(chunk)
    return bytes(buf)


async def iter_upload_bounded(
    file: UploadFile,
    max_bytes: int = DEFAULT_UPLOAD_MAX_BYTES,
    *,
    chunk_size: int = DEFAULT_UPLOAD_CHUNK_BYTES,
) -> AsyncIterator[bytes]:
    """Async iterator over ``file`` chunks that trips 413 past the cap.

    Suitable for endpoints that stream the body straight to disk or to
    another HTTP client without holding it in memory. The 413 is raised
    mid-stream on the read whose chunk would push the running total
    past ``max_bytes``, so a chunked-without-length client that intends
    to send far more than the cap is stopped after (cap + one chunk)
    bytes have been read from the spool.
    """
    cap = _validated_cap(max_bytes)
    total = 0
    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            return
        if total + len(chunk) > cap:
            raise _payload_too_large(cap)
        total += len(chunk)
        yield chunk
