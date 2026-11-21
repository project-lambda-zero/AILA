"""Shared bounded-body reader and redirect policy on the platform HTTP clients."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from aila.platform.http_body import BodyTooLargeError, read_bounded_body
from aila.platform.services.http import build_async_http_client


class _Settings:
    request_timeout_seconds = 5.0
    user_agent = "aila-test"


async def _chunks(*parts: bytes) -> AsyncIterator[bytes]:
    for part in parts:
        yield part


@pytest.mark.parametrize("limit", [64 * 1024, 2 * 1024 * 1024])
async def test_bounded_body_accepts_exact_limit(limit: int) -> None:
    body = await read_bounded_body(_chunks(b"a" * (limit // 2), b"b" * (limit - limit // 2)), max_bytes=limit)

    assert len(body) == limit


@pytest.mark.parametrize("limit", [64 * 1024, 2 * 1024 * 1024])
async def test_bounded_body_rejects_one_byte_over_limit(limit: int) -> None:
    with pytest.raises(BodyTooLargeError, match=str(limit)):
        await read_bounded_body(_chunks(b"a" * limit, b"b"), max_bytes=limit)


async def test_bounded_body_stops_at_crossing_chunk() -> None:
    consumed: list[int] = []

    async def _tracked() -> AsyncIterator[bytes]:
        for part in (b"12345", b"67890", b"never-read"):
            consumed.append(len(part))
            yield part

    with pytest.raises(BodyTooLargeError):
        await read_bounded_body(_tracked(), max_bytes=8)

    assert consumed == [5, 5]


def test_async_client_follows_redirects_by_default() -> None:
    client = build_async_http_client(_Settings(), timeout=5.0)

    assert client.follow_redirects is True


def test_async_client_honours_disabled_redirects() -> None:
    client = build_async_http_client(_Settings(), timeout=5.0, follow_redirects=False)

    assert client.follow_redirects is False
