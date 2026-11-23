"""Async system DNS resolution owned by the platform services layer."""
from __future__ import annotations

import socket

from .runtime import run_blocking_io

__all__ = ["resolve_system_addresses"]


async def resolve_system_addresses(host: str) -> list[str]:
    """Resolve unique numeric addresses without blocking the event loop."""
    def resolve() -> list[str]:
        answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        return sorted({str(answer[4][0]) for answer in answers})

    return await run_blocking_io(resolve)
