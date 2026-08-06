"""Platform SSE streaming helpers.

Modules must not own async plumbing (Queue, create_task, wait_for) per the
"platform decides threading internally" rule. Use these helpers to expose a
StreamingResponse-ready generator while keeping asyncio primitives behind
the platform boundary.
"""
from __future__ import annotations

from .user_fanout import QUEUE_MAXSIZE, UserFanoutRegistry
from .worker_stream import stream_from_worker

__all__ = ["QUEUE_MAXSIZE", "UserFanoutRegistry", "stream_from_worker"]
