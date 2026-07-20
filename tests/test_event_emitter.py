"""Tests for EventEmitter and ThreadSafeEventEmitter."""
from __future__ import annotations

import threading

from aila.platform.events.emitter import EventEmitter, ThreadSafeEventEmitter
from aila.platform.events.event import PlatformEvent


def _make_event(key: str = "test") -> PlatformEvent:
    return PlatformEvent(stage="test", action="test", key=key, message="test event")


class TestEventEmitter:
    def test_register_and_emit(self):
        emitter = EventEmitter()
        received = []
        emitter.register_destination("sink", lambda e: received.append(e.key))
        emitter.emit(_make_event("a"))
        assert received == ["a"]

    def test_multiple_destinations(self):
        emitter = EventEmitter()
        r1, r2 = [], []
        emitter.register_destination("d1", lambda e: r1.append(e.key))
        emitter.register_destination("d2", lambda e: r2.append(e.key))
        emitter.emit(_make_event("x"))
        assert r1 == ["x"]
        assert r2 == ["x"]

    def test_emit_with_no_destinations(self):
        emitter = EventEmitter()
        emitter.emit(_make_event())  # must not raise

    def test_order_preserved(self):
        emitter = EventEmitter()
        order = []
        emitter.register_destination("first", lambda e: order.append("first"))
        emitter.register_destination("second", lambda e: order.append("second"))
        emitter.emit(_make_event())
        assert order == ["first", "second"]


class TestThreadSafeEventEmitter:
    def test_basic_emit(self):
        emitter = ThreadSafeEventEmitter()
        received = []
        emitter.register_destination("sink", lambda e: received.append(e.key))
        emitter.emit(_make_event("a"))
        assert received == ["a"]

    def test_concurrent_emit(self):
        emitter = ThreadSafeEventEmitter()
        received = []
        lock = threading.Lock()

        def dest(e):
            with lock:
                received.append(e.key)

        emitter.register_destination("sink", dest)
        threads = [threading.Thread(target=emitter.emit, args=(_make_event(str(i)),)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(received) == 20
        assert set(received) == {str(i) for i in range(20)}

    def test_multiple_events_sequential(self):
        emitter = ThreadSafeEventEmitter()
        received = []
        emitter.register_destination("sink", lambda e: received.append(e.key))
        for i in range(5):
            emitter.emit(_make_event(str(i)))
        assert received == ["0", "1", "2", "3", "4"]

    def test_no_destinations_safe(self):
        emitter = ThreadSafeEventEmitter()
        emitter.emit(_make_event())  # must not raise


class TestSyncRedisClientCache:
    """#60-2: the redis_stream destination reuses one pooled client per URL."""

    def test_client_is_created_once_and_reused(self):
        import pytest
        pytest.importorskip("redis")
        from unittest.mock import MagicMock, patch

        from aila.platform.events import emitter as emitter_mod

        url = "redis://localhost:6379/7"
        emitter_mod._SYNC_REDIS_CLIENTS.pop(url, None)
        sentinel = MagicMock(name="redis-client")
        try:
            with patch("redis.from_url", return_value=sentinel) as from_url:
                first = emitter_mod._get_sync_redis_client(url)
                second = emitter_mod._get_sync_redis_client(url)
            assert first is sentinel
            assert second is sentinel
            assert from_url.call_count == 1  # not re-created per call
        finally:
            emitter_mod._SYNC_REDIS_CLIENTS.pop(url, None)
