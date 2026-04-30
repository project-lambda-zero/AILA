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
