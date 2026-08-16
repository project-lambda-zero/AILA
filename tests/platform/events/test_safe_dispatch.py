"""Unit tests for the shared fan-out isolation primitive
(:mod:`aila.platform.events._dispatch`).

Both :class:`aila.platform.events.emitter.EventEmitter` and
:class:`aila.platform.events.bus.DomainEventBus` route their
per-subscriber isolation through :func:`safe_dispatch`. These tests
exercise the primitive directly and then confirm both event systems
still honour the contract end-to-end (delivery past a raising
subscriber, failure counter increment, never-crash-the-caller).

Pure in-memory tests: no HTTP, no Redis, no database.
"""
from __future__ import annotations

from typing import Any

from aila.platform.events._dispatch import ISOLATION_ERRORS, safe_dispatch
from aila.platform.events.bus import DomainEventBus, SubscriberFn
from aila.platform.events.domain_events import (
    ConfigChanged,
    ConfigChangedPayload,
)
from aila.platform.events.emitter import EventEmitter
from aila.platform.events.event import PlatformEvent


def _event(key: str = "k", stage: str = "s", action: str = "a") -> PlatformEvent:
    return PlatformEvent(stage=stage, action=action, key=key, message="m")


def _domain_event(namespace: str = "test") -> ConfigChanged:
    return ConfigChanged(
        payload=ConfigChangedPayload(
            namespace=namespace, key="k", old_value="", new_value="v",
        ),
    )


# ---------------------------------------------------------------------------
# Primitive-level tests: safe_dispatch alone.
# ---------------------------------------------------------------------------


class TestSafeDispatch:
    def test_calls_subscriber_with_event(self) -> None:
        seen: list[Any] = []
        evt = _event()
        safe_dispatch(
            "sub",
            seen.append,
            evt,
            log_label="test",
            event_description="evt",
        )
        assert seen == [evt]

    def test_exception_never_propagates_to_caller(self) -> None:
        """Every ISOLATION_ERRORS family is caught inside the guard."""
        def bad(_evt: Any) -> None:
            raise RuntimeError("boom")

        # No try/except in the caller -- if the guard leaks, the test fails.
        safe_dispatch(
            "bad",
            bad,
            _event(),
            log_label="test",
            event_description="evt",
        )

    def test_on_failure_hook_receives_name_and_exception(self) -> None:
        seen_failures: list[tuple[str, BaseException]] = []

        def bad(_evt: Any) -> None:
            raise ValueError("nope")

        safe_dispatch(
            "bad",
            bad,
            _event(),
            log_label="test",
            event_description="evt",
            on_failure=lambda name, exc: seen_failures.append((name, exc)),
        )
        assert len(seen_failures) == 1
        assert seen_failures[0][0] == "bad"
        assert isinstance(seen_failures[0][1], ValueError)

    def test_on_failure_hook_not_called_on_success(self) -> None:
        calls: list[Any] = []
        safe_dispatch(
            "ok",
            lambda _evt: None,
            _event(),
            log_label="test",
            event_description="evt",
            on_failure=lambda name, exc: calls.append((name, exc)),
        )
        assert calls == []

    def test_baseexception_only_subclasses_propagate(self) -> None:
        """KeyboardInterrupt / SystemExit MUST NOT be swallowed."""
        def rude(_evt: Any) -> None:
            raise KeyboardInterrupt

        raised = False
        try:
            safe_dispatch(
                "rude",
                rude,
                _event(),
                log_label="test",
                event_description="evt",
            )
        except KeyboardInterrupt:
            raised = True
        assert raised, "KeyboardInterrupt must propagate past the isolation guard"

    def test_isolation_tuple_covers_broad_families(self) -> None:
        """The shared policy must cover every family the platform relies on."""
        expected = {
            RuntimeError,
            OSError,
            TimeoutError,
            ValueError,
            TypeError,
            AttributeError,
            KeyError,
            IndexError,
            LookupError,
            ArithmeticError,
            ImportError,
            AssertionError,
            ReferenceError,
        }
        for family in expected:
            assert issubclass(family, ISOLATION_ERRORS), (
                f"{family.__name__} missing from ISOLATION_ERRORS"
            )


# ---------------------------------------------------------------------------
# End-to-end: both event systems now route through the shared primitive.
# ---------------------------------------------------------------------------


class TestEventEmitterUsesSafeDispatch:
    def test_delivers_to_all_destinations(self) -> None:
        emitter = EventEmitter()
        seen: dict[str, list[PlatformEvent]] = {"a": [], "b": [], "c": []}
        for name in ("a", "b", "c"):
            emitter.register_destination(name, seen[name].append)
        evt = _event()
        emitter.emit(evt)
        assert seen == {"a": [evt], "b": [evt], "c": [evt]}

    def test_failure_isolates_and_fan_out_continues(self) -> None:
        emitter = EventEmitter()
        received_after_bad: list[PlatformEvent] = []

        def bad(_evt: PlatformEvent) -> None:
            raise RuntimeError("first destination raises")

        emitter.register_destination("bad", bad)
        emitter.register_destination("good", received_after_bad.append)

        evt = _event()
        emitter.emit(evt)  # must not raise

        # Downstream destination still saw the event.
        assert received_after_bad == [evt]
        # Failure counter incremented for the offender only.
        failures = emitter.get_destination_failures()
        assert failures == {"bad": 1}


class TestDomainEventBusUsesSafeDispatch:
    def test_delivers_to_all_subscribers(self) -> None:
        bus = DomainEventBus()
        seen: dict[str, list[Any]] = {"a": [], "b": [], "c": []}
        for name in ("a", "b", "c"):
            appender: SubscriberFn = seen[name].append
            bus.subscribe(name, appender)
        evt = _domain_event()
        bus.publish(evt)
        assert seen == {"a": [evt], "b": [evt], "c": [evt]}

    def test_failure_isolates_and_fan_out_continues(self) -> None:
        bus = DomainEventBus()
        received_after_bad: list[Any] = []

        def bad(_evt: Any) -> None:
            raise RuntimeError("first subscriber raises")

        bus.subscribe("bad", bad)
        bus.subscribe("good", received_after_bad.append)

        evt = _domain_event()
        bus.publish(evt)  # must not raise

        assert len(received_after_bad) == 1
        assert received_after_bad[0] is evt
        assert bus.failure_counts() == {"bad": 1}
