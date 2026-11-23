"""Synthetic deterministic classifiers for the agent endpoint runtime."""
from __future__ import annotations

import pytest

from aila.modules.pentest.services.transports.classification import (
    EventClass,
    EventRules,
    classify_engagement,
    classify_event,
    is_fatal_auth_status,
    is_terminal_event,
)

_PROMPT = "synthetic prompt"


def _event(**changes: object) -> dict[str, object]:
    event: dict[str, object] = {"kind": "final", "text": "synthetic answer", "terminal": True}
    event.update(changes)
    return event


def _classify(event: dict[str, object], rules: EventRules = EventRules()) -> object:
    return classify_event(
        event,
        prompt=_PROMPT,
        correlation_id="turn-correlation",
        session_id="raw-session",
        generation=3,
        rules=rules,
    )


def test_internal_and_history_events_precede_candidate_classification() -> None:
    assert _classify(_event(channel="internal")).disposition is EventClass.INTERNAL
    assert _classify(_event(kind="telemetry")).disposition is EventClass.INTERNAL
    assert _classify(_event(history=True)).disposition is EventClass.HISTORY
    assert _classify(_event(kind="history")).disposition is EventClass.HISTORY


def test_stale_generation_and_session_are_never_candidates() -> None:
    rules = EventRules(generation_path="meta.generation", session_path="meta.session")
    stale_generation = _classify(_event(meta={"generation": 2, "session": "raw-session"}), rules)
    stale_session = _classify(_event(meta={"generation": 3, "session": "older-session"}), rules)
    malformed_generation = _classify(_event(meta={"generation": True, "session": "raw-session"}), rules)
    assert stale_generation.disposition is EventClass.STALE
    assert stale_session.disposition is EventClass.STALE
    assert malformed_generation.disposition is EventClass.STALE


def test_correlation_rule_is_strict_when_configured() -> None:
    rules = EventRules(correlation_path="meta.correlation")
    missing = _classify(_event(), rules)
    wrong = _classify(_event(meta={"correlation": "other-turn"}), rules)
    matched = _classify(_event(meta={"correlation": "turn-correlation"}), rules)
    assert missing.disposition is EventClass.CORRELATION_MISMATCH
    assert wrong.disposition is EventClass.CORRELATION_MISMATCH
    assert matched.disposition is EventClass.CANDIDATE


def test_echo_requires_a_declared_rule_or_explicit_signal() -> None:
    assert _classify(_event(kind="echo", text=_PROMPT)).disposition is EventClass.ECHO
    assert _classify(_event(text=_PROMPT)).disposition is EventClass.CANDIDATE
    assert _classify(_event(text=_PROMPT), EventRules(reject_exact_prompt=True)).disposition is EventClass.ECHO
    echo_path = EventRules(echo_path="meta.original")
    assert _classify(_event(meta={"original": _PROMPT}), echo_path).disposition is EventClass.ECHO


def test_malformed_candidate_does_not_become_empty_engaged_response() -> None:
    result = _classify(_event(text=17))
    assert result.disposition is EventClass.MALFORMED
    assert classify_engagement(None, candidate=False) == "unknown"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("route: elsewhere", "routed_away"),
        ("scope: unrelated", "off_topic"),
        ("generic fallback", "fallback"),
        ("ordinary answer", "engaged"),
    ]
)
def test_engagement_markers_have_deterministic_precedence(text: str, expected: str) -> None:
    rules = EventRules(
        off_topic_markers=("scope: unrelated",),
        routed_away_markers=("route: elsewhere",),
        fallback_markers=("generic fallback",),
    )
    assert classify_engagement(text, rules=rules) == expected


def test_explicit_engagement_and_strict_engaged_markers_fail_closed() -> None:
    assert classify_engagement("answer", explicit="off_topic") == "off_topic"
    assert classify_engagement("answer", explicit="not-a-state") == "unknown"
    rules = EventRules(engaged_markers=("expected marker",))
    assert classify_engagement("ordinary answer", rules=rules) == "unknown"
    assert classify_engagement("expected marker: answer", rules=rules) == "engaged"
    assert classify_engagement("answer", rules=EventRules(default_engaged=False)) == "unknown"


def test_terminal_and_fatal_auth_rules_are_exact() -> None:
    assert is_terminal_event(_event())
    assert is_terminal_event(_event(kind="message", terminal=False)) is False
    assert is_fatal_auth_status(401)
    assert is_fatal_auth_status(403)
    assert not is_fatal_auth_status(400)
    assert not is_fatal_auth_status(429)
    assert not is_fatal_auth_status(500)
