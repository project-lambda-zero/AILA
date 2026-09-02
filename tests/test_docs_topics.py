"""Unit tests for the read-only docs router helpers (req 29).

Pure-function tests: no TestClient, no DB, no auth fixtures. Exercises the
allow-list lookup, path escape rejection, and body read.
"""
from __future__ import annotations

from aila.api.routers.docs import (
    available_topics,
    read_topic_body,
    resolve_topic_path,
)

_REQUIRED_SLUGS: frozenset[str] = frozenset(
    {
        "quick-start",
        "module-standard",
        "frontend-module-standard",
        "golden-rules",
        "changelog",
    }
)


def test_available_topics_includes_required_slugs() -> None:
    topics = available_topics()
    slugs = {t.slug for t in topics}
    missing = _REQUIRED_SLUGS - slugs
    assert not missing, f"missing required slugs: {sorted(missing)}"
    for topic in topics:
        assert topic.title, f"empty title for slug={topic.slug!r}"


def test_available_topics_all_resolve_to_files() -> None:
    for topic in available_topics():
        path = resolve_topic_path(topic.slug)
        assert path is not None, f"resolve_topic_path({topic.slug!r}) returned None"
        assert path.is_file(), f"resolved path is not a file: {path}"


def test_resolve_topic_path_rejects_unknown_and_escape_keys() -> None:
    hostile_keys = (
        "does-not-exist",
        "..",
        "../etc/passwd",
        "docs/MODULE_STANDARD.md",
        "%2e%2e%2fetc%2fpasswd",
        "../../pyproject.toml",
    )
    for key in hostile_keys:
        assert resolve_topic_path(key) is None, f"expected None for key={key!r}"


def test_read_topic_body_rejects_escape_key() -> None:
    assert read_topic_body("../etc/passwd") is None


def test_read_topic_body_returns_content_for_known_slug() -> None:
    body = read_topic_body("module-standard")
    assert body is not None
    assert len(body) > 0
