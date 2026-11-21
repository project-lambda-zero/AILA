"""IdempotencyMiddleware namespaces its Redis cache key by the caller's
credential so a replayed Idempotency-Key cannot read another tenant's
cached response (issue #57)."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from aila.api.middleware import idempotency
from aila.api.middleware.idempotency import (
    _IDEMPOTENCY_PREFIX,
    IdempotencyMiddleware,
    _derive_cache_key,
    _is_idempotency_exempt,
)

PENTEST_EXEMPT_PATHS = (
    "/pentest/live/campaigns",
    "/pentest/live/templates/{template_id}/campaigns",
)


@pytest.fixture
def declared_pentest_exempt_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stand in for module discovery with the pentest declarations only."""
    monkeypatch.setattr(
        "aila.api.middleware.idempotency.declared_idempotency_exempt_post_paths",
        lambda: PENTEST_EXEMPT_PATHS,
    )
    idempotency._idempotency_exempt_patterns.cache_clear()
    yield
    idempotency._idempotency_exempt_patterns.cache_clear()


@pytest.mark.parametrize(
    "path",
    [
        "/pentest/live/campaigns",
        "/pentest/live/templates/tpl-1/campaigns",
    ],
)
def test_declared_exempt_paths_match(declared_pentest_exempt_paths: None, path: str) -> None:
    assert _is_idempotency_exempt(path)


@pytest.mark.parametrize(
    "path",
    [
        "/pentest/live/campaigns/extra",
        "/pentest/live/templates/tpl-1/campaigns/extra",
        "/pentest/live/templates/a/b/campaigns",
        "/vr/projects",
    ],
)
def test_undeclared_or_deeper_paths_are_not_exempt(declared_pentest_exempt_paths: None, path: str) -> None:
    assert not _is_idempotency_exempt(path)


def test_cross_credential_keys_differ() -> None:
    a = _derive_cache_key("k1", "Bearer AAA")
    b = _derive_cache_key("k1", "Bearer BBB")
    assert a != b, "same idem-key from different credentials must not collide"


def test_same_credential_same_key_replays() -> None:
    assert _derive_cache_key("k1", "Bearer AAA") == _derive_cache_key("k1", "Bearer AAA")


def test_distinct_keys_within_anon_bucket() -> None:
    assert _derive_cache_key("k1", None) != _derive_cache_key("k2", None)


def test_raw_credential_not_embedded() -> None:
    key = _derive_cache_key("k1", "Bearer super-secret-token")
    assert "super-secret-token" not in key
    assert key.startswith(_IDEMPOTENCY_PREFIX)


def test_cookie_credential_also_scopes() -> None:
    # Cookie-based auth is scoped the same way as bearer auth.
    assert _derive_cache_key("k1", "session=aaa") != _derive_cache_key("k1", "session=bbb")


@pytest.mark.asyncio
async def test_live_campaign_create_uses_route_fingerprint_not_response_cache(
    declared_pentest_exempt_paths: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    middleware = IdempotencyMiddleware(app=None)
    request = SimpleNamespace(method="POST", url=SimpleNamespace(path="/pentest/live/campaigns"))
    expected = object()

    def fail_if_redis_is_checked() -> None:
        raise AssertionError("Live route idempotency must run before the generic Redis cache")

    async def call_next(received: object) -> object:
        assert received is request
        return expected

    monkeypatch.setattr("aila.api.middleware.idempotency.pool_available", fail_if_redis_is_checked)
    assert await middleware.dispatch(request, call_next) is expected
