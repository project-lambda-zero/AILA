"""IdempotencyMiddleware namespaces its Redis cache key by the caller's
credential so a replayed Idempotency-Key cannot read another tenant's
cached response (issue #57)."""
from __future__ import annotations

from aila.api.middleware.idempotency import _IDEMPOTENCY_PREFIX, _derive_cache_key


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
