"""Thread-safe token bucket rate limiter for HTTP adapter throttling.

A token bucket allows a configurable burst (up to `capacity` tokens) then
refills at `rate` tokens/second.  Concurrent callers each claim a future token
slot and sleep only for their specific wait — they do not serialize behind each
other for the full interval.

Usage (module-level singleton, shared across all instances of an adapter)::

    _limiter = TokenBucketRateLimiter(rate=1 / 0.75, capacity=1)

    def make_request():
        _limiter.acquire()
        return httpx.get(url)

The lock is held only during the token accounting calculation — never during
the sleep — so it scales to many concurrent callers without contention.
"""

from __future__ import annotations

import threading
import time


class TokenBucketRateLimiter:
    """Token bucket rate limiter safe for use across multiple threads.

    Args:
        rate: Refill rate in tokens per second (e.g. 1/0.75 ≈ 1.33 req/s).
        capacity: Maximum tokens the bucket can hold (burst size).
                  Defaults to 1 (no burst — pure leaky-bucket behaviour).
    """

    def __init__(self, rate: float, capacity: float = 1.0) -> None:
        if rate <= 0:
            raise ValueError(f"rate must be positive, got {rate}")
        if capacity <= 0:
            raise ValueError(f"capacity must be positive, got {capacity}")
        self._rate = rate
        self._capacity = capacity
        self._tokens = capacity
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Block until a token is available, then consume it.

        The lock is held only for the accounting step.  Sleep (if any) happens
        outside the lock so concurrent callers do not serialize on it.
        """
        sleep_for = self._claim_token()
        if sleep_for > 0:
            time.sleep(sleep_for)

    def _claim_token(self) -> float:
        """Refill bucket, claim one token, return seconds to sleep (0 if immediate).

        Concurrent callers each get their own future slot — the next caller will
        see a bucket that already has the current caller's token subtracted, so
        it naturally gets assigned a slot one interval later.
        """
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
            self._last_refill = now

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return 0.0

            # Not enough tokens — calculate how long until one is available
            deficit = 1.0 - self._tokens
            wait = deficit / self._rate
            # Pre-subtract the token we are claiming for the future slot
            self._tokens -= 1.0
            return wait

    def update_rate(self, rate: float) -> None:
        """Update the refill rate at runtime (e.g. after token resolution).

        Args:
            rate: New refill rate in tokens per second.
        """
        if rate <= 0:
            raise ValueError(f"rate must be positive, got {rate}")
        with self._lock:
            self._rate = rate
