"""Thread-safe token bucket rate limiter for HTTP adapter throttling.

A token bucket allows a configurable burst (up to `capacity` tokens) then
refills at `rate` tokens/second.  Concurrent callers each claim a future token
slot and sleep only for their specific wait -- they do not serialize behind each
other for the full interval.

Usage (module-level singleton, shared across all instances of an adapter)::

    _limiter = TokenBucketRateLimiter(rate=1 / 0.75, capacity=1)

    def make_request():
        _limiter.acquire()
        return httpx.get(url)

The lock is held only during the token accounting calculation -- never during
the sleep -- so it scales to many concurrent callers without contention.

Backpressure (#54)
------------------
Under a concurrent burst the previous accounting drove ``self._tokens``
arbitrarily negative -- the 100th caller in a stampede would then wait
``100 / rate`` seconds (~75s at ``rate = 1 / 0.75``, and unboundedly higher
for larger bursts). The limiter now clamps the debt floor via
``max_wait_seconds`` and raises :class:`RateLimitError` when a claim would
exceed that ceiling. Callers propagate the failure as an upstream 429 instead
of pinning a worker for minutes on cumulative sleep.
"""

from __future__ import annotations

import threading
import time

from aila.platform.exceptions import RateLimitError


class TokenBucketRateLimiter:
    """Token bucket rate limiter safe for use across multiple threads.

    Args:
        rate: Refill rate in tokens per second (e.g. 1/0.75 ≈ 1.33 req/s).
        capacity: Maximum tokens the bucket can hold (burst size).
                  Defaults to 1 (no burst -- pure leaky-bucket behaviour).
        max_wait_seconds: Upper bound on the sleep any single caller may be
                  assigned. When the pending debt would push wait above this
                  value the limiter refuses the claim (raises
                  :class:`RateLimitError`) rather than pinning the caller for
                  minutes on cumulative sleep. Bounds queue depth so a burst
                  cannot drive tokens arbitrarily negative. Defaults to 60s.
    """

    #: Sentinel used to disable the backpressure cap (tests/edge cases).
    _NO_LIMIT: float = float("inf")

    def __init__(
        self,
        rate: float,
        capacity: float = 1.0,
        max_wait_seconds: float = 60.0,
    ) -> None:
        if rate <= 0:
            raise ValueError(f"rate must be positive, got {rate}")
        if capacity <= 0:
            raise ValueError(f"capacity must be positive, got {capacity}")
        if max_wait_seconds <= 0:
            raise ValueError(
                f"max_wait_seconds must be positive, got {max_wait_seconds}"
            )
        self._rate = rate
        self._capacity = capacity
        self._max_wait_seconds = max_wait_seconds
        self._tokens = capacity
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Block until a token is available, then consume it.

        The lock is held only for the accounting step.  Sleep (if any) happens
        outside the lock so concurrent callers do not serialize on it.

        Raises:
            RateLimitError: When the accounting step determines the required
                wait would exceed ``max_wait_seconds``. The token is NOT
                claimed so the limiter's internal debt stays bounded.
        """
        sleep_for = self._claim_token()
        if sleep_for > 0:
            time.sleep(sleep_for)

    def _claim_token(self) -> float:
        """Refill bucket, claim one token, return seconds to sleep (0 if immediate).

        Concurrent callers each get their own future slot -- the next caller will
        see a bucket that already has the current caller's token subtracted, so
        it naturally gets assigned a slot one interval later.

        Raises:
            RateLimitError: When the required wait would exceed
                ``max_wait_seconds``. The claim is refused so the debt floor
                stays bounded across a concurrent stampede.
        """
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
            self._last_refill = now

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return 0.0

            # Not enough tokens -- calculate how long until one is available.
            # Refuse the claim if it would push the caller past the backpressure
            # ceiling; this is the debt-floor clamp (#54).
            deficit = 1.0 - self._tokens
            wait = deficit / self._rate
            if wait > self._max_wait_seconds:
                raise RateLimitError(
                    f"rate limiter queue full: wait {wait:.2f}s exceeds "
                    f"max_wait_seconds={self._max_wait_seconds:.2f}s "
                    f"(rate={self._rate:.3f}/s, capacity={self._capacity:g})"
                )
            # Pre-subtract the token we are claiming for the future slot; the
            # backpressure check above guarantees ``self._tokens`` never drops
            # below ``-max_wait_seconds * rate`` even under a large burst, so
            # a subsequent caller's calculated wait stays bounded.
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
