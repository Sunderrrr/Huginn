"""A small in-process fixed-window rate limiter.

Sufficient for a single hub instance. For a horizontally-scaled deployment, back
this with Redis; the interface stays the same.
"""

from __future__ import annotations

import threading
import time


class RateLimiter:
    def __init__(self, max_per_minute: int) -> None:
        self._max = max_per_minute
        self._window = 60.0
        self._lock = threading.Lock()
        self._buckets: dict[str, tuple[float, int]] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            start, count = self._buckets.get(key, (now, 0))
            if now - start >= self._window:
                start, count = now, 0
            if count >= self._max:
                self._buckets[key] = (start, count)
                return False
            self._buckets[key] = (start, count + 1)
            return True

    def check(self, key: str) -> bool:
        """Return whether the key is currently under the limit, without consuming."""
        now = time.monotonic()
        with self._lock:
            start, count = self._buckets.get(key, (now, 0))
            if now - start >= self._window:
                return True
            return count < self._max
