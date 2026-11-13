"""Cooperative cancellation and rate limiting for active workers."""

from __future__ import annotations

import time
from threading import Event, Lock

from netsentinel.domain.errors import OperationCancelled


class CancellationToken:
    """Thread-safe cancellation signal shared by a job and its adapters."""

    def __init__(self) -> None:
        self._event = Event()

    @property
    def is_cancelled(self) -> bool:
        """Return whether cancellation has been requested."""
        return self._event.is_set()

    def cancel(self) -> None:
        """Request cancellation; setting the token is idempotent."""
        self._event.set()

    def wait(self, timeout: float | None = None) -> bool:
        """Wait for cancellation and return the event state."""
        return self._event.wait(timeout)

    def raise_if_cancelled(self) -> None:
        """Raise a domain error at a cooperative cancellation checkpoint."""
        if self.is_cancelled:
            raise OperationCancelled("The operation was cancelled")


class RateLimiter:
    """Serialize operation starts to a configured maximum rate."""

    def __init__(self, rate_per_second: float) -> None:
        if rate_per_second <= 0:
            raise ValueError("rate_per_second must be positive")
        self._interval = 1.0 / rate_per_second
        self._lock = Lock()
        self._next_slot = 0.0

    def wait(self, cancellation: CancellationToken | None = None) -> None:
        """Wait until the next operation slot, honoring cancellation."""
        while True:
            if cancellation is not None:
                cancellation.raise_if_cancelled()

            with self._lock:
                now = time.monotonic()
                slot = max(now, self._next_slot)
                delay = slot - now
                self._next_slot = slot + self._interval

            if delay <= 0:
                return
            if cancellation is not None:
                cancellation.wait(delay)
            else:
                time.sleep(delay)
