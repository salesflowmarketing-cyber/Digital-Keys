"""
digital_keys.ratelimit - stop passphrase guessing.

The control API used to accept unlimited ``/v1/grant`` attempts, each carrying a
candidate vault passphrase. Argon2id at 64 MiB makes every attempt cost roughly
a tenth of a second, which is a real deterrent but not a limit: an attacker on
the same machine could still run thousands of attempts an hour, and the correct
passphrase eventually lands.

This module adds the missing limit. Failures are counted per key (the peer's
UID on a Unix socket, the peer address on TCP) inside a sliding window. When the
window fills, the key is locked out for a period that doubles on each repeat
offence, up to a ceiling. A successful call clears the key, so a legitimate
operator who mistypes once is never locked out for long.

The limiter is process-local and in-memory. That is deliberate: a broker restart
clears it, but a restart also rotates the control token and drops every
outstanding grant, so the attacker gains nothing by waiting for one.
"""

from __future__ import annotations

import threading
import time
from collections import deque


class RateLimiter:
    """
    Sliding-window failure counter with escalating lockout.

    Example: with the defaults, five failures inside sixty seconds lock the key
    for thirty seconds. Five more failures after the lockout expires lock it for
    sixty, then a hundred and twenty, and so on to fifteen minutes.
    """

    def __init__(
        self,
        max_failures: int = 5,
        window: float = 60.0,
        base_lockout: float = 30.0,
        max_lockout: float = 900.0,
        clock=time.monotonic,
    ) -> None:
        if max_failures < 1:
            raise ValueError("max_failures must be at least 1")
        self.max_failures = max_failures
        self.window = window
        self.base_lockout = base_lockout
        self.max_lockout = max_lockout
        self._clock = clock
        self._lock = threading.Lock()
        self._failures: dict[str, deque[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._strikes: dict[str, int] = {}

    # -- queries ----------------------------------------------------------

    def retry_after(self, key: str) -> float | None:
        """
        Seconds the caller must wait, or None if it may proceed.

        Returns a value rounded up so callers never print "retry in 0.0s".
        """
        with self._lock:
            until = self._locked_until.get(key)
            if until is None:
                return None
            now = self._clock()
            if now >= until:
                del self._locked_until[key]
                return None
            return max(1.0, float(int(until - now) + 1))

    # -- mutation ---------------------------------------------------------

    def fail(self, key: str) -> float | None:
        """
        Record one failed attempt. Returns the lockout length if this failure
        tripped the limit, else None.
        """
        with self._lock:
            now = self._clock()
            hits = self._failures.setdefault(key, deque())
            hits.append(now)
            self._prune(hits, now)

            if len(hits) < self.max_failures:
                return None

            strikes = self._strikes.get(key, 0) + 1
            self._strikes[key] = strikes
            lockout = min(self.base_lockout * (2 ** (strikes - 1)), self.max_lockout)
            self._locked_until[key] = now + lockout
            hits.clear()
            return lockout

    def succeed(self, key: str) -> None:
        """Clear every trace of failure for this key."""
        with self._lock:
            self._failures.pop(key, None)
            self._locked_until.pop(key, None)
            self._strikes.pop(key, None)

    # -- internals --------------------------------------------------------

    def _prune(self, hits: deque[float], now: float) -> None:
        cutoff = now - self.window
        while hits and hits[0] < cutoff:
            hits.popleft()


def key_for_peer(uid: int | None, addr: object) -> str:
    """
    A stable key for whoever is calling.

    A verified UID is the strongest identity available, so prefer it. Otherwise
    fall back to the socket peer address. ``addr`` is a ``(host, port)`` tuple
    on TCP and a path string on Unix sockets.
    """
    if uid is not None:
        return f"uid:{uid}"
    if isinstance(addr, tuple) and addr:
        return f"ip:{addr[0]}"
    return f"peer:{addr}"
