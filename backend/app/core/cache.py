"""In-process TTL cache.

Deliberately shaped like Redis — ``get(key)`` / ``set(key, value, ttl)`` — so the
answer to "why not Redis?" is a file someone can open rather than a promise. The
migration is an import change and a connection string.

For the MVP this is the right call twice over. It removes a daemon that can die
mid-demo, and it removes a class of failure where the cache is up but empty and
every page load burns Safe Browsing quota.

Not an optimisation. Rehearsing a demo means reloading the same page twenty
times; without this, that is twenty Safe Browsing calls and twenty RDAP calls,
and RDAP throttles by IP. The cache is what stops rehearsal from breaking the
performance.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any

#: Hard ceiling on entries. A browsing session touches a bounded number of
#: domains, but an unbounded dict in a long-lived process is a leak waiting for
#: a slow afternoon.
DEFAULT_MAX_ENTRIES = 2_000


@dataclass
class _Entry:
    value: Any
    expires_at: float


class TTLCache:
    """Thread-safe, lazily-expiring key/value store."""

    def __init__(self, max_entries: int = DEFAULT_MAX_ENTRIES) -> None:
        self._data: dict[str, _Entry] = {}
        self._lock = threading.Lock()
        self._max_entries = max_entries

    def get(self, key: str) -> Any | None:
        """Return the cached value, or ``None`` if absent or expired.

        ``None`` is an unusable sentinel if callers ever cache ``None``. They do
        not — the site engine caches a verdict object, and "no verdict" is
        represented by an ``unknown`` verdict rather than by absence.
        """
        now = time.monotonic()
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            if entry.expires_at <= now:
                # Expire on read rather than on a timer. No background thread to
                # supervise, and a key nobody asks for costs nothing to keep.
                del self._data[key]
                return None
            return entry.value

    def set(self, key: str, value: Any, ttl: float) -> None:
        now = time.monotonic()
        with self._lock:
            if len(self._data) >= self._max_entries and key not in self._data:
                self._evict_locked(now)
            self._data[key] = _Entry(value=value, expires_at=now + ttl)

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def _evict_locked(self, now: float) -> None:
        """Drop expired entries; if that frees nothing, drop the soonest to expire.

        Caller must hold the lock. Evicting by expiry rather than by LRU is the
        cheaper approximation and is well matched to this workload, where every
        entry has the same TTL and age is therefore the same ordering as LRU.
        """
        expired = [k for k, e in self._data.items() if e.expires_at <= now]
        for key in expired:
            del self._data[key]
        if not expired and self._data:
            oldest = min(self._data, key=lambda k: self._data[k].expires_at)
            del self._data[oldest]
