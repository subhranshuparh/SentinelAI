"""Per-device token bucket.

Guards two distinct things, which is why it exists this early:

* **Your Gemini quota.** A content script bug — a debounce that stops debouncing,
  a re-render loop on a busy page — can fire hundreds of scans a second. Without
  a cap that drains a free-tier quota in minutes, mid-demo.
* **The backend itself.** ``/pii/scan`` runs 14 regexes over user text. Cheap
  individually, unbounded in aggregate.

In-memory, per-process, no dependency. Correct for a single-process MVP; a
multi-worker deploy would move this to Redis, using the same ``check()`` shape.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from fastapi import Depends, HTTPException, Request, status

from app.core.config import get_settings
from app.core.security import get_current_device

settings = get_settings()


@dataclass
class _Bucket:
    tokens: float
    last_refill: float


@dataclass
class TokenBucketLimiter:
    """Classic token bucket: steady refill, burst up to capacity.

    Chosen over a fixed window because typing is bursty by nature. A fixed
    window rejects a legitimate flurry of edits that lands at the wrong second;
    a bucket absorbs the burst and only throttles sustained abuse.
    """

    rate_per_minute: int
    _buckets: dict[str, _Bucket] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def _refill_per_second(self) -> float:
        return self.rate_per_minute / 60.0

    def check(self, key: str) -> tuple[bool, int]:
        """Consume one token. Returns ``(allowed, retry_after_seconds)``."""
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                # New callers start full so a first request is never throttled.
                bucket = _Bucket(tokens=float(self.rate_per_minute), last_refill=now)
                self._buckets[key] = bucket

            elapsed = now - bucket.last_refill
            bucket.tokens = min(
                float(self.rate_per_minute), bucket.tokens + elapsed * self._refill_per_second
            )
            bucket.last_refill = now

            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return True, 0

            # Seconds until one whole token is available again.
            deficit = 1.0 - bucket.tokens
            return False, max(1, int(deficit / self._refill_per_second) + 1)


_limiter = TokenBucketLimiter(rate_per_minute=settings.RATE_LIMIT_PER_MINUTE)


def rate_limit(request: Request, device_id: str = Depends(get_current_device)) -> str:
    """FastAPI dependency: enforce the limit, then hand back the device id.

    Returning the device id lets a route depend on this alone rather than on
    both this and ``get_current_device`` — one dependency, one identity, no way
    to accidentally rate-limit one key while acting on another.
    """
    allowed, retry_after = _limiter.check(device_id)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. SentinelAI is catching up.",
            headers={"Retry-After": str(retry_after)},
        )
    return device_id
