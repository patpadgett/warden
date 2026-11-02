from __future__ import annotations

import time

from warden.utils import RateLimiter


def test_memory_rate_limiter() -> None:
    r = RateLimiter()
    assert r.allow("test", 2, 60.0)[0] is True
    assert r.allow("test", 2, 60.0)[0] is True


def test_memory_rate_limiter_blocks_after_limit() -> None:
    r = RateLimiter()
    assert r.allow("key", 2, 60.0)[0] is True
    assert r.allow("key", 2, 60.0)[0] is True
    assert r.allow("key", 2, 60.0)[0] is False
    assert r.allow("other", 1, 60.0)[0] is True


def test_memory_rate_limiter_expires_old_entries() -> None:
    r = RateLimiter()
    assert r.allow("key", 1, 0.5)[0] is True
    time.sleep(0.6)
    assert r.allow("key", 1, 0.5)[0] is True
