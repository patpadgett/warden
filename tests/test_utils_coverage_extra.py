from __future__ import annotations
from warden.utils import RateLimiter, RedisRateLimiter

def test_memory_rate_limiter() -> None:
    r = RateLimiter()
    assert r.allow("test", 2, 60.0) is True
    assert r.allow("test", 2, 60.0) is True
