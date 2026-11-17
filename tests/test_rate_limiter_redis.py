"""Rate-limiter checks against a real Redis server.

They run when a server answers on ``WARDEN_TEST_REDIS_URL`` (default
``redis://localhost:6379/0``) and are skipped otherwise, so ``pytest`` without
Redis still passes; the CI workflow starts a ``redis:7`` service.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from warden.main import create_app
from warden.utils import RedisRateLimiter

from .conftest import config_dict, seed_user, write_config

REDIS_URL = os.environ.get("WARDEN_TEST_REDIS_URL", "redis://localhost:6379/0")


def _redis_available() -> bool:
    """Return ``True`` when redis-py is installed and the server answers."""
    try:
        import redis.asyncio as redis
    except ImportError:
        return False

    async def ping() -> bool:
        client = redis.from_url(REDIS_URL)
        try:
            return bool(await client.ping())
        except Exception:  # noqa: BLE001 - unreachable server means "skip"
            return False
        finally:
            await client.aclose()

    try:
        return asyncio.run(ping())
    except Exception:  # noqa: BLE001
        return False


pytestmark = pytest.mark.skipif(
    not _redis_available(), reason=f"no Redis server at {REDIS_URL}"
)


def _client():
    """Build a plain async client for inspecting what the limiter stored."""
    import redis.asyncio as redis

    return redis.from_url(REDIS_URL)


async def _rate_keys() -> set[str]:
    client = _client()
    try:
        return {key async for key in client.scan_iter("rate:*")}
    finally:
        await client.aclose()


async def _inspect_and_clean(keys: set[str]) -> list[tuple[int, int]]:
    """Return ``(cardinality, ttl)`` per key, then delete those keys."""
    if not keys:
        return []
    client = _client()
    try:
        stats = [(await client.zcard(key), await client.ttl(key)) for key in sorted(keys)]
        await client.delete(*keys)
        return stats
    finally:
        await client.aclose()


async def test_redis_limiter_enforces_limit_and_sets_ttl() -> None:
    limiter = RedisRateLimiter(REDIS_URL, ttl=60)
    key = f"pytest-{uuid.uuid4().hex}:login"
    zset = f"rate:{key}"
    client = _client()
    try:
        assert await limiter.allow(key, 2, 60.0) == (True, 1)
        assert await limiter.allow(key, 2, 60.0) == (True, 0)
        # The refusal is not recorded, so it cannot extend the window.
        assert await limiter.allow(key, 2, 60.0) == (False, 0)
        assert await client.zcard(zset) == 2
        assert await client.ttl(zset) > 0
    finally:
        await client.delete(zset)
        await client.aclose()
        await limiter.close()


async def test_redis_limiter_prunes_stale_entries_on_server() -> None:
    limiter = RedisRateLimiter(REDIS_URL, ttl=60)
    key = f"pytest-{uuid.uuid4().hex}:prune"
    zset = f"rate:{key}"
    client = _client()
    try:
        # A member from two windows ago must free the slot for a new request.
        await client.zadd(zset, {"stale": time.time() - 120})
        assert await limiter.allow(key, 1, 60.0) == (True, 0)
        assert await client.zcard(zset) == 1
        assert await client.zscore(zset, "stale") is None
    finally:
        await client.delete(zset)
        await client.aclose()
        await limiter.close()


def test_redis_backed_limiter_blocks_login_end_to_end(tmp_path: Path) -> None:
    """Sign-in attempts are counted in Redis and then refused with a 429."""
    before = asyncio.run(_rate_keys())
    path = write_config(tmp_path, config_dict(tmp_path))
    seed_user(tmp_path / "warden.db", credential_count=1)
    app = create_app(path)
    app.state.rate_limiter = RedisRateLimiter(REDIS_URL, ttl=300)
    blocked = None
    allowed = 0
    with TestClient(app, base_url="http://admin.home.lan") as client:
        for _ in range(100):
            response = client.post(
                "/_warden/auth/login/begin",
                json={"username": "pat", "next": "/"},
                headers={"host": "admin.home.lan", "origin": "http://admin.home.lan"},
            )
            if response.status_code == 429:
                blocked = response
                break
            assert response.status_code == 200, response.text
            allowed += 1
    created = asyncio.run(_rate_keys()) - before
    stats = asyncio.run(_inspect_and_clean(created))

    assert blocked is not None, "the limiter never blocked"
    assert allowed > 1
    assert blocked.headers["x-ratelimit-remaining"] == "0"
    assert int(blocked.headers["x-ratelimit-limit"]) == allowed
    # The attempts really landed in Redis, with a TTL so they expire.
    assert created, "no rate-limit key was written to Redis"
    assert all(cardinality >= 1 and ttl > 0 for cardinality, ttl in stats)
