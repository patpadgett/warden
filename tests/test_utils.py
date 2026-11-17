from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

import pytest

from warden.config import RouteConfig, parse_config_text
from warden.utils import (
    RateLimiter,
    RedisRateLimiter,
    check_origin,
    get_host,
    get_port,
    is_reserved_cookie,
    parse_cookies,
    parse_user_agent,
    relative_time,
    route_color,
    route_initials,
    safe_next,
    strip_reserved_cookies,
    upstream_url,
)

from .conftest import config_dict, dump_yaml


def scope(
    *,
    host: str | None = None,
    scheme: str = "http",
    server: tuple[str, int] = ("127.0.0.1", 8080),
    **headers: str,
) -> dict:
    raw_headers = []
    if host is not None:
        raw_headers.append((b"host", host.encode("latin-1")))
    for key, value in headers.items():
        raw_headers.append((key.replace("_", "-").lower().encode("latin-1"), value.encode("latin-1")))
    return {
        "type": "http",
        "method": "GET",
        "scheme": scheme,
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": raw_headers,
        "server": server,
        "client": ("203.0.113.9", 50000),
    }


@pytest.fixture
def config(tmp_path: Path):
    return parse_config_text(dump_yaml(config_dict(tmp_path)), base_dir=tmp_path)


def test_get_host_strips_port_and_normalizes() -> None:
    assert get_host(scope(host="App.Home.LAN:8443")) == "app.home.lan"
    assert get_host(scope(host="APP.HOME.LAN.")) == "app.home.lan"
    assert get_host(scope(host="[::1]:8080")) == "::1"
    assert get_host(scope(host=None, server=("10.0.0.5", 80))) == "10.0.0.5"


def test_get_port_prefers_host_header() -> None:
    assert get_port(scope(host="admin.home.lan:9443")) == 9443
    assert get_port(scope(host="admin.home.lan")) == 8080
    assert get_port(scope(host="[::1]:443", server=("::1", 8080))) == 443
    assert get_port(scope(host="[::1]", server=("::1", 8080))) == 8080


def test_parse_cookies_and_strip_reserved() -> None:
    parsed = parse_cookies(scope(host="a", cookie="warden_session=abc; theme=dark"))
    assert parsed == {"warden_session": "abc", "theme": "dark"}
    assert strip_reserved_cookies("warden_session=abc; theme=dark; warden_challenge=x") == "theme=dark"
    assert strip_reserved_cookies("warden_session=abc") is None
    assert strip_reserved_cookies(None) is None


def test_strip_reserved_cookies_handles_browser_prefixes() -> None:
    # Over HTTPS the session cookie is issued as ``__Host-warden_session``, so
    # matching only the bare names let the token reach every upstream.
    assert strip_reserved_cookies("__Host-warden_session=abc; theme=dark") == "theme=dark"
    assert strip_reserved_cookies("__Secure-warden_challenge=x; other=1") == "other=1"
    assert strip_reserved_cookies("__Host-warden_session=abc") is None
    assert is_reserved_cookie("__Host-warden_session") is True
    assert is_reserved_cookie("theme") is False


def test_safe_next_rejects_absolute_and_tricky_urls() -> None:
    assert safe_next("/services?x=1") == "/services?x=1"
    assert safe_next(None) == "/"
    for value in (
        "https://evil.example",
        "//evil.example",
        "/\\evil.example",
        "/line\nbreak",
        None,
        "",
    ):
        assert safe_next(value) == "/"
    assert safe_next("x" * 3000) == "/"


def test_check_origin_accepts_same_origin_and_rejects_cross_site(config) -> None:
    same = scope(host="admin.home.lan", origin="http://admin.home.lan")
    assert check_origin(same, config)
    cross = scope(host="admin.home.lan", origin="http://evil.example")
    assert not check_origin(cross, config)
    null_origin = scope(host="admin.home.lan", origin="null")
    assert not check_origin(null_origin, config)
    null_same_origin = scope(
        host="admin.home.lan", origin="null", Sec_Fetch_Site="same-origin"
    )
    assert check_origin(null_same_origin, config)
    null_cross_site = scope(
        host="admin.home.lan", origin="null", Sec_Fetch_Site="cross-site"
    )
    assert not check_origin(null_cross_site, config)
    null_navigation = scope(
        host="admin.home.lan", origin="null", Sec_Fetch_Site="none"
    )
    assert not check_origin(null_navigation, config)
    sans_origin = scope(host="admin.home.lan", Sec_Fetch_Site="cross-site")
    assert not check_origin(sans_origin, config)
    assert check_origin(scope(host="admin.home.lan"), config)
    assert not check_origin(scope(host="admin.home.lan"), config, required=True)
    allowed = scope(host="app.home.lan", origin="https://other.home.lan")
    assert config.origin_allowed("https://other.home.lan")
    assert check_origin(allowed, config)


def test_upstream_url_joins_base_path_and_query() -> None:
    route = RouteConfig(host="app.home.lan", upstream="http://127.0.0.1:9000/base/")
    assert upstream_url(route, b"/hello", b"a=1") == "http://127.0.0.1:9000/base/hello?a=1"
    assert upstream_url(route, b"/", b"") == "http://127.0.0.1:9000/base/"
    assert upstream_url(route, b"/ws", b"", websocket=True) == "ws://127.0.0.1:9000/base/ws"
    plain = RouteConfig(host="app.home.lan", upstream="https://example.internal")
    assert (
        upstream_url(plain, b"/x", b"", websocket=True)
        == "wss://example.internal/x"
    )


def _offline_redis_limiter(monkeypatch, *, ttl: int = 300) -> RedisRateLimiter:
    """Build a ``RedisRateLimiter`` on its in-memory fallback.

    Blocking the ``redis.asyncio`` import makes the test independent of both
    redis-py and a running server, while still executing the real limiter.
    """
    monkeypatch.setitem(sys.modules, "redis.asyncio", None)
    return RedisRateLimiter("redis://localhost", ttl=ttl)


def test_redis_rate_limiter_enforces_window(monkeypatch) -> None:
    limiter = _offline_redis_limiter(monkeypatch)
    clock = {"now": 1_000.0}
    monkeypatch.setattr("warden.utils.time.time", lambda: clock["now"])

    clock["now"] = 1_000.0
    assert asyncio.run(limiter.allow("1.2.3.4:login", 2, 60.0)) == (True, 1)
    clock["now"] = 1_001.0
    assert asyncio.run(limiter.allow("1.2.3.4:login", 2, 60.0)) == (True, 0)
    clock["now"] = 1_002.0
    # Over-limit attempts are refused and do not extend the window.
    assert asyncio.run(limiter.allow("1.2.3.4:login", 2, 60.0)) == (False, 0)
    # Limits are tracked per key.
    assert asyncio.run(limiter.allow("5.6.7.8:login", 2, 60.0)) == (True, 1)
    # Entries older than the window are pruned, so a client recovers.
    clock["now"] = 1_070.0
    assert asyncio.run(limiter.allow("1.2.3.4:login", 2, 60.0)) == (True, 1)


def test_rate_limiter_window() -> None:
    limiter = RateLimiter()
    assert limiter.allow("k", 2, 60)
    assert limiter.allow("k", 2, 60)
    assert not limiter.allow("k", 2, 60)[0]
    assert limiter.allow("other", 1, 60)[0]
    # A zero-length window expires immediately.
    assert limiter.allow("k", 1, 0)


def test_formatting_helpers() -> None:
    now = time.time()
    assert relative_time(None) == "never"
    assert relative_time(now - 3, now=now) == "just now"
    assert relative_time(now - 30, now=now) == "30s ago"
    assert relative_time(now - 120, now=now) == "2m ago"
    assert route_initials("Home Assistant", None) == "HA"
    assert route_initials("Files", "📁") == "📁"
    assert route_initials("", None) == "W"
    assert route_color("app.home.lan") == route_color("app.home.lan")
    assert route_color("app.home.lan") in {"moss", "clay", "sky", "plum", "sand", "rose"}
    assert parse_user_agent("Mozilla/5.0 Firefox/128.0") == "Firefox"
    assert parse_user_agent("python-httpx/0.28") == "httpx"
    assert parse_user_agent("") == "Unknown client"
